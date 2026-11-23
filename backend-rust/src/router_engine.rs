use crate::config::AppConfig;
use crate::db::{ApiKeyRecord, CallLogInsert, DbStore, ProviderConnection, ProviderNode};
use crate::providers::{
    antigravity_user_agent, ensure_fresh_access_token, find_builtin_provider,
    resolve_upstream_for_connection, ResolvedUpstream, UpstreamFormat,
};
use crate::translator::{
    build_antigravity_envelope, build_openai_chat_completion_from_antigravity,
    openai_to_anthropic_response, chat_to_responses_json, process_antigravity_sse_line,
    AntigravityCollected,
};
use anyhow::{anyhow, Result};
use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bytes::Bytes;
use chrono::Utc;
use futures_util::StreamExt;
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientResponseFormat {
    OpenAIChat,
    AnthropicMessages,
    OpenAIResponses,
}

pub struct AppState {
    pub config: AppConfig,
    pub db: DbStore,
    pub http: Client,
    pub started_at: Instant,
    pub rr_counter: AtomicUsize,
}

#[derive(Clone, Debug)]
pub struct CandidateTarget {
    pub upstream: ResolvedUpstream,
    pub display_model: String,
    pub combo_name: Option<String>,
}

pub fn resolve_execution_candidates(
    state: &AppState,
    requested_model: &str,
    api_key: Option<&ApiKeyRecord>,
) -> Result<Vec<CandidateTarget>> {
    let effective_model = api_key
        .and_then(|k| k.forced_model.as_deref())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(requested_model)
        .trim();

    let connections = state.db.list_provider_connections(None, true)?;
    let nodes = state.db.list_provider_nodes()?;
    let combos = state.db.list_combos()?;
    let aliases = state.db.get_model_aliases();

    let mut targets = Vec::new();
    collect_candidates_recursive(
        state,
        effective_model,
        &connections,
        &nodes,
        &combos,
        &aliases,
        None,
        0,
        &mut targets,
    )?;

    if targets.is_empty() {
        return Err(anyhow!(
            "No active provider connections available for model '{}'",
            effective_model
        ));
    }
    Ok(targets)
}

#[allow(clippy::too_many_arguments)]
fn collect_candidates_recursive(
    state: &AppState,
    model_or_combo: &str,
    connections: &[ProviderConnection],
    nodes: &[ProviderNode],
    combos: &[Value],
    aliases: &HashMap<String, String>,
    parent_combo: Option<&str>,
    depth: usize,
    out: &mut Vec<CandidateTarget>,
) -> Result<()> {
    if depth > 4 {
        return Ok(());
    }

    let clean_name = model_or_combo
        .strip_prefix("combo/")
        .unwrap_or(model_or_combo)
        .trim();

    if let Some(combo) = combos.iter().find(|c| {
        c.get("name")
            .and_then(Value::as_str)
            .map(|n| n.eq_ignore_ascii_case(clean_name))
            .unwrap_or(false)
    }) {
        let combo_name = combo
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(clean_name)
            .to_string();
        let strategy = combo
            .get("strategy")
            .and_then(Value::as_str)
            .unwrap_or("priority");

        if let Some(models_arr) = combo.get("models").and_then(Value::as_array) {
            let mut steps: Vec<Value> = models_arr.clone();
            if strategy == "round-robin" && !steps.is_empty() {
                let offset = state.rr_counter.fetch_add(1, Ordering::Relaxed) % steps.len();
                steps.rotate_left(offset);
            }

            for step in &steps {
                if let Some(s) = step.as_str() {
                    collect_candidates_recursive(
                        state,
                        s,
                        connections,
                        nodes,
                        combos,
                        aliases,
                        Some(&combo_name),
                        depth + 1,
                        out,
                    )?;
                    continue;
                }

                let kind = step.get("kind").and_then(Value::as_str).unwrap_or("model");
                let step_model = step
                    .get("model")
                    .or_else(|| step.get("comboName"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if step_model.is_empty() {
                    continue;
                }

                if kind == "combo" {
                    collect_candidates_recursive(
                        state,
                        step_model,
                        connections,
                        nodes,
                        combos,
                        aliases,
                        Some(&combo_name),
                        depth + 1,
                        out,
                    )?;
                    continue;
                }

                let explicit_conn_id = step
                    .get("connectionId")
                    .or_else(|| step.get("connection_id"))
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty());
                let explicit_provider_id = step
                    .get("providerId")
                    .or_else(|| step.get("provider_id"))
                    .or_else(|| step.get("provider"))
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty());

                if let Some(cid) = explicit_conn_id {
                    if let Some(conn) = connections.iter().find(|c| c.id == cid) {
                        if let Ok(upstream) =
                            resolve_upstream_for_connection(conn, nodes, step_model)
                        {
                            out.push(CandidateTarget {
                                upstream,
                                display_model: step_model.to_string(),
                                combo_name: Some(combo_name.clone()),
                            });
                            continue;
                        }
                    }
                }

                if let Some(pid) = explicit_provider_id {
                    let matching_conns = find_connections_for_provider(pid, connections, nodes);
                    if !matching_conns.is_empty() {
                        for conn in matching_conns {
                            if let Ok(upstream) =
                                resolve_upstream_for_connection(conn, nodes, step_model)
                            {
                                out.push(CandidateTarget {
                                    upstream,
                                    display_model: step_model.to_string(),
                                    combo_name: Some(combo_name.clone()),
                                });
                            }
                        }
                        continue;
                    }
                }

                collect_candidates_recursive(
                    state,
                    step_model,
                    connections,
                    nodes,
                    combos,
                    aliases,
                    Some(&combo_name),
                    depth + 1,
                    out,
                )?;
            }
        }
        return Ok(());
    }

    let resolved_model_str = aliases
        .get(clean_name)
        .map(String::as_str)
        .unwrap_or(clean_name);

    if let Some((prefix, _rest)) = resolved_model_str.split_once('/') {
        let matching_conns = find_connections_for_provider(prefix, connections, nodes);
        if !matching_conns.is_empty() {
            for conn in matching_conns {
                if let Ok(upstream) =
                    resolve_upstream_for_connection(conn, nodes, resolved_model_str)
                {
                    out.push(CandidateTarget {
                        upstream,
                        display_model: resolved_model_str.to_string(),
                        combo_name: parent_combo.map(String::from),
                    });
                }
            }
            return Ok(());
        }
    }

    // Check syncedAvailableModels / customModels in key_value to see which connection owns this model
    if let Ok(synced_map) = state.db.get_namespace_json_map("syncedAvailableModels") {
        for (k, val) in synced_map {
            if let Some(arr) = val.as_array() {
                let has_model = arr.iter().any(|item| {
                    item.get("id")
                        .and_then(Value::as_str)
                        .map(|id| id.eq_ignore_ascii_case(resolved_model_str))
                        .unwrap_or(false)
                        || item
                            .as_str()
                            .map(|id| id.eq_ignore_ascii_case(resolved_model_str))
                            .unwrap_or(false)
                });
                if has_model {
                    if let Some((_prov, conn_id)) = k.rsplit_once(':') {
                        if let Some(conn) = connections.iter().find(|c| c.id == conn_id) {
                            if let Ok(upstream) =
                                resolve_upstream_for_connection(conn, nodes, resolved_model_str)
                            {
                                out.push(CandidateTarget {
                                    upstream,
                                    display_model: resolved_model_str.to_string(),
                                    combo_name: parent_combo.map(String::from),
                                });
                            }
                        }
                    }
                }
            }
        }
        if !out.is_empty() {
            return Ok(());
        }
    }

    // Fallback: try custom openai-compatible connections first, then other active connections
    let mut fallback_conns: Vec<&ProviderConnection> = connections.iter().collect();
    fallback_conns.sort_by_key(|c| {
        let is_compat = c.provider.starts_with("openai-compatible");
        (!is_compat, c.priority)
    });
    for conn in fallback_conns {
        if let Ok(upstream) = resolve_upstream_for_connection(conn, nodes, resolved_model_str) {
            out.push(CandidateTarget {
                upstream,
                display_model: resolved_model_str.to_string(),
                combo_name: parent_combo.map(String::from),
            });
        }
    }

    Ok(())
}

fn find_connections_for_provider<'a>(
    prefix_or_id: &str,
    connections: &'a [ProviderConnection],
    nodes: &[ProviderNode],
) -> Vec<&'a ProviderConnection> {
    let lower = prefix_or_id.to_lowercase();
    let mut matched = Vec::new();

    for conn in connections {
        let conn_prov_lower = conn.provider.to_lowercase();
        let psd_prefix = conn
            .provider_specific_data
            .get("prefix")
            .and_then(Value::as_str)
            .map(str::to_lowercase);
        let psd_node_name = conn
            .provider_specific_data
            .get("nodeName")
            .and_then(Value::as_str)
            .map(str::to_lowercase);

        let node_match = nodes.iter().find(|n| n.id == conn.provider).map(|n| {
            n.prefix.eq_ignore_ascii_case(&lower)
                || n.name.eq_ignore_ascii_case(&lower)
                || n.id.eq_ignore_ascii_case(&lower)
        });

        let builtin_match = find_builtin_provider(&conn_prov_lower)
            .map(|b| b.id == lower || b.alias == lower)
            .unwrap_or(false);

        if conn_prov_lower == lower
            || psd_prefix.as_deref() == Some(lower.as_str())
            || psd_node_name.as_deref() == Some(lower.as_str())
            || node_match == Some(true)
            || builtin_match
        {
            matched.push(conn);
        }
    }
    matched
}

pub async fn execute_chat_with_failover(
    state: Arc<AppState>,
    mut openai_body: Value,
    endpoint_path: &str,
    client_format: ClientResponseFormat,
    api_key: Option<ApiKeyRecord>,
) -> Response {
    let started = Instant::now();
    let correlation_id = Uuid::new_v4().to_string();
    let requested_model = openai_body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();

    if requested_model.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": {
                    "message": "Field 'model' is required",
                    "type": "invalid_request_error",
                }
            })),
        )
            .into_response();
    }

    let client_stream = openai_body
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let candidates = match resolve_execution_candidates(&state, &requested_model, api_key.as_ref())
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": {
                        "message": e.to_string(),
                        "type": "invalid_request_error",
                    }
                })),
            )
                .into_response();
        }
    };

    let mut last_error_status = StatusCode::BAD_GATEWAY;
    let mut last_error_body = json!({
        "error": {
            "message": "All candidate upstream providers failed",
            "type": "upstream_error",
        }
    });

    for candidate in candidates {
        let mut conn = candidate.upstream.connection.clone();
        let token = match ensure_fresh_access_token(&state.http, &state.db, &mut conn, false).await
        {
            Ok(t) => t,
            Err(e) => {
                let msg = e.to_string();
                state
                    .db
                    .mark_connection_result(&conn.id, false, Some(401), Some(&msg));
                last_error_status = StatusCode::UNAUTHORIZED;
                last_error_body = json!({
                    "error": {
                        "message": msg,
                        "type": "authentication_error",
                        "provider": candidate.upstream.provider_id,
                    }
                });
                continue;
            }
        };

        match candidate.upstream.format {
            UpstreamFormat::Antigravity => {
                match execute_antigravity_candidate(
                    state.clone(),
                    &candidate,
                    &mut conn,
                    &token,
                    &openai_body,
                    &requested_model,
                    client_stream,
                    client_format,
                    endpoint_path,
                    api_key.as_ref(),
                    started,
                    &correlation_id,
                )
                .await
                {
                    Ok(resp) => return resp,
                    Err((status, err_val)) => {
                        last_error_status = status;
                        last_error_body = err_val;
                        continue;
                    }
                }
            }
            UpstreamFormat::OpenAI | UpstreamFormat::Anthropic => {
                openai_body["model"] = json!(candidate.upstream.upstream_model);
                match execute_openai_compatible_candidate(
                    state.clone(),
                    &candidate,
                    &conn,
                    &token,
                    &openai_body,
                    &requested_model,
                    client_stream,
                    client_format,
                    endpoint_path,
                    api_key.as_ref(),
                    started,
                    &correlation_id,
                )
                .await
                {
                    Ok(resp) => return resp,
                    Err((status, err_val)) => {
                        last_error_status = status;
                        last_error_body = err_val;
                        continue;
                    }
                }
            }
        }
    }

    (last_error_status, Json(last_error_body)).into_response()
}

#[allow(clippy::too_many_arguments)]
async fn execute_antigravity_candidate(
    state: Arc<AppState>,
    candidate: &CandidateTarget,
    conn: &mut ProviderConnection,
    initial_token: &str,
    openai_body: &Value,
    requested_model: &str,
    client_stream: bool,
    client_format: ClientResponseFormat,
    endpoint_path: &str,
    api_key: Option<&ApiKeyRecord>,
    started: Instant,
    correlation_id: &str,
) -> std::result::Result<Response, (StatusCode, Value)> {
    let envelope = build_antigravity_envelope(
        &candidate.upstream.upstream_model,
        openai_body,
        conn,
        &state.db,
    );
    let ua = antigravity_user_agent(conn);
    let mut current_token = initial_token.to_string();
    let mut refreshed_once = false;

    for url in &candidate.upstream.fallback_chat_urls {
        let mut attempt = 0;
        while attempt < 2 {
            attempt += 1;
            let req = state
                .http
                .post(url)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", current_token))
                .header("User-Agent", &ua)
                .header("Accept", "text/event-stream")
                .json(&envelope);

            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("Antigravity network error: {}", e);
                    state
                        .db
                        .mark_connection_result(&conn.id, false, Some(502), Some(&msg));
                    break;
                }
            };

            let status_u16 = resp.status().as_u16();
            if (status_u16 == 401 || status_u16 == 403) && !refreshed_once {
                refreshed_once = true;
                if let Ok(new_tok) =
                    ensure_fresh_access_token(&state.http, &state.db, conn, true).await
                {
                    current_token = new_tok;
                    continue;
                }
            }

            if !resp.status().is_success() {
                let err_text = resp.text().await.unwrap_or_default();
                let short_err: String = err_text.chars().take(400).collect();
                state
                    .db
                    .mark_connection_result(&conn.id, false, Some(status_u16), Some(&short_err));
                state.db.insert_call_log(&CallLogInsert {
                    method: "POST".to_string(),
                    path: endpoint_path.to_string(),
                    status: status_u16 as i64,
                    model: candidate.display_model.clone(),
                    requested_model: requested_model.to_string(),
                    provider: candidate.upstream.provider_id.clone(),
                    account: conn.email.clone().or_else(|| conn.name.clone()),
                    connection_id: Some(conn.id.clone()),
                    duration_ms: started.elapsed().as_millis() as i64,
                    ttft_ms: None,
                    tokens_in: 0,
                    tokens_out: 0,
                    tokens_reasoning: 0,
                    tokens_cached: 0,
                    request_type: "chat".to_string(),
                    source_format: "openai".to_string(),
                    target_format: "antigravity".to_string(),
                    api_key_id: api_key.map(|k| k.id.clone()),
                    api_key_name: api_key.map(|k| k.name.clone()),
                    combo_name: candidate.combo_name.clone(),
                    error_summary: Some(short_err.clone()),
                    correlation_id: Some(correlation_id.to_string()),
                });
                if status_u16 == 429 || status_u16 >= 500 || status_u16 == 404 {
                    break;
                }
                return Err((
                    StatusCode::from_u16(status_u16).unwrap_or(StatusCode::BAD_GATEWAY),
                    json!({
                        "error": {
                            "message": short_err,
                            "type": "upstream_error",
                            "code": status_u16,
                            "provider": candidate.upstream.provider_id,
                        }
                    }),
                ));
            }

            // 200 OK from Antigravity SSE endpoint
            if !client_stream {
                let full_bytes = resp.bytes().await.map_err(|e| {
                    (
                        StatusCode::BAD_GATEWAY,
                        json!({ "error": { "message": e.to_string() } }),
                    )
                })?;
                let raw_text = String::from_utf8_lossy(&full_bytes);
                let mut collected = AntigravityCollected::default();
                for line in raw_text.lines() {
                    let trimmed = line.trim();
                    if let Some(data_part) = trimmed.strip_prefix("data:") {
                        process_antigravity_sse_line(
                            data_part,
                            &mut collected,
                            Some(&conn.id),
                            &candidate.upstream.upstream_model,
                            &state.db,
                        );
                    }
                }
                if collected.text_content.is_empty()
                    && collected.tool_calls.is_empty()
                    && collected.reasoning_content.is_empty()
                {
                    process_antigravity_sse_line(
                        &raw_text,
                        &mut collected,
                        Some(&conn.id),
                        &candidate.upstream.upstream_model,
                        &state.db,
                    );
                }

                let duration_ms = started.elapsed().as_millis() as i64;
                state.db.mark_connection_result(&conn.id, true, Some(200), None);
                state.db.insert_call_log(&CallLogInsert {
                    method: "POST".to_string(),
                    path: endpoint_path.to_string(),
                    status: 200,
                    model: candidate.display_model.clone(),
                    requested_model: requested_model.to_string(),
                    provider: candidate.upstream.provider_id.clone(),
                    account: conn.email.clone().or_else(|| conn.name.clone()),
                    connection_id: Some(conn.id.clone()),
                    duration_ms,
                    ttft_ms: Some(duration_ms),
                    tokens_in: collected.prompt_tokens,
                    tokens_out: collected.completion_tokens,
                    tokens_reasoning: collected.reasoning_tokens,
                    tokens_cached: collected.cached_tokens,
                    request_type: "chat".to_string(),
                    source_format: "openai".to_string(),
                    target_format: "antigravity".to_string(),
                    api_key_id: api_key.map(|k| k.id.clone()),
                    api_key_name: api_key.map(|k| k.name.clone()),
                    combo_name: candidate.combo_name.clone(),
                    error_summary: None,
                    correlation_id: Some(correlation_id.to_string()),
                });

                let oa_resp =
                    build_openai_chat_completion_from_antigravity(&collected, requested_model);
                let out_json = match client_format {
                    ClientResponseFormat::OpenAIChat => oa_resp,
                    ClientResponseFormat::AnthropicMessages => {
                        openai_to_anthropic_response(&oa_resp, requested_model)
                    }
                    ClientResponseFormat::OpenAIResponses => {
                        chat_to_responses_json(&oa_resp, requested_model)
                    }
                };
                return Ok((StatusCode::OK, Json(out_json)).into_response());
            }

            // Streaming Antigravity SSE -> OpenAI SSE
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(64);
            let state_cl = state.clone();
            let conn_id = conn.id.clone();
            let conn_account = conn.email.clone().or_else(|| conn.name.clone());
            let upstream_model = candidate.upstream.upstream_model.clone();
            let display_model = candidate.display_model.clone();
            let provider_id = candidate.upstream.provider_id.clone();
            let req_model_cl = requested_model.to_string();
            let endpoint_cl = endpoint_path.to_string();
            let combo_cl = candidate.combo_name.clone();
            let api_key_id = api_key.map(|k| k.id.clone());
            let api_key_name = api_key.map(|k| k.name.clone());
            let corr_cl = correlation_id.to_string();

            tokio::spawn(async move {
                let mut byte_stream = resp.bytes_stream();
                let mut buffer = String::new();
                let mut collected = AntigravityCollected::default();
                let chunk_id = format!("chatcmpl-{}", Uuid::new_v4());
                let created = Utc::now().timestamp();
                let mut sent_role = false;
                let mut ttft_ms: Option<i64> = None;

                while let Some(item) = byte_stream.next().await {
                    let Ok(chunk) = item else { break };
                    buffer.push_str(&String::from_utf8_lossy(&chunk));
                    while let Some(pos) = buffer.find('\n') {
                        let line = buffer[..pos].trim().to_string();
                        buffer.drain(..=pos);
                        let Some(data_part) = line.strip_prefix("data:") else {
                            continue;
                        };
                        let deltas = process_antigravity_sse_line(
                            data_part,
                            &mut collected,
                            Some(&conn_id),
                            &upstream_model,
                            &state_cl.db,
                        );
                        for mut delta in deltas {
                            if ttft_ms.is_none() {
                                ttft_ms = Some(started.elapsed().as_millis() as i64);
                            }
                            if !sent_role {
                                sent_role = true;
                                if let Some(obj) = delta.as_object_mut() {
                                    obj.insert("role".to_string(), json!("assistant"));
                                }
                            }
                            let sse_chunk = json!({
                                "id": chunk_id,
                                "object": "chat.completion.chunk",
                                "created": created,
                                "model": req_model_cl,
                                "choices": [{
                                    "index": 0,
                                    "delta": delta,
                                    "finish_reason": null,
                                }]
                            });
                            let formatted = format!("data: {}\n\n", sse_chunk);
                            if tx.send(Ok(Bytes::from(formatted))).await.is_err() {
                                return;
                            }
                        }
                    }
                }

                let finish_reason = if !collected.tool_calls.is_empty() {
                    "tool_calls"
                } else if collected.finish_reason.is_empty() {
                    "stop"
                } else {
                    collected.finish_reason.as_str()
                };
                let final_chunk = json!({
                    "id": chunk_id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": req_model_cl,
                    "choices": [{
                        "index": 0,
                        "delta": {},
                        "finish_reason": finish_reason,
                    }],
                    "usage": {
                        "prompt_tokens": collected.prompt_tokens,
                        "completion_tokens": collected.completion_tokens,
                        "total_tokens": collected.total_tokens,
                    }
                });
                let _ = tx
                    .send(Ok(Bytes::from(format!(
                        "data: {}\n\ndata: [DONE]\n\n",
                        final_chunk
                    ))))
                    .await;

                state_cl
                    .db
                    .mark_connection_result(&conn_id, true, Some(200), None);
                state_cl.db.insert_call_log(&CallLogInsert {
                    method: "POST".to_string(),
                    path: endpoint_cl,
                    status: 200,
                    model: display_model,
                    requested_model: req_model_cl,
                    provider: provider_id,
                    account: conn_account,
                    connection_id: Some(conn_id),
                    duration_ms: started.elapsed().as_millis() as i64,
                    ttft_ms,
                    tokens_in: collected.prompt_tokens,
                    tokens_out: collected.completion_tokens,
                    tokens_reasoning: collected.reasoning_tokens,
                    tokens_cached: collected.cached_tokens,
                    request_type: "chat_stream".to_string(),
                    source_format: "openai".to_string(),
                    target_format: "antigravity".to_string(),
                    api_key_id,
                    api_key_name,
                    combo_name: combo_cl,
                    error_summary: None,
                    correlation_id: Some(corr_cl),
                });
            });

            let stream_body = Body::from_stream(ReceiverStream::new(rx));
            let mut response = Response::new(stream_body);
            *response.status_mut() = StatusCode::OK;
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream; charset=utf-8"),
            );
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
            return Ok(response);
        }
    }

    Err((
        StatusCode::BAD_GATEWAY,
        json!({
            "error": {
                "message": "Antigravity upstream endpoints exhausted",
                "type": "upstream_error",
                "provider": candidate.upstream.provider_id,
            }
        }),
    ))
}

#[allow(clippy::too_many_arguments)]
async fn execute_openai_compatible_candidate(
    state: Arc<AppState>,
    candidate: &CandidateTarget,
    conn: &ProviderConnection,
    token: &str,
    openai_body: &Value,
    requested_model: &str,
    client_stream: bool,
    client_format: ClientResponseFormat,
    endpoint_path: &str,
    api_key: Option<&ApiKeyRecord>,
    started: Instant,
    correlation_id: &str,
) -> std::result::Result<Response, (StatusCode, Value)> {
    let mut req = state
        .http
        .post(&candidate.upstream.chat_url)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", token));

    if let Some(ua) = conn
        .provider_specific_data
        .get("customUserAgent")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
    {
        req = req.header("User-Agent", ua);
    }

    for (k, v) in &candidate.upstream.custom_headers {
        req = req.header(k.as_str(), v.as_str());
    }

    let resp = match req.json(openai_body).send().await {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("Upstream request failed: {}", e);
            state
                .db
                .mark_connection_result(&conn.id, false, Some(502), Some(&msg));
            return Err((
                StatusCode::BAD_GATEWAY,
                json!({
                    "error": {
                        "message": msg,
                        "type": "upstream_error",
                        "provider": candidate.upstream.provider_id,
                    }
                }),
            ));
        }
    };

    let status_u16 = resp.status().as_u16();
    if !resp.status().is_success() {
        let err_text = resp.text().await.unwrap_or_default();
        let short_err: String = err_text.chars().take(400).collect();
        state
            .db
            .mark_connection_result(&conn.id, false, Some(status_u16), Some(&short_err));
        state.db.insert_call_log(&CallLogInsert {
            method: "POST".to_string(),
            path: endpoint_path.to_string(),
            status: status_u16 as i64,
            model: candidate.display_model.clone(),
            requested_model: requested_model.to_string(),
            provider: candidate.upstream.provider_id.clone(),
            account: conn.name.clone().or_else(|| conn.email.clone()),
            connection_id: Some(conn.id.clone()),
            duration_ms: started.elapsed().as_millis() as i64,
            ttft_ms: None,
            tokens_in: 0,
            tokens_out: 0,
            tokens_reasoning: 0,
            tokens_cached: 0,
            request_type: "chat".to_string(),
            source_format: "openai".to_string(),
            target_format: "openai".to_string(),
            api_key_id: api_key.map(|k| k.id.clone()),
            api_key_name: api_key.map(|k| k.name.clone()),
            combo_name: candidate.combo_name.clone(),
            error_summary: Some(short_err.clone()),
            correlation_id: Some(correlation_id.to_string()),
        });
        let parsed_err = serde_json::from_str::<Value>(&err_text).unwrap_or_else(|_| {
            json!({
                "error": {
                    "message": short_err,
                    "type": "upstream_error",
                    "code": status_u16,
                    "provider": candidate.upstream.provider_id,
                }
            })
        });
        return Err((
            StatusCode::from_u16(status_u16).unwrap_or(StatusCode::BAD_GATEWAY),
            parsed_err,
        ));
    }

    if !client_stream {
        let body_bytes = resp.bytes().await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                json!({ "error": { "message": e.to_string() } }),
            )
        })?;
        let raw_str = String::from_utf8_lossy(&body_bytes);
        let mut oa_json = match serde_json::from_str::<Value>(&raw_str) {
            Ok(v) => v,
            Err(_) => collect_openai_sse_into_completion(&raw_str, requested_model),
        };
        if oa_json.get("model").is_none() {
            oa_json["model"] = json!(requested_model);
        }

        let usage = oa_json.get("usage");
        let tokens_in = usage
            .and_then(|u| u.get("prompt_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let tokens_out = usage
            .and_then(|u| u.get("completion_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let tokens_reasoning = usage
            .and_then(|u| u.get("completion_tokens_details"))
            .and_then(|d| d.get("reasoning_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let tokens_cached = usage
            .and_then(|u| u.get("prompt_tokens_details"))
            .and_then(|d| d.get("cached_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let duration_ms = started.elapsed().as_millis() as i64;

        state
            .db
            .mark_connection_result(&conn.id, true, Some(200), None);
        state.db.insert_call_log(&CallLogInsert {
            method: "POST".to_string(),
            path: endpoint_path.to_string(),
            status: 200,
            model: candidate.display_model.clone(),
            requested_model: requested_model.to_string(),
            provider: candidate.upstream.provider_id.clone(),
            account: conn.name.clone().or_else(|| conn.email.clone()),
            connection_id: Some(conn.id.clone()),
            duration_ms,
            ttft_ms: Some(duration_ms),
            tokens_in,
            tokens_out,
            tokens_reasoning,
            tokens_cached,
            request_type: "chat".to_string(),
            source_format: "openai".to_string(),
            target_format: "openai".to_string(),
            api_key_id: api_key.map(|k| k.id.clone()),
            api_key_name: api_key.map(|k| k.name.clone()),
            combo_name: candidate.combo_name.clone(),
            error_summary: None,
            correlation_id: Some(correlation_id.to_string()),
        });

        let out_json = match client_format {
            ClientResponseFormat::OpenAIChat => oa_json,
            ClientResponseFormat::AnthropicMessages => {
                openai_to_anthropic_response(&oa_json, requested_model)
            }
            ClientResponseFormat::OpenAIResponses => {
                chat_to_responses_json(&oa_json, requested_model)
            }
        };
        return Ok((StatusCode::OK, Json(out_json)).into_response());
    }

    // Streaming pass-through from OpenAI-compatible upstream
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    let state_cl = state.clone();
    let conn_id = conn.id.clone();
    let conn_account = conn.name.clone().or_else(|| conn.email.clone());
    let display_model = candidate.display_model.clone();
    let provider_id = candidate.upstream.provider_id.clone();
    let req_model_cl = requested_model.to_string();
    let endpoint_cl = endpoint_path.to_string();
    let combo_cl = candidate.combo_name.clone();
    let api_key_id = api_key.map(|k| k.id.clone());
    let api_key_name = api_key.map(|k| k.name.clone());
    let corr_cl = correlation_id.to_string();

    tokio::spawn(async move {
        let mut byte_stream = resp.bytes_stream();
        let mut ttft_ms: Option<i64> = None;
        let mut tokens_in = 0i64;
        let mut tokens_out = 0i64;
        let mut line_buf = String::new();

        while let Some(item) = byte_stream.next().await {
            let Ok(chunk) = item else { break };
            if ttft_ms.is_none() {
                ttft_ms = Some(started.elapsed().as_millis() as i64);
            }
            line_buf.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(pos) = line_buf.find('\n') {
                let line = line_buf[..pos].trim().to_string();
                line_buf.drain(..=pos);
                if let Some(data_part) = line.strip_prefix("data:") {
                    let trimmed = data_part.trim();
                    if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
                        if let Some(u) = v.get("usage") {
                            tokens_in = u
                                .get("prompt_tokens")
                                .and_then(Value::as_i64)
                                .unwrap_or(tokens_in);
                            tokens_out = u
                                .get("completion_tokens")
                                .and_then(Value::as_i64)
                                .unwrap_or(tokens_out);
                        }
                    }
                }
            }
            if tx.send(Ok(chunk)).await.is_err() {
                return;
            }
        }

        state_cl
            .db
            .mark_connection_result(&conn_id, true, Some(200), None);
        state_cl.db.insert_call_log(&CallLogInsert {
            method: "POST".to_string(),
            path: endpoint_cl,
            status: 200,
            model: display_model,
            requested_model: req_model_cl,
            provider: provider_id,
            account: conn_account,
            connection_id: Some(conn_id),
            duration_ms: started.elapsed().as_millis() as i64,
            ttft_ms,
            tokens_in,
            tokens_out,
            tokens_reasoning: 0,
            tokens_cached: 0,
            request_type: "chat_stream".to_string(),
            source_format: "openai".to_string(),
            target_format: "openai".to_string(),
            api_key_id,
            api_key_name,
            combo_name: combo_cl,
            error_summary: None,
            correlation_id: Some(corr_cl),
        });
    });

    let stream_body = Body::from_stream(ReceiverStream::new(rx));
    let mut response = Response::new(stream_body);
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
    Ok(response)
}

fn collect_openai_sse_into_completion(raw_sse: &str, requested_model: &str) -> Value {
    let mut content = String::new();
    let mut reasoning = String::new();
    let mut finish_reason = "stop".to_string();
    let mut prompt_tokens = 0i64;
    let mut completion_tokens = 0i64;

    for line in raw_sse.lines() {
        let Some(data) = line.trim().strip_prefix("data:") else {
            continue;
        };
        let trimmed = data.trim();
        if trimmed == "[DONE]" || trimmed.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        if let Some(choice) = v
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
        {
            if let Some(delta) = choice.get("delta") {
                if let Some(c) = delta.get("content").and_then(Value::as_str) {
                    content.push_str(c);
                }
                if let Some(r) = delta.get("reasoning_content").and_then(Value::as_str) {
                    reasoning.push_str(r);
                }
            }
            if let Some(fr) = choice.get("finish_reason").and_then(Value::as_str) {
                finish_reason = fr.to_string();
            }
        }
        if let Some(u) = v.get("usage") {
            prompt_tokens = u
                .get("prompt_tokens")
                .and_then(Value::as_i64)
                .unwrap_or(prompt_tokens);
            completion_tokens = u
                .get("completion_tokens")
                .and_then(Value::as_i64)
                .unwrap_or(completion_tokens);
        }
    }

    let mut msg = json!({
        "role": "assistant",
        "content": content,
    });
    if !reasoning.is_empty() {
        msg["reasoning_content"] = json!(reasoning);
    }

    json!({
        "id": format!("chatcmpl-{}", Uuid::new_v4()),
        "object": "chat.completion",
        "created": Utc::now().timestamp(),
        "model": requested_model,
        "choices": [{
            "index": 0,
            "message": msg,
            "finish_reason": finish_reason,
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        }
    })
}
