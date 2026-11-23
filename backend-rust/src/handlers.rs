use crate::auth::{
    extract_bearer_or_api_key, extract_cookie, mint_dashboard_session_token, resolve_jwt_secret,
    verify_client_gateway_auth, verify_dashboard_session_token, verify_management_auth,
    verify_management_password, DASHBOARD_SESSION_COOKIE,
};
use crate::providers::{ensure_fresh_access_token, resolve_upstream_for_connection};
use crate::router_engine::{
    execute_chat_with_failover, resolve_execution_candidates, AppState, ClientResponseFormat,
};
use crate::translator::{
    anthropic_to_openai_request, extract_openai_message_text, responses_to_chat_request,
};
use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;

pub async fn get_models_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(err_resp) = verify_client_gateway_auth(&headers, &state.config, &state.db) {
        return err_resp;
    }

    let now_ts = Utc::now().timestamp();
    let mut data: Vec<Value> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    if let Ok(combos) = state.db.list_combos() {
        for combo in &combos {
            let is_hidden = combo
                .get("isHidden")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if is_hidden {
                continue;
            }
            if let Some(name) = combo.get("name").and_then(Value::as_str) {
                if seen.insert(name.to_string()) {
                    data.push(json!({
                        "id": name,
                        "object": "model",
                        "created": now_ts,
                        "owned_by": "combo",
                        "permission": [],
                        "root": name,
                        "parent": null,
                        "custom": true,
                    }));
                }
            }
            if let Some(steps) = combo.get("models").and_then(Value::as_array) {
                for step in steps {
                    let step_model = step
                        .get("model")
                        .and_then(Value::as_str)
                        .or_else(|| step.as_str());
                    if let Some(m) = step_model.filter(|s| !s.is_empty()) {
                        let owner = m.split('/').next().unwrap_or("omniroute");
                        if seen.insert(m.to_string()) {
                            data.push(json!({
                                "id": m,
                                "object": "model",
                                "created": now_ts,
                                "owned_by": owner,
                                "permission": [],
                                "root": m,
                                "parent": null,
                            }));
                        }
                    }
                }
            }
        }
    }

    let connections = state
        .db
        .list_provider_connections(None, true)
        .unwrap_or_default();
    let nodes = state.db.list_provider_nodes().unwrap_or_default();

    let has_agy = connections.iter().any(|c| c.provider == "agy");
    let has_ag = connections.iter().any(|c| c.provider == "antigravity");

    let ag_models = [
        "gemini-4-argon-medium",
        "gemini-3.8-flash-high",
        "gemini-3.7-flash-tiered",
        "gemini-2.5-pro",
        "gemini-2.5-flash",
        "claude-sonnet-4-6",
        "claude-opus-4-6-thinking",
        "gpt-oss-120b-medium",
    ];
    if has_agy {
        for m in &ag_models {
            let full = format!("agy/{}", m);
            if seen.insert(full.clone()) {
                data.push(json!({
                    "id": full,
                    "object": "model",
                    "created": now_ts,
                    "owned_by": "agy",
                    "permission": [],
                    "root": m,
                    "parent": null,
                }));
            }
        }
    }
    if has_ag {
        for m in &ag_models {
            let full = format!("antigravity/{}", m);
            if seen.insert(full.clone()) {
                data.push(json!({
                    "id": full,
                    "object": "model",
                    "created": now_ts,
                    "owned_by": "antigravity",
                    "permission": [],
                    "root": m,
                    "parent": null,
                }));
            }
        }
    }

    if let Ok(synced_map) = state.db.get_namespace_json_map("syncedAvailableModels") {
        for (key, val) in synced_map {
            let prov_id = key.split(':').next().unwrap_or(&key);
            let prefix = nodes
                .iter()
                .find(|n| n.id == prov_id)
                .map(|n| n.prefix.as_str())
                .unwrap_or(prov_id);
            if let Some(arr) = val.as_array() {
                for item in arr {
                    let mid = item
                        .get("id")
                        .and_then(Value::as_str)
                        .or_else(|| item.as_str());
                    if let Some(m) = mid.filter(|s| !s.is_empty()) {
                        let prefixed = format!("{}/{}", prefix, m);
                        if seen.insert(prefixed.clone()) {
                            data.push(json!({
                                "id": prefixed,
                                "object": "model",
                                "created": now_ts,
                                "owned_by": prefix,
                                "permission": [],
                                "root": m,
                                "parent": null,
                            }));
                        }
                        if seen.insert(m.to_string()) {
                            data.push(json!({
                                "id": m,
                                "object": "model",
                                "created": now_ts,
                                "owned_by": prefix,
                                "permission": [],
                                "root": m,
                                "parent": null,
                            }));
                        }
                    }
                }
            }
        }
    }

    if let Ok(custom_map) = state.db.get_namespace_json_map("customModels") {
        for (prov_id, val) in custom_map {
            let prefix = nodes
                .iter()
                .find(|n| n.id == prov_id)
                .map(|n| n.prefix.as_str())
                .unwrap_or(&prov_id);
            if let Some(arr) = val.as_array() {
                for item in arr {
                    let mid = item
                        .get("id")
                        .and_then(Value::as_str)
                        .or_else(|| item.as_str());
                    if let Some(m) = mid.filter(|s| !s.is_empty()) {
                        let prefixed = format!("{}/{}", prefix, m);
                        if seen.insert(prefixed.clone()) {
                            data.push(json!({
                                "id": prefixed,
                                "object": "model",
                                "created": now_ts,
                                "owned_by": prefix,
                                "permission": [],
                                "root": m,
                                "parent": null,
                                "custom": true,
                            }));
                        }
                    }
                }
            }
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "object": "list",
            "data": data,
        })),
    )
        .into_response()
}

pub async fn post_chat_completions_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let api_key = match verify_client_gateway_auth(&headers, &state.config, &state.db) {
        Ok(k) => k,
        Err(err_resp) => return err_resp,
    };
    execute_chat_with_failover(
        state,
        body,
        "/v1/chat/completions",
        ClientResponseFormat::OpenAIChat,
        api_key,
    )
    .await
}

pub async fn post_messages_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let api_key = match verify_client_gateway_auth(&headers, &state.config, &state.db) {
        Ok(k) => k,
        Err(err_resp) => return err_resp,
    };
    let oa_body = anthropic_to_openai_request(&body);
    execute_chat_with_failover(
        state,
        oa_body,
        "/v1/messages",
        ClientResponseFormat::AnthropicMessages,
        api_key,
    )
    .await
}

pub async fn post_messages_count_tokens_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(err_resp) = verify_client_gateway_auth(&headers, &state.config, &state.db) {
        return err_resp;
    }
    let mut chars = 0usize;
    if let Some(sys) = body.get("system") {
        chars += extract_openai_message_text(Some(sys)).len();
    }
    if let Some(msgs) = body.get("messages").and_then(Value::as_array) {
        for m in msgs {
            chars += extract_openai_message_text(m.get("content")).len();
        }
    }
    let approx_tokens = ((chars as f64) / 3.8).ceil() as i64;
    (
        StatusCode::OK,
        Json(json!({
            "input_tokens": approx_tokens.max(1),
        })),
    )
        .into_response()
}

pub async fn post_responses_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let api_key = match verify_client_gateway_auth(&headers, &state.config, &state.db) {
        Ok(k) => k,
        Err(err_resp) => return err_resp,
    };
    let oa_body = responses_to_chat_request(&body);
    execute_chat_with_failover(
        state,
        oa_body,
        "/v1/responses",
        ClientResponseFormat::OpenAIResponses,
        api_key,
    )
    .await
}

pub async fn post_embeddings_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Response {
    let api_key = match verify_client_gateway_auth(&headers, &state.config, &state.db) {
        Ok(k) => k,
        Err(err_resp) => return err_resp,
    };
    let requested_model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let candidates = match resolve_execution_candidates(&state, &requested_model, api_key.as_ref())
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": { "message": e.to_string() } })),
            )
                .into_response()
        }
    };

    for candidate in candidates {
        let mut conn = candidate.upstream.connection.clone();
        let Ok(token) = ensure_fresh_access_token(&state.http, &state.db, &mut conn, false).await
        else {
            continue;
        };
        body["model"] = json!(candidate.upstream.upstream_model);
        let emb_url = format!(
            "{}/embeddings",
            candidate.upstream.base_url.trim_end_matches('/')
        );
        if let Ok(resp) = state
            .http
            .post(&emb_url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", token))
            .json(&body)
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(val) = resp.json::<Value>().await {
                    return (StatusCode::OK, Json(val)).into_response();
                }
            }
        }
    }

    (
        StatusCode::BAD_GATEWAY,
        Json(json!({
            "error": {
                "message": "Upstream embeddings request failed",
                "type": "upstream_error"
            }
        })),
    )
        .into_response()
}

pub async fn get_health_handler(State(state): State<Arc<AppState>>) -> Response {
    let uptime_secs = state.started_at.elapsed().as_secs();
    let active_conns = state
        .db
        .list_provider_connections(None, true)
        .map(|v| v.len())
        .unwrap_or(0);
    let total_conns = state
        .db
        .list_provider_connections(None, false)
        .map(|v| v.len())
        .unwrap_or(0);
    let combos_count = state.db.list_combos().map(|v| v.len()).unwrap_or(0);

    (
        StatusCode::OK,
        Json(json!({
            "status": "healthy",
            "version": state.config.app_version,
            "engine": "omniroute-rust",
            "uptime": uptime_secs,
            "timestamp": Utc::now().to_rfc3339(),
            "database": {
                "status": "ok",
                "driver": "rusqlite-wal",
                "path": state.config.db_path.to_string_lossy(),
                "activeConnections": active_conns,
                "totalConnections": total_conns,
                "combos": combos_count,
            },
            "memory": {
                "backend": "rust-native",
            },
            "circuitBreakers": [],
            "rateLimits": {},
            "localProviders": {},
        })),
    )
        .into_response()
}

pub async fn post_auth_login_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Response {
    let password = body.get("password").and_then(Value::as_str).unwrap_or("");
    if !verify_management_password(password, &state.db) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid password" })),
        )
            .into_response();
    }

    let Some(secret) = resolve_jwt_secret(&state.config, &state.db) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "JWT secret is not configured" })),
        )
            .into_response();
    };
    let Some(token) = mint_dashboard_session_token(&secret) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to mint session token" })),
        )
            .into_response();
    };

    let cookie = format!(
        "{}={}; HttpOnly; Path=/; Max-Age={}; SameSite=Lax",
        DASHBOARD_SESSION_COOKIE,
        token,
        30 * 24 * 3600
    );
    let mut resp = (StatusCode::OK, Json(json!({ "success": true, "token": token }))).into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

pub async fn post_auth_logout_handler() -> Response {
    let cookie = format!(
        "{}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax",
        DASHBOARD_SESSION_COOKIE
    );
    let mut resp = (StatusCode::OK, Json(json!({ "success": true }))).into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

pub async fn get_auth_status_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let require_login = match state.db.get_kv_json("settings", "requireLogin").ok().flatten() {
        Some(Value::Bool(b)) => b,
        Some(Value::String(s)) => s != "false" && s != "0",
        _ => true,
    };
    let mut authenticated = !require_login;
    if !authenticated {
        if let Some(secret) = resolve_jwt_secret(&state.config, &state.db) {
            if let Some(cookie_tok) = extract_cookie(&headers, DASHBOARD_SESSION_COOKIE) {
                if verify_dashboard_session_token(&cookie_tok, &secret, &state.db) {
                    authenticated = true;
                }
            }
            if !authenticated {
                if let Some(bearer) = extract_bearer_or_api_key(&headers) {
                    if verify_dashboard_session_token(&bearer, &secret, &state.db) {
                        authenticated = true;
                    }
                }
            }
        }
    }
    let has_password = state
        .db
        .get_kv_raw("settings", "password")
        .ok()
        .flatten()
        .is_some();

    (
        StatusCode::OK,
        Json(json!({
            "authenticated": authenticated,
            "requireLogin": require_login,
            "hasPassword": has_password,
        })),
    )
        .into_response()
}

pub async fn get_settings_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    let mut settings = state
        .db
        .get_namespace_json_map("settings")
        .unwrap_or_default();
    let has_password = settings.remove("password").is_some();
    settings.insert("hasPassword".to_string(), json!(has_password));

    if let Ok(flags) = state.db.get_namespace_json_map("feature_flags") {
        settings.insert("featureFlags".to_string(), Value::Object(flags));
    }

    (StatusCode::OK, Json(Value::Object(settings))).into_response()
}

pub async fn patch_settings_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    if let Some(obj) = body.as_object() {
        for (k, v) in obj {
            if k == "password" {
                if let Some(pw) = v.as_str().filter(|s| !s.is_empty()) {
                    if let Ok(hashed) = bcrypt::hash(pw, 10) {
                        let _ = state.db.set_kv_json("settings", "password", &json!(hashed));
                    }
                }
                continue;
            }
            let _ = state.db.set_kv_json("settings", k, v);
        }
    }
    get_settings_handler(State(state), headers).await
}

pub async fn list_providers_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    let conns = state
        .db
        .list_provider_connections(None, false)
        .unwrap_or_default();
    let list: Vec<Value> = conns.iter().map(|c| c.to_api_json(false)).collect();
    (
        StatusCode::OK,
        Json(json!({
            "connections": list,
        })),
    )
        .into_response()
}

pub async fn create_provider_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    match state.db.create_provider_connection(&body) {
        Ok(conn) => (
            StatusCode::CREATED,
            Json(json!({ "connection": conn.to_api_json(false) })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn get_provider_by_id_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    match state.db.get_provider_connection_by_id(&id) {
        Ok(Some(conn)) => (
            StatusCode::OK,
            Json(json!({ "connection": conn.to_api_json(false) })),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Connection not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn update_provider_by_id_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    match state.db.update_provider_connection(&id, &body) {
        Ok(Some(conn)) => (
            StatusCode::OK,
            Json(json!({ "connection": conn.to_api_json(false) })),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Connection not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn delete_provider_by_id_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    match state.db.delete_provider_connection(&id) {
        Ok(true) => (StatusCode::OK, Json(json!({ "deleted": true }))).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Connection not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn test_provider_by_id_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    let Ok(Some(mut conn)) = state.db.get_provider_connection_by_id(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Connection not found" })),
        )
            .into_response();
    };

    let token = match ensure_fresh_access_token(&state.http, &state.db, &mut conn, false).await {
        Ok(t) => t,
        Err(e) => {
            let msg = e.to_string();
            state
                .db
                .mark_connection_result(&conn.id, false, Some(401), Some(&msg));
            return (
                StatusCode::OK,
                Json(json!({
                    "valid": false,
                    "error": msg,
                })),
            )
                .into_response();
        }
    };

    if matches!(conn.provider.as_str(), "agy" | "antigravity") {
        state
            .db
            .mark_connection_result(&conn.id, true, Some(200), None);
        return (
            StatusCode::OK,
            Json(json!({
                "valid": true,
                "provider": conn.provider,
                "message": "OAuth token verified",
            })),
        )
            .into_response();
    }

    let nodes = state.db.list_provider_nodes().unwrap_or_default();
    if let Ok(upstream) = resolve_upstream_for_connection(&conn, &nodes, "test") {
        if let Ok(resp) = state
            .http
            .get(&upstream.models_url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
        {
            let ok = resp.status().is_success();
            let code = resp.status().as_u16();
            state
                .db
                .mark_connection_result(&conn.id, ok, Some(code), None);
            return (
                StatusCode::OK,
                Json(json!({
                    "valid": ok,
                    "status": code,
                })),
            )
                .into_response();
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "valid": true,
        })),
    )
        .into_response()
}

pub async fn list_provider_nodes_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    let nodes = state.db.list_provider_nodes().unwrap_or_default();
    let list: Vec<Value> = nodes.iter().map(|n| n.to_api_json()).collect();
    (StatusCode::OK, Json(json!({ "nodes": list }))).into_response()
}

pub async fn create_provider_node_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    match state.db.create_provider_node(&body) {
        Ok(node) => (
            StatusCode::CREATED,
            Json(json!({ "node": node.to_api_json() })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn delete_provider_node_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    match state.db.delete_provider_node(&id) {
        Ok(true) => (StatusCode::OK, Json(json!({ "deleted": true }))).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Provider node not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn list_combos_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    let combos = state.db.list_combos().unwrap_or_default();
    (StatusCode::OK, Json(json!({ "combos": combos }))).into_response()
}

pub async fn create_combo_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    match state.db.create_combo(&body) {
        Ok(combo) => (StatusCode::CREATED, Json(combo)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn get_combo_by_id_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    let found = state
        .db
        .get_combo_by_id(&id)
        .ok()
        .flatten()
        .or_else(|| state.db.get_combo_by_name(&id).ok().flatten());
    match found {
        Some(combo) => (StatusCode::OK, Json(combo)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Combo not found" })),
        )
            .into_response(),
    }
}

pub async fn update_combo_by_id_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    match state.db.update_combo(&id, &body) {
        Ok(Some(combo)) => (StatusCode::OK, Json(combo)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Combo not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn delete_combo_by_id_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    match state.db.delete_combo(&id) {
        Ok(true) => (StatusCode::OK, Json(json!({ "deleted": true }))).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Combo not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn list_keys_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    let keys = state.db.list_api_keys().unwrap_or_default();
    let list: Vec<Value> = keys.iter().map(|k| k.to_api_json(false)).collect();
    (StatusCode::OK, Json(json!({ "keys": list }))).into_response()
}

pub async fn create_key_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    match state.db.create_api_key(&body) {
        Ok((rec, raw_key)) => (
            StatusCode::CREATED,
            Json(json!({
                "id": rec.id,
                "name": rec.name,
                "key": raw_key,
                "createdAt": rec.created_at,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn reveal_key_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    let found = state
        .db
        .list_api_keys()
        .unwrap_or_default()
        .into_iter()
        .find(|k| k.id == id);
    match found {
        Some(k) => (
            StatusCode::OK,
            Json(json!({
                "id": k.id,
                "name": k.name,
                "key": k.key_decrypted,
            })),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "API key not found" })),
        )
            .into_response(),
    }
}

pub async fn delete_key_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    match state.db.delete_api_key(&id) {
        Ok(true) => (StatusCode::OK, Json(json!({ "deleted": true }))).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "API key not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct LogsQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn list_logs_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<LogsQuery>,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).max(0);
    match state.db.list_call_logs(limit, offset) {
        Ok((logs, total)) => (
            StatusCode::OK,
            Json(json!({
                "logs": logs,
                "total": total,
                "limit": limit,
                "offset": offset,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn get_usage_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    match state.db.get_usage_summary() {
        Ok(summary) => (StatusCode::OK, Json(summary)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn get_model_aliases_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    let aliases = state
        .db
        .get_namespace_json_map("modelAliases")
        .unwrap_or_default();
    (
        StatusCode::OK,
        Json(json!({ "aliases": Value::Object(aliases) })),
    )
        .into_response()
}

pub async fn put_model_aliases_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(err) = verify_management_auth(&headers, &state.config, &state.db) {
        return err;
    }
    let obj = body
        .get("aliases")
        .and_then(Value::as_object)
        .or_else(|| body.as_object());
    if let Some(map) = obj {
        for (k, v) in map {
            let _ = state.db.set_kv_json("modelAliases", k, v);
        }
    }
    get_model_aliases_handler(State(state), headers).await
}

pub async fn fallback_handler(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    if let Some(upstream_base) = &state.config.next_upstream_url {
        let target_url = format!("{}{}", upstream_base.trim_end_matches('/'), path_and_query);
        let method = req.method().clone();
        let headers = req.headers().clone();
        let body_bytes = axum::body::to_bytes(req.into_body(), 32 * 1024 * 1024)
            .await
            .unwrap_or_default();

        let mut builder = state.http.request(method, &target_url);
        for (k, v) in &headers {
            if k != header::HOST {
                builder = builder.header(k, v);
            }
        }
        if !body_bytes.is_empty() {
            builder = builder.body(body_bytes);
        }
        if let Ok(up_resp) = builder.send().await {
            let status =
                StatusCode::from_u16(up_resp.status().as_u16()).unwrap_or(StatusCode::OK);
            let up_headers = up_resp.headers().clone();
            let stream = up_resp.bytes_stream();
            let mut resp = Response::new(Body::from_stream(stream));
            *resp.status_mut() = status;
            for (k, v) in up_headers {
                if let Some(name) = k {
                    resp.headers_mut().insert(name, v);
                }
            }
            return resp;
        }
    }

    if path_and_query == "/" || path_and_query.starts_with("/dashboard") {
        let html = format!(
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>OmniRoute Rust Gateway v{}</title>\
            <style>body{{font-family:system-ui,-apple-system,sans-serif;background:#090d16;color:#e2e8f0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}\
            .card{{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:32px;max-width:560px;box-shadow:0 10px 30px rgba(0,0,0,.5)}}\
            h1{{margin:0 0 12px;font-size:22px;color:#38bdf8}}p{{margin:8px 0;color:#94a3b8;line-height:1.5}}\
            code{{background:#1e293b;color:#7dd3fc;padding:2px 6px;border-radius:4px}}</style></head>\
            <body><div class=\"card\"><h1>OmniRoute Rust Gateway v{}</h1>\
            <p>High-performance native Rust AI Routing Engine is active and connected to <code>{}</code>.</p>\
            <p>Endpoints: <code>/v1/models</code>, <code>/v1/chat/completions</code>, <code>/v1/messages</code>, <code>/v1/responses</code>, <code>/api/health</code></p></div></body></html>",
            state.config.app_version,
            state.config.app_version,
            state.config.db_path.display()
        );
        return Html(html).into_response();
    }

    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": {
                "message": format!("Route not found: {}", path_and_query),
                "type": "not_found_error"
            }
        })),
    )
        .into_response()
}
