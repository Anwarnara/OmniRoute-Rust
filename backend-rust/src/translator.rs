use crate::db::{DbStore, ProviderConnection};
use chrono::Utc;
use serde_json::{json, Map, Value};
use uuid::Uuid;

pub const ANTIGRAVITY_DEFAULT_SYSTEM: &str = "You are Antigravity, a powerful agentic AI coding assistant designed by the Google Deepmind team working on Advanced Agentic Coding.\nYou are pair programming with a USER to solve their coding task. The task may require creating a new codebase, modifying or debugging an existing codebase, or simply answering a question.\n**Absolute paths only**\n**Proactiveness**";

pub fn clean_antigravity_model_name(raw: &str) -> String {
    let stripped = raw
        .rsplit('/')
        .next()
        .unwrap_or(raw)
        .trim();
    match stripped {
        "gemini-3.7-flash"
        | "gemini-3.7-flash-high"
        | "gemini-3.7-flash-medium"
        | "gemini-3.7-flash-low" => "gemini-3.7-flash-tiered".to_string(),
        "gemini-3.8-flash" | "gemini-3.8-flash-tiered" => "gemini-3.8-flash-high".to_string(),
        "gemini-4-argon" => "gemini-4-argon-medium".to_string(),
        "gemini-4-carbon" => "gemini-4-carbon-medium".to_string(),
        "gemini-4-hydrogen" => "gemini-4-hydrogen-high".to_string(),
        "gpt-oss-120b" => "gpt-oss-120b-medium".to_string(),
        "gemini-3.1-pro-high" => "gemini-pro-agent".to_string(),
        "gemini-3-pro-image-preview" => "gemini-3-pro-image".to_string(),
        "gemini-claude-sonnet-4-5" | "gemini-claude-sonnet-4-5-thinking" => {
            "claude-sonnet-4-6".to_string()
        }
        "gemini-claude-opus-4-5-thinking" => "claude-opus-4-6-thinking".to_string(),
        other => other.to_string(),
    }
}

fn fnv1a_i64_session_id(key: &str) -> String {
    let mut hash: i64 = -3750763034362895579i64;
    let prime: i64 = 1099511628211i64;
    for b in key.as_bytes() {
        hash ^= *b as i64;
        hash = hash.wrapping_mul(prime);
    }
    hash.to_string()
}

pub fn build_antigravity_envelope(
    upstream_model: &str,
    openai_body: &Value,
    conn: &ProviderConnection,
    db: &DbStore,
) -> Value {
    let project_id = conn
        .project_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            conn.provider_specific_data
                .get("projectId")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or("aicode-consumers")
        .to_string();

    let is_claude = upstream_model.to_lowercase().contains("claude");
    let is_gemini = upstream_model.to_lowercase().contains("gemini");

    let agent_id = Uuid::new_v4().to_string();
    let trajectory_id = Uuid::new_v4().to_string();
    let step = 2;
    let request_id = format!(
        "agent/{}/{}/{}/{}",
        agent_id,
        Utc::now().timestamp_millis(),
        trajectory_id,
        step
    );
    let account_key = conn
        .email
        .as_deref()
        .or(Some(conn.id.as_str()))
        .unwrap_or("antigravity");
    let session_id = fnv1a_i64_session_id(account_key);

    let mut client_system_parts: Vec<Value> = Vec::new();
    let mut contents: Vec<Value> = Vec::new();
    let mut tc_id_to_name: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    if let Some(messages) = openai_body.get("messages").and_then(Value::as_array) {
        for msg in messages {
            if msg.get("role").and_then(Value::as_str) == Some("assistant") {
                if let Some(tcs) = msg.get("tool_calls").and_then(Value::as_array) {
                    for tc in tcs {
                        if let (Some(id), Some(name)) = (
                            tc.get("id").and_then(Value::as_str),
                            tc.get("function")
                                .and_then(|f| f.get("name"))
                                .and_then(Value::as_str),
                        ) {
                            tc_id_to_name.insert(id.to_string(), name.to_string());
                        }
                    }
                }
            }
        }

        for msg in messages {
            let role = msg.get("role").and_then(Value::as_str).unwrap_or("user");
            match role {
                "system" | "developer" => {
                    let text = extract_openai_message_text(msg.get("content"));
                    if !text.trim().is_empty() {
                        client_system_parts.push(json!({ "text": text }));
                    }
                }
                "user" => {
                    let parts = convert_openai_content_to_gemini_parts(msg.get("content"));
                    if !parts.is_empty() {
                        push_or_merge_gemini_content(&mut contents, "user", parts);
                    }
                }
                "assistant" => {
                    let mut parts: Vec<Value> = Vec::new();
                    let text = extract_openai_message_text(msg.get("content"));
                    if !text.is_empty() {
                        parts.push(json!({ "text": text }));
                    }
                    if let Some(tcs) = msg.get("tool_calls").and_then(Value::as_array) {
                        for tc in tcs {
                            let id = tc.get("id").and_then(Value::as_str).unwrap_or("");
                            let fn_obj = tc.get("function");
                            let name = fn_obj
                                .and_then(|f| f.get("name"))
                                .and_then(Value::as_str)
                                .unwrap_or("");
                            if name.is_empty() {
                                continue;
                            }
                            let raw_args = fn_obj
                                .and_then(|f| f.get("arguments"))
                                .and_then(Value::as_str)
                                .unwrap_or("{}");
                            let args_val = serde_json::from_str::<Value>(raw_args)
                                .unwrap_or_else(|_| json!({}));
                            let sig = db
                                .get_thought_signature(Some(&conn.id), upstream_model, id)
                                .unwrap_or_else(|| "skip_thought_signature_validator".to_string());

                            let mut fc = json!({
                                "name": name,
                                "args": args_val,
                            });
                            if !id.is_empty() {
                                fc["id"] = json!(id);
                            }
                            parts.push(json!({
                                "thoughtSignature": sig,
                                "functionCall": fc,
                            }));
                        }
                    }
                    if !parts.is_empty() {
                        push_or_merge_gemini_content(&mut contents, "model", parts);
                    }
                }
                "tool" => {
                    let tool_call_id = msg
                        .get("tool_call_id")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let name = msg
                        .get("name")
                        .and_then(Value::as_str)
                        .map(String::from)
                        .or_else(|| tc_id_to_name.get(tool_call_id).cloned())
                        .unwrap_or_else(|| "tool".to_string());
                    let result_text = extract_openai_message_text(msg.get("content"));
                    let mut fr = json!({
                        "name": name,
                        "response": {
                            "result": result_text
                        }
                    });
                    if !tool_call_id.is_empty() {
                        fr["id"] = json!(tool_call_id);
                    }
                    push_or_merge_gemini_content(
                        &mut contents,
                        "user",
                        vec![json!({ "functionResponse": fr })],
                    );
                }
                _ => {}
            }
        }
    }

    // Relocate client system instructions to the first user message (#9030)
    if !client_system_parts.is_empty() {
        if let Some(first) = contents.first_mut() {
            if first.get("role").and_then(Value::as_str) == Some("user") {
                if let Some(parts_arr) = first.get_mut("parts").and_then(Value::as_array_mut) {
                    let mut combined = client_system_parts;
                    combined.append(parts_arr);
                    *parts_arr = combined;
                }
            } else {
                contents.insert(
                    0,
                    json!({
                        "role": "user",
                        "parts": client_system_parts
                    }),
                );
            }
        } else {
            contents.push(json!({
                "role": "user",
                "parts": client_system_parts
            }));
        }
    }

    // Strip trailing model turn for Claude/Gemini if needed (#10104)
    if (is_claude || is_gemini) && contents.len() > 1 {
        while contents.len() > 1
            && contents
                .last()
                .and_then(|c| c.get("role"))
                .and_then(Value::as_str)
                == Some("model")
        {
            let has_fc = contents
                .last()
                .and_then(|c| c.get("parts"))
                .and_then(Value::as_array)
                .map(|arr| arr.iter().any(|p| p.get("functionCall").is_some()))
                .unwrap_or(false);
            if has_fc {
                break;
            }
            contents.pop();
        }
    }

    let mut generation_config = Map::new();
    generation_config.insert("topK".to_string(), json!(40));
    generation_config.insert(
        "topP".to_string(),
        openai_body
            .get("top_p")
            .cloned()
            .unwrap_or_else(|| json!(1.0)),
    );
    if let Some(temp) = openai_body.get("temperature") {
        if !temp.is_null() {
            generation_config.insert("temperature".to_string(), temp.clone());
        }
    }
    if let Some(max_tok) = openai_body
        .get("max_tokens")
        .or_else(|| openai_body.get("max_completion_tokens"))
        .and_then(Value::as_i64)
    {
        let cap = if is_claude { 16384 } else { 65536 };
        generation_config.insert(
            "maxOutputTokens".to_string(),
            json!(std::cmp::min(max_tok.max(1), cap)),
        );
    }

    let is_claude_str = if is_claude { "true" } else { "false" };
    let labels = json!({
        "last_step_index": "1",
        "trajectory_id": trajectory_id,
        "used_claude": is_claude_str,
        "used_claude_conservative": is_claude_str,
    });

    let mut inner_req = Map::new();
    inner_req.insert("sessionId".to_string(), json!(session_id));
    inner_req.insert("contents".to_string(), Value::Array(contents));
    inner_req.insert(
        "systemInstruction".to_string(),
        json!({
            "role": "system",
            "parts": [{ "text": ANTIGRAVITY_DEFAULT_SYSTEM }]
        }),
    );
    inner_req.insert(
        "generationConfig".to_string(),
        Value::Object(generation_config),
    );
    inner_req.insert("labels".to_string(), labels);

    if let Some(tools) = openai_body.get("tools").and_then(Value::as_array) {
        let mut func_decls = Vec::new();
        for tool in tools {
            let fn_obj = if tool.get("type").and_then(Value::as_str) == Some("function") {
                tool.get("function")
            } else {
                Some(tool)
            };
            let Some(f) = fn_obj else { continue };
            let Some(name) = f.get("name").and_then(Value::as_str) else {
                continue;
            };
            let desc = f
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("");
            let params = f
                .get("parameters")
                .map(clean_json_schema_for_gemini)
                .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
            func_decls.push(json!({
                "name": name,
                "description": desc,
                "parameters": params,
            }));
        }
        if !func_decls.is_empty() {
            inner_req.insert(
                "tools".to_string(),
                json!([{ "functionDeclarations": func_decls }]),
            );
            let mode = match openai_body.get("tool_choice") {
                Some(Value::String(s)) if s == "none" => "NONE",
                Some(Value::String(s)) if s == "required" || s == "any" => "ANY",
                _ => "VALIDATED",
            };
            inner_req.insert(
                "toolConfig".to_string(),
                json!({
                    "functionCallingConfig": {
                        "mode": mode
                    }
                }),
            );
        }
    }

    json!({
        "project": project_id,
        "requestId": request_id,
        "model": upstream_model,
        "userAgent": "antigravity",
        "requestType": "agent",
        "request": Value::Object(inner_req),
    })
}

fn push_or_merge_gemini_content(contents: &mut Vec<Value>, role: &str, mut parts: Vec<Value>) {
    if parts.is_empty() {
        return;
    }
    if let Some(last) = contents.last_mut() {
        if last.get("role").and_then(Value::as_str) == Some(role) {
            if let Some(arr) = last.get_mut("parts").and_then(Value::as_array_mut) {
                arr.append(&mut parts);
                return;
            }
        }
    }
    contents.push(json!({
        "role": role,
        "parts": parts,
    }));
}

pub fn extract_openai_message_text(content: Option<&Value>) -> String {
    let Some(c) = content else {
        return String::new();
    };
    match c {
        Value::String(s) => s.clone(),
        Value::Array(arr) => {
            let mut out = Vec::new();
            for item in arr {
                if let Some(s) = item.as_str() {
                    out.push(s.to_string());
                } else if let Some(t) = item.get("text").and_then(Value::as_str) {
                    out.push(t.to_string());
                }
            }
            out.join("\n")
        }
        _ => String::new(),
    }
}

fn convert_openai_content_to_gemini_parts(content: Option<&Value>) -> Vec<Value> {
    let Some(c) = content else {
        return Vec::new();
    };
    match c {
        Value::String(s) => {
            if s.is_empty() {
                Vec::new()
            } else {
                vec![json!({ "text": s })]
            }
        }
        Value::Array(arr) => {
            let mut parts = Vec::new();
            for item in arr {
                let item_type = item.get("type").and_then(Value::as_str).unwrap_or("text");
                if item_type == "text" {
                    if let Some(t) = item.get("text").and_then(Value::as_str) {
                        if !t.is_empty() {
                            parts.push(json!({ "text": t }));
                        }
                    }
                } else if item_type == "image_url" {
                    if let Some(url) = item
                        .get("image_url")
                        .and_then(|u| u.get("url").or(Some(u)))
                        .and_then(Value::as_str)
                    {
                        if let Some(rest) = url.strip_prefix("data:") {
                            if let Some((mime_part, b64)) = rest.split_once(";base64,") {
                                parts.push(json!({
                                    "inlineData": {
                                        "mimeType": mime_part,
                                        "data": b64,
                                    }
                                }));
                            }
                        }
                    }
                }
            }
            parts
        }
        _ => Vec::new(),
    }
}

fn clean_json_schema_for_gemini(schema: &Value) -> Value {
    match schema {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                if matches!(
                    k.as_str(),
                    "$schema"
                        | "additionalProperties"
                        | "strict"
                        | "default"
                        | "examples"
                        | "title"
                        | "$id"
                ) {
                    continue;
                }
                if k == "type" {
                    if let Value::Array(types) = v {
                        if let Some(first_non_null) = types
                            .iter()
                            .filter_map(Value::as_str)
                            .find(|t| *t != "null")
                        {
                            out.insert("type".to_string(), json!(first_non_null));
                            continue;
                        }
                    }
                }
                out.insert(k.clone(), clean_json_schema_for_gemini(v));
            }
            if !out.contains_key("type") && out.contains_key("properties") {
                out.insert("type".to_string(), json!("object"));
            }
            Value::Object(out)
        }
        Value::Array(arr) => {
            Value::Array(arr.iter().map(clean_json_schema_for_gemini).collect())
        }
        other => other.clone(),
    }
}

#[derive(Default, Debug)]
pub struct AntigravityCollected {
    pub text_content: String,
    pub reasoning_content: String,
    pub finish_reason: String,
    pub tool_calls: Vec<Value>,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub reasoning_tokens: i64,
    pub cached_tokens: i64,
    pub total_tokens: i64,
}

pub fn process_antigravity_sse_line(
    data_str: &str,
    collected: &mut AntigravityCollected,
    conn_id: Option<&str>,
    upstream_model: &str,
    db: &DbStore,
) -> Vec<Value> {
    let mut delta_events = Vec::new();
    let trimmed = data_str.trim();
    if trimmed.is_empty() || trimmed == "[DONE]" {
        return delta_events;
    }
    let Ok(parsed) = serde_json::from_str::<Value>(trimmed) else {
        return delta_events;
    };

    if let Some(md) = parsed
        .get("markdown")
        .or_else(|| parsed.get("response").and_then(|r| r.get("markdown")))
        .and_then(Value::as_str)
    {
        if !md.is_empty() {
            collected.text_content.push_str(md);
            delta_events.push(json!({ "content": md }));
        }
    }

    let resp_obj = parsed.get("response").unwrap_or(&parsed);
    if let Some(candidate) = resp_obj
        .get("candidates")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
    {
        if let Some(parts) = candidate
            .get("content")
            .and_then(|c| c.get("parts"))
            .and_then(Value::as_array)
        {
            for part in parts {
                let is_thought = part
                    .get("thought")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if let Some(fc) = part.get("functionCall") {
                    if let Some(name) = fc.get("name").and_then(Value::as_str) {
                        let idx = collected.tool_calls.len();
                        let id = fc
                            .get("id")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                            .map(String::from)
                            .unwrap_or_else(|| {
                                format!("call_{}_{}", name, Utc::now().timestamp_millis())
                            });
                        let args_str = serde_json::to_string(
                            fc.get("args").unwrap_or(&json!({})),
                        )
                        .unwrap_or_else(|_| "{}".to_string());

                        if let Some(sig) = part.get("thoughtSignature").and_then(Value::as_str) {
                            db.store_thought_signature(conn_id, upstream_model, &id, sig);
                        }

                        let tc_val = json!({
                            "id": id,
                            "index": idx,
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": args_str,
                            }
                        });
                        collected.tool_calls.push(tc_val.clone());
                        collected.finish_reason = "tool_calls".to_string();
                        delta_events.push(json!({
                            "tool_calls": [tc_val]
                        }));
                        continue;
                    }
                }
                if let Some(t) = part.get("text").and_then(Value::as_str) {
                    if !t.is_empty() {
                        if is_thought {
                            collected.reasoning_content.push_str(t);
                            delta_events.push(json!({ "reasoning_content": t }));
                        } else {
                            collected.text_content.push_str(t);
                            delta_events.push(json!({ "content": t }));
                        }
                    }
                }
            }
        }
        if collected.tool_calls.is_empty() {
            if let Some(fr) = candidate.get("finishReason").and_then(Value::as_str) {
                collected.finish_reason = match fr.to_uppercase().as_str() {
                    "MAX_TOKENS" => "length".to_string(),
                    "SAFETY" | "RECITATION" => "content_filter".to_string(),
                    _ => "stop".to_string(),
                };
            }
        }
    }

    if let Some(um) = resp_obj.get("usageMetadata") {
        let prompt = um
            .get("promptTokenCount")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let candidates = um
            .get("candidatesTokenCount")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let thoughts = um
            .get("thoughtsTokenCount")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let cached = um
            .get("cachedContentTokenCount")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let total = um
            .get("totalTokenCount")
            .and_then(Value::as_i64)
            .unwrap_or(prompt + candidates + thoughts);
        collected.prompt_tokens = prompt;
        collected.completion_tokens = candidates + thoughts;
        collected.reasoning_tokens = thoughts;
        collected.cached_tokens = cached;
        collected.total_tokens = total;
    }

    delta_events
}

pub fn build_openai_chat_completion_from_antigravity(
    collected: &AntigravityCollected,
    requested_model: &str,
) -> Value {
    let finish_reason = if !collected.tool_calls.is_empty() {
        "tool_calls"
    } else if collected.finish_reason.is_empty() {
        "stop"
    } else {
        collected.finish_reason.as_str()
    };

    let mut message = Map::new();
    message.insert("role".to_string(), json!("assistant"));
    if !collected.tool_calls.is_empty() && collected.text_content.is_empty() {
        message.insert("content".to_string(), Value::Null);
    } else {
        message.insert("content".to_string(), json!(collected.text_content));
    }
    if !collected.reasoning_content.is_empty() {
        message.insert(
            "reasoning_content".to_string(),
            json!(collected.reasoning_content),
        );
    }
    if !collected.tool_calls.is_empty() {
        message.insert("tool_calls".to_string(), json!(collected.tool_calls));
    }

    let mut usage = json!({
        "prompt_tokens": collected.prompt_tokens,
        "completion_tokens": collected.completion_tokens,
        "total_tokens": collected.total_tokens,
    });
    if collected.reasoning_tokens > 0 {
        usage["completion_tokens_details"] = json!({
            "reasoning_tokens": collected.reasoning_tokens
        });
    }
    if collected.cached_tokens > 0 {
        usage["prompt_tokens_details"] = json!({
            "cached_tokens": collected.cached_tokens
        });
    }

    json!({
        "id": format!("chatcmpl-{}", Uuid::new_v4()),
        "object": "chat.completion",
        "created": Utc::now().timestamp(),
        "model": requested_model,
        "choices": [{
            "index": 0,
            "message": Value::Object(message),
            "finish_reason": finish_reason,
        }],
        "usage": usage,
    })
}

pub fn anthropic_to_openai_request(body: &Value) -> Value {
    let mut messages = Vec::new();
    if let Some(sys) = body.get("system") {
        let sys_text = match sys {
            Value::String(s) => s.clone(),
            Value::Array(arr) => arr
                .iter()
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n"),
            _ => String::new(),
        };
        if !sys_text.is_empty() {
            messages.push(json!({
                "role": "system",
                "content": sys_text,
            }));
        }
    }

    if let Some(in_msgs) = body.get("messages").and_then(Value::as_array) {
        for m in in_msgs {
            let role = m.get("role").and_then(Value::as_str).unwrap_or("user");
            match m.get("content") {
                Some(Value::String(s)) => {
                    messages.push(json!({ "role": role, "content": s }));
                }
                Some(Value::Array(blocks)) => {
                    let mut text_parts = Vec::new();
                    let mut tool_calls = Vec::new();
                    let mut tool_results = Vec::new();

                    for b in blocks {
                        let b_type = b.get("type").and_then(Value::as_str).unwrap_or("text");
                        match b_type {
                            "text" => {
                                if let Some(t) = b.get("text").and_then(Value::as_str) {
                                    text_parts.push(t.to_string());
                                }
                            }
                            "tool_use" => {
                                let id = b.get("id").and_then(Value::as_str).unwrap_or("");
                                let name = b.get("name").and_then(Value::as_str).unwrap_or("");
                                let input = b.get("input").cloned().unwrap_or_else(|| json!({}));
                                tool_calls.push(json!({
                                    "id": id,
                                    "type": "function",
                                    "function": {
                                        "name": name,
                                        "arguments": serde_json::to_string(&input).unwrap_or_else(|_| "{}".to_string()),
                                    }
                                }));
                            }
                            "tool_result" => {
                                let tool_use_id =
                                    b.get("tool_use_id").and_then(Value::as_str).unwrap_or("");
                                let content_txt = extract_openai_message_text(b.get("content"));
                                tool_results.push(json!({
                                    "role": "tool",
                                    "tool_call_id": tool_use_id,
                                    "content": content_txt,
                                }));
                            }
                            _ => {}
                        }
                    }

                    if !text_parts.is_empty() || !tool_calls.is_empty() {
                        let mut msg_obj = json!({
                            "role": role,
                            "content": text_parts.join("\n"),
                        });
                        if !tool_calls.is_empty() {
                            msg_obj["tool_calls"] = Value::Array(tool_calls);
                        }
                        messages.push(msg_obj);
                    }
                    messages.extend(tool_results);
                }
                _ => {}
            }
        }
    }

    let mut out = json!({
        "model": body.get("model").and_then(Value::as_str).unwrap_or(""),
        "messages": messages,
        "stream": body.get("stream").and_then(Value::as_bool).unwrap_or(false),
    });
    if let Some(max_tok) = body.get("max_tokens") {
        out["max_tokens"] = max_tok.clone();
    }
    if let Some(temp) = body.get("temperature") {
        out["temperature"] = temp.clone();
    }
    if let Some(tools) = body.get("tools").and_then(Value::as_array) {
        let oa_tools: Vec<Value> = tools
            .iter()
            .filter_map(|t| {
                let name = t.get("name")?.as_str()?;
                let desc = t.get("description").and_then(Value::as_str).unwrap_or("");
                let params = t
                    .get("input_schema")
                    .or_else(|| t.get("parameters"))
                    .cloned()
                    .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
                Some(json!({
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": desc,
                        "parameters": params,
                    }
                }))
            })
            .collect();
        if !oa_tools.is_empty() {
            out["tools"] = Value::Array(oa_tools);
        }
    }
    out
}

pub fn openai_to_anthropic_response(oa: &Value, requested_model: &str) -> Value {
    let choice = oa
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|a| a.first());
    let msg = choice.and_then(|c| c.get("message"));
    let mut content_blocks = Vec::new();

    if let Some(reasoning) = msg
        .and_then(|m| m.get("reasoning_content"))
        .and_then(Value::as_str)
    {
        if !reasoning.is_empty() {
            content_blocks.push(json!({
                "type": "thinking",
                "thinking": reasoning,
            }));
        }
    }
    if let Some(txt) = msg.and_then(|m| m.get("content")).and_then(Value::as_str) {
        if !txt.is_empty() {
            content_blocks.push(json!({
                "type": "text",
                "text": txt,
            }));
        }
    }
    if let Some(tcs) = msg
        .and_then(|m| m.get("tool_calls"))
        .and_then(Value::as_array)
    {
        for tc in tcs {
            let id = tc.get("id").and_then(Value::as_str).unwrap_or("toolu_01");
            let fn_obj = tc.get("function");
            let name = fn_obj
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let args_str = fn_obj
                .and_then(|f| f.get("arguments"))
                .and_then(Value::as_str)
                .unwrap_or("{}");
            let input = serde_json::from_str::<Value>(args_str).unwrap_or_else(|_| json!({}));
            content_blocks.push(json!({
                "type": "tool_use",
                "id": id,
                "name": name,
                "input": input,
            }));
        }
    }
    if content_blocks.is_empty() {
        content_blocks.push(json!({ "type": "text", "text": "" }));
    }

    let finish_reason = choice
        .and_then(|c| c.get("finish_reason"))
        .and_then(Value::as_str)
        .unwrap_or("stop");
    let stop_reason = match finish_reason {
        "tool_calls" => "tool_use",
        "length" => "max_tokens",
        _ => "end_turn",
    };

    let usage = oa.get("usage");
    let in_tok = usage
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let out_tok = usage
        .and_then(|u| u.get("completion_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(0);

    json!({
        "id": format!("msg_{}", Uuid::new_v4().simple()),
        "type": "message",
        "role": "assistant",
        "model": requested_model,
        "content": content_blocks,
        "stop_reason": stop_reason,
        "stop_sequence": null,
        "usage": {
            "input_tokens": in_tok,
            "output_tokens": out_tok,
        }
    })
}

pub fn responses_to_chat_request(body: &Value) -> Value {
    if body.get("messages").is_some() {
        return body.clone();
    }
    let mut messages = Vec::new();
    if let Some(inst) = body.get("instructions").and_then(Value::as_str) {
        if !inst.is_empty() {
            messages.push(json!({ "role": "system", "content": inst }));
        }
    }
    match body.get("input") {
        Some(Value::String(s)) => {
            messages.push(json!({ "role": "user", "content": s }));
        }
        Some(Value::Array(items)) => {
            for item in items {
                let role = item.get("role").and_then(Value::as_str).unwrap_or("user");
                let content = extract_openai_message_text(item.get("content"));
                if !content.is_empty() {
                    messages.push(json!({ "role": role, "content": content }));
                }
            }
        }
        _ => {}
    }
    let mut out = json!({
        "model": body.get("model").and_then(Value::as_str).unwrap_or(""),
        "messages": messages,
        "stream": body.get("stream").and_then(Value::as_bool).unwrap_or(false),
    });
    if let Some(max_tok) = body.get("max_output_tokens").or_else(|| body.get("max_tokens")) {
        out["max_tokens"] = max_tok.clone();
    }
    if let Some(temp) = body.get("temperature") {
        out["temperature"] = temp.clone();
    }
    out
}

pub fn chat_to_responses_json(oa: &Value, requested_model: &str) -> Value {
    let choice = oa
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|a| a.first());
    let text = choice
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let usage = oa.get("usage");
    let in_tok = usage
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let out_tok = usage
        .and_then(|u| u.get("completion_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(0);

    let msg_id = format!("msg_{}", Uuid::new_v4().simple());
    json!({
        "id": format!("resp_{}", Uuid::new_v4().simple()),
        "object": "response",
        "created_at": Utc::now().timestamp(),
        "status": "completed",
        "model": requested_model,
        "output": [{
            "type": "message",
            "id": msg_id,
            "status": "completed",
            "role": "assistant",
            "content": [{
                "type": "output_text",
                "text": text,
                "annotations": []
            }]
        }],
        "output_text": text,
        "usage": {
            "input_tokens": in_tok,
            "output_tokens": out_tok,
            "total_tokens": in_tok + out_tok,
        }
    })
}
