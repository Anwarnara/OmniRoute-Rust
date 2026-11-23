use crate::config::builtin_google_oauth_client;
use crate::db::{DbStore, ProviderConnection, ProviderNode};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamFormat {
    OpenAI,
    Antigravity,
    Anthropic,
}

#[derive(Clone, Debug)]
pub struct ResolvedUpstream {
    pub provider_id: String,
    pub connection: ProviderConnection,
    pub format: UpstreamFormat,
    pub base_url: String,
    pub chat_url: String,
    pub models_url: String,
    pub upstream_model: String,
    pub custom_headers: HashMap<String, String>,
    pub fallback_chat_urls: Vec<String>,
}

pub struct BuiltinProviderSpec {
    pub id: &'static str,
    pub alias: &'static str,
    pub base_url: &'static str,
    pub format: UpstreamFormat,
}

pub const BUILTIN_PROVIDERS: &[BuiltinProviderSpec] = &[
    BuiltinProviderSpec {
        id: "openai",
        alias: "oa",
        base_url: "https://api.openai.com/v1",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "anthropic",
        alias: "cc",
        base_url: "https://api.anthropic.com/v1",
        format: UpstreamFormat::Anthropic,
    },
    BuiltinProviderSpec {
        id: "claude",
        alias: "cc",
        base_url: "https://api.anthropic.com/v1",
        format: UpstreamFormat::Anthropic,
    },
    BuiltinProviderSpec {
        id: "antigravity",
        alias: "ag",
        base_url: "https://daily-cloudcode-pa.googleapis.com",
        format: UpstreamFormat::Antigravity,
    },
    BuiltinProviderSpec {
        id: "agy",
        alias: "agy",
        base_url: "https://daily-cloudcode-pa.googleapis.com",
        format: UpstreamFormat::Antigravity,
    },
    BuiltinProviderSpec {
        id: "gemini",
        alias: "gemini",
        base_url: "https://generativelanguage.googleapis.com/v1beta/openai",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "openrouter",
        alias: "or",
        base_url: "https://openrouter.ai/api/v1",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "groq",
        alias: "groq",
        base_url: "https://api.groq.com/openai/v1",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "deepseek",
        alias: "ds",
        base_url: "https://api.deepseek.com/v1",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "mistral",
        alias: "mistral",
        base_url: "https://api.mistral.ai/v1",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "xai",
        alias: "xai",
        base_url: "https://api.x.ai/v1",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "together",
        alias: "together",
        base_url: "https://api.together.xyz/v1",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "fireworks",
        alias: "fireworks",
        base_url: "https://api.fireworks.ai/inference/v1",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "cerebras",
        alias: "cerebras",
        base_url: "https://api.cerebras.ai/v1",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "cohere",
        alias: "cohere",
        base_url: "https://api.cohere.com/compatibility/v1",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "perplexity",
        alias: "pplx",
        base_url: "https://api.perplexity.ai",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "nvidia",
        alias: "nvidia",
        base_url: "https://integrate.api.nvidia.com/v1",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "zai",
        alias: "zai",
        base_url: "https://api.z.ai/api/paas/v4",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "glm",
        alias: "glm",
        base_url: "https://api.z.ai/api/paas/v4",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "moonshot",
        alias: "kimi",
        base_url: "https://api.moonshot.cn/v1",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "kimi",
        alias: "kimi",
        base_url: "https://api.moonshot.cn/v1",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "alibaba",
        alias: "qwen",
        base_url: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "qwen",
        alias: "qwen",
        base_url: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        format: UpstreamFormat::OpenAI,
    },
    BuiltinProviderSpec {
        id: "ollama",
        alias: "ollama",
        base_url: "http://127.0.0.1:11434/v1",
        format: UpstreamFormat::OpenAI,
    },
];

pub fn find_builtin_provider(id_or_alias: &str) -> Option<&'static BuiltinProviderSpec> {
    let lower = id_or_alias.to_lowercase();
    BUILTIN_PROVIDERS
        .iter()
        .find(|p| p.id == lower || p.alias == lower)
}

pub fn resolve_upstream_for_connection(
    conn: &ProviderConnection,
    nodes: &[ProviderNode],
    raw_model: &str,
) -> Result<ResolvedUpstream> {
    let provider_id = conn.provider.clone();
    let matching_node = nodes.iter().find(|n| n.id == provider_id);

    let psd = &conn.provider_specific_data;
    let psd_base_url = psd
        .get("baseUrl")
        .or_else(|| psd.get("base_url"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let psd_prefix = psd
        .get("prefix")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let mut custom_headers = HashMap::new();
    if let Some(node) = matching_node {
        if let Some(obj) = node.custom_headers.as_object() {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    custom_headers.insert(k.clone(), s.to_string());
                }
            }
        }
    }
    if let Some(obj) = psd.get("customHeaders").and_then(Value::as_object) {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                custom_headers.insert(k.clone(), s.to_string());
            }
        }
    }

    if provider_id == "antigravity" || provider_id == "agy" {
        let stripped = strip_model_prefix(raw_model, &[&provider_id, "ag", "agy", "antigravity"]);
        let upstream_model = crate::translator::clean_antigravity_model_name(&stripped);
        let primary_url =
            "https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse"
                .to_string();
        let fallback_url =
            "https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse"
                .to_string();
        return Ok(ResolvedUpstream {
            provider_id,
            connection: conn.clone(),
            format: UpstreamFormat::Antigravity,
            base_url: "https://daily-cloudcode-pa.googleapis.com".to_string(),
            chat_url: primary_url.clone(),
            models_url: "https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels"
                .to_string(),
            upstream_model,
            custom_headers,
            fallback_chat_urls: vec![primary_url, fallback_url],
        });
    }

    if let Some(node) = matching_node {
        let base_url = psd_base_url
            .unwrap_or(&node.base_url)
            .trim_end_matches('/')
            .to_string();
        let prefix = psd_prefix.unwrap_or(&node.prefix);
        let stripped = strip_model_prefix(raw_model, &[&provider_id, prefix, &node.name]);
        let format = if node.node_type.contains("anthropic")
            || node.api_type.as_deref() == Some("messages")
        {
            UpstreamFormat::Anthropic
        } else {
            UpstreamFormat::OpenAI
        };
        let chat_path = node
            .chat_path
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(match format {
                UpstreamFormat::Anthropic => "/messages",
                _ => "/chat/completions",
            });
        let models_path = node
            .models_path
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("/models");
        let chat_url = join_base_and_path(&base_url, chat_path);
        let models_url = join_base_and_path(&base_url, models_path);

        return Ok(ResolvedUpstream {
            provider_id,
            connection: conn.clone(),
            format,
            base_url,
            chat_url: chat_url.clone(),
            models_url,
            upstream_model: stripped,
            custom_headers,
            fallback_chat_urls: vec![chat_url],
        });
    }

    if let Some(base_url_raw) = psd_base_url {
        let base_url = base_url_raw.trim_end_matches('/').to_string();
        let mut prefixes = vec![provider_id.as_str()];
        if let Some(p) = psd_prefix {
            prefixes.push(p);
        }
        let stripped = strip_model_prefix(raw_model, &prefixes);
        let format = if provider_id.contains("anthropic") {
            UpstreamFormat::Anthropic
        } else {
            UpstreamFormat::OpenAI
        };
        let chat_url = join_base_and_path(
            &base_url,
            match format {
                UpstreamFormat::Anthropic => "/messages",
                _ => "/chat/completions",
            },
        );
        let models_url = join_base_and_path(&base_url, "/models");
        return Ok(ResolvedUpstream {
            provider_id,
            connection: conn.clone(),
            format,
            base_url,
            chat_url: chat_url.clone(),
            models_url,
            upstream_model: stripped,
            custom_headers,
            fallback_chat_urls: vec![chat_url],
        });
    }

    if let Some(spec) = find_builtin_provider(&provider_id) {
        let base_url = spec.base_url.trim_end_matches('/').to_string();
        let stripped = strip_model_prefix(raw_model, &[spec.id, spec.alias, &provider_id]);
        let chat_url = join_base_and_path(
            &base_url,
            match spec.format {
                UpstreamFormat::Anthropic => "/messages",
                _ => "/chat/completions",
            },
        );
        let models_url = join_base_and_path(&base_url, "/models");
        return Ok(ResolvedUpstream {
            provider_id,
            connection: conn.clone(),
            format: spec.format,
            base_url,
            chat_url: chat_url.clone(),
            models_url,
            upstream_model: stripped,
            custom_headers,
            fallback_chat_urls: vec![chat_url],
        });
    }

    Err(anyhow!(
        "Unable to resolve upstream URL for provider '{}'",
        provider_id
    ))
}

pub fn strip_model_prefix(raw_model: &str, prefixes: &[&str]) -> String {
    let trimmed = raw_model.trim();
    for pref in prefixes {
        if pref.is_empty() {
            continue;
        }
        let with_slash = format!("{}/", pref);
        if trimmed.len() > with_slash.len()
            && trimmed[..with_slash.len()].eq_ignore_ascii_case(&with_slash)
        {
            return trimmed[with_slash.len()..].to_string();
        }
    }
    trimmed.to_string()
}

fn join_base_and_path(base: &str, path: &str) -> String {
    let b = base.trim_end_matches('/');
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }
    let p = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };
    if b.ends_with(&p) {
        b.to_string()
    } else {
        format!("{}{}", b, p)
    }
}

pub fn antigravity_user_agent(conn: &ProviderConnection) -> String {
    let profile = conn
        .provider_specific_data
        .get("clientProfile")
        .and_then(Value::as_str)
        .unwrap_or(if conn.provider == "agy" { "cli" } else { "ide" });
    if profile == "cli" || conn.provider == "agy" {
        "antigravity/cli/1.4.4 (aidev_client; os_type=linux; arch=amd64; cl=1003595037; auth_method=consumer)"
            .to_string()
    } else {
        "antigravity/ide/1.107.0 darwin/arm64".to_string()
    }
}

pub fn is_token_near_expiry(conn: &ProviderConnection, lead_seconds: i64) -> bool {
    let exp_str = conn
        .expires_at
        .as_deref()
        .or(conn.token_expires_at.as_deref());
    let Some(s) = exp_str else {
        return false;
    };
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        let remaining = dt.with_timezone(&Utc).timestamp() - Utc::now().timestamp();
        return remaining <= lead_seconds;
    }
    if let Ok(ms) = s.parse::<i64>() {
        let now_ms = Utc::now().timestamp_millis();
        return (ms - now_ms) <= lead_seconds * 1000;
    }
    false
}

pub async fn ensure_fresh_access_token(
    http: &Client,
    db: &DbStore,
    conn: &mut ProviderConnection,
    force_refresh: bool,
) -> Result<String> {
    if !force_refresh {
        if let Some(at) = &conn.access_token {
            if !at.is_empty() && !is_token_near_expiry(conn, 600) {
                return Ok(at.clone());
            }
        }
    }

    if matches!(conn.provider.as_str(), "antigravity" | "agy" | "gemini") {
        if let Some(rt) = conn.refresh_token.clone().filter(|s| !s.is_empty()) {
            let (client_id, client_secret) = builtin_google_oauth_client(&conn.provider);
            let ua = antigravity_user_agent(conn);
            let form = [
                ("grant_type", "refresh_token"),
                ("refresh_token", rt.as_str()),
                ("client_id", client_id.as_str()),
                ("client_secret", client_secret.as_str()),
            ];
            let resp = http
                .post("https://oauth2.googleapis.com/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .header("User-Agent", ua)
                .form(&form)
                .send()
                .await?;

            if resp.status().is_success() {
                let body: Value = resp.json().await?;
                if let Some(new_at) = body.get("access_token").and_then(Value::as_str) {
                    let new_rt = body.get("refresh_token").and_then(Value::as_str);
                    let expires_in = body.get("expires_in").and_then(Value::as_i64);
                    let _ = db.update_connection_tokens(&conn.id, new_at, new_rt, expires_in);
                    conn.access_token = Some(new_at.to_string());
                    if let Some(r) = new_rt {
                        conn.refresh_token = Some(r.to_string());
                    }
                    return Ok(new_at.to_string());
                }
            } else {
                let status = resp.status();
                let err_txt = resp.text().await.unwrap_or_default();
                if !force_refresh {
                    if let Some(existing) = &conn.access_token {
                        if !existing.is_empty() {
                            return Ok(existing.clone());
                        }
                    }
                }
                return Err(anyhow!(
                    "Google OAuth token refresh failed ({}): {}",
                    status,
                    err_txt
                ));
            }
        }
    }

    conn.access_token
        .clone()
        .or_else(|| conn.api_key.clone())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("No valid access_token or api_key on connection {}", conn.id))
}
