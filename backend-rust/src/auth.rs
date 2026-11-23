use crate::config::AppConfig;
use crate::db::{ApiKeyRecord, DbStore};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

pub const DASHBOARD_SESSION_COOKIE: &str = "auth_token";

#[derive(Debug, Serialize, Deserialize)]
pub struct DashboardJwtClaims {
    pub authenticated: bool,
    pub iat: usize,
    pub exp: usize,
    pub jti: String,
}

pub fn resolve_jwt_secret(config: &AppConfig, db: &DbStore) -> Option<String> {
    config
        .jwt_secret_env
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| db.get_persisted_secret("jwtSecret"))
        .or_else(|| db.get_persisted_secret("JWT_SECRET"))
}

pub fn mint_dashboard_session_token(secret: &str) -> Option<String> {
    let now = Utc::now().timestamp() as usize;
    let exp = now + 30 * 24 * 3600;
    let claims = DashboardJwtClaims {
        authenticated: true,
        iat: now,
        exp,
        jti: Uuid::new_v4().to_string(),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .ok()
}

pub fn verify_dashboard_session_token(token: &str, secret: &str, db: &DbStore) -> bool {
    if token.is_empty() || secret.is_empty() {
        return false;
    }
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    let Ok(token_data) = decode::<Value>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    ) else {
        return false;
    };
    let claims = &token_data.claims;
    if claims.get("authenticated").and_then(Value::as_bool) != Some(true) {
        return false;
    }
    if let Ok(Some(Value::Number(valid_after))) = db.get_kv_json("settings", "sessionsValidAfter") {
        let iat = claims.get("iat").and_then(Value::as_i64).unwrap_or(0);
        if let Some(va) = valid_after.as_i64() {
            if iat < va {
                return false;
            }
        }
    }
    true
}

pub fn extract_bearer_or_api_key(headers: &HeaderMap) -> Option<String> {
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        let trimmed = auth.trim();
        if let Some(rest) = trimmed
            .strip_prefix("Bearer ")
            .or_else(|| trimmed.strip_prefix("bearer "))
        {
            let token = rest.trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    if let Some(x_key) = headers
        .get("x-api-key")
        .or_else(|| headers.get("x-goog-api-key"))
        .and_then(|v| v.to_str().ok())
    {
        let token = x_key.trim();
        if !token.is_empty() {
            return Some(token.to_string());
        }
    }
    None
}

pub fn extract_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    for val in headers.get_all("cookie") {
        let Ok(s) = val.to_str() else { continue };
        for part in s.split(';') {
            let trimmed = part.trim();
            if let Some(eq_idx) = trimmed.find('=') {
                let k = trimmed[..eq_idx].trim();
                let v = trimmed[eq_idx + 1..].trim();
                if k == cookie_name && !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

pub fn verify_client_gateway_auth(
    headers: &HeaderMap,
    config: &AppConfig,
    db: &DbStore,
) -> Result<Option<ApiKeyRecord>, Response> {
    let require_api_key = db.is_feature_flag_enabled("REQUIRE_API_KEY", true);
    let token = extract_bearer_or_api_key(headers);

    if let Some(tok) = token {
        if let Ok(Some(record)) = db.verify_client_api_key(&tok) {
            return Ok(Some(record));
        }
        if let Some(secret) = resolve_jwt_secret(config, db) {
            if verify_dashboard_session_token(&tok, &secret, db) {
                return Ok(None);
            }
        }
        if require_api_key {
            let corr_id = Uuid::new_v4().to_string();
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": {
                        "code": "AUTH_001",
                        "type": "invalid_request_error",
                        "message": "Invalid API key provided",
                        "correlation_id": corr_id,
                    }
                })),
            )
                .into_response());
        }
    } else if let Some(cookie_tok) = extract_cookie(headers, DASHBOARD_SESSION_COOKIE) {
        if let Some(secret) = resolve_jwt_secret(config, db) {
            if verify_dashboard_session_token(&cookie_tok, &secret, db) {
                return Ok(None);
            }
        }
    }

    if require_api_key {
        let corr_id = Uuid::new_v4().to_string();
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": {
                    "code": "AUTH_002",
                    "type": "invalid_request_error",
                    "message": "Authentication required",
                    "correlation_id": corr_id,
                }
            })),
        )
            .into_response());
    }

    Ok(None)
}

pub fn verify_management_auth(
    headers: &HeaderMap,
    config: &AppConfig,
    db: &DbStore,
) -> Result<(), Response> {
    let require_login = match db.get_kv_json("settings", "requireLogin").ok().flatten() {
        Some(Value::Bool(b)) => b,
        Some(Value::String(s)) => s != "false" && s != "0",
        _ => true,
    };
    if !require_login {
        return Ok(());
    }

    if let Some(secret) = resolve_jwt_secret(config, db) {
        if let Some(cookie_tok) = extract_cookie(headers, DASHBOARD_SESSION_COOKIE) {
            if verify_dashboard_session_token(&cookie_tok, &secret, db) {
                return Ok(());
            }
        }
        if let Some(bearer) = extract_bearer_or_api_key(headers) {
            if verify_dashboard_session_token(&bearer, &secret, db) {
                return Ok(());
            }
        }
    }

    if let Some(bearer) = extract_bearer_or_api_key(headers) {
        if let Ok(Some(api_key)) = db.verify_client_api_key(&bearer) {
            let has_manage = api_key.scopes.is_empty()
                || api_key.scopes.iter().any(|s| {
                    matches!(
                        s.as_str(),
                        "manage" | "admin" | "*" | "all" | "management"
                    )
                });
            if has_manage {
                return Ok(());
            }
        }
    }

    Err((
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": {
                "message": "Authentication required",
                "type": "authentication_error",
            }
        })),
    )
        .into_response())
}

pub fn verify_management_password(password: &str, db: &DbStore) -> bool {
    if let Ok(Some(val)) = db.get_kv_json("settings", "password") {
        if let Some(stored) = val.as_str() {
            if stored.starts_with("$2a$") || stored.starts_with("$2b$") || stored.starts_with("$2y$")
            {
                return bcrypt::verify(password, stored).unwrap_or(false);
            } else {
                return stored == password;
            }
        }
    }
    if let Ok(env_pw) = std::env::var("INITIAL_PASSWORD") {
        if !env_pw.is_empty() {
            return env_pw == password;
        }
    }
    password == "123456"
}
