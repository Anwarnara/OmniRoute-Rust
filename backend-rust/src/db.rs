use crate::crypto::{mask_secret, opaque_token_fingerprint, CryptoEngine};
use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Clone)]
pub struct DbStore {
    pub db_path: PathBuf,
    pub crypto: CryptoEngine,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderConnection {
    pub id: String,
    pub provider: String,
    pub auth_type: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub priority: i64,
    pub is_active: bool,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<String>,
    pub token_expires_at: Option<String>,
    pub scope: Option<String>,
    pub project_id: Option<String>,
    pub test_status: Option<String>,
    pub error_code: Option<String>,
    pub last_error: Option<String>,
    pub last_error_at: Option<String>,
    pub last_error_type: Option<String>,
    pub last_error_source: Option<String>,
    pub backoff_level: i64,
    pub rate_limited_until: Option<String>,
    pub health_check_interval: Option<i64>,
    pub last_health_check_at: Option<String>,
    pub last_tested: Option<String>,
    pub api_key: Option<String>,
    pub id_token: Option<String>,
    pub provider_specific_data: Value,
    pub expires_in: Option<i64>,
    pub display_name: Option<String>,
    pub global_priority: Option<i64>,
    pub default_model: Option<String>,
    pub token_type: Option<String>,
    pub consecutive_use_count: i64,
    pub rate_limit_protection: bool,
    pub last_used_at: Option<String>,
    pub group: Option<String>,
    pub max_concurrent: Option<i64>,
    pub proxy_enabled: bool,
    pub per_key_proxy_enabled: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub credential_decrypt_failed: bool,
}

impl ProviderConnection {
    pub fn to_api_json(&self, reveal_keys: bool) -> Value {
        let masked_api_key = self.api_key.as_deref().map(|k| {
            if reveal_keys {
                k.to_string()
            } else {
                mask_secret(k)
            }
        });
        json!({
            "id": self.id,
            "provider": self.provider,
            "authType": self.auth_type,
            "name": self.name,
            "email": self.email,
            "priority": self.priority,
            "isActive": self.is_active,
            "hasAccessToken": self.access_token.as_ref().map(|s| !s.is_empty()).unwrap_or(false),
            "hasRefreshToken": self.refresh_token.as_ref().map(|s| !s.is_empty()).unwrap_or(false),
            "hasApiKey": self.api_key.as_ref().map(|s| !s.is_empty()).unwrap_or(false),
            "apiKey": masked_api_key,
            "expiresAt": self.expires_at,
            "tokenExpiresAt": self.token_expires_at,
            "scope": self.scope,
            "projectId": self.project_id,
            "testStatus": self.test_status,
            "errorCode": self.error_code,
            "lastError": self.last_error,
            "lastErrorAt": self.last_error_at,
            "lastErrorType": self.last_error_type,
            "lastErrorSource": self.last_error_source,
            "backoffLevel": self.backoff_level,
            "rateLimitedUntil": self.rate_limited_until,
            "healthCheckInterval": self.health_check_interval,
            "lastHealthCheckAt": self.last_health_check_at,
            "lastTested": self.last_tested,
            "providerSpecificData": self.provider_specific_data,
            "expiresIn": self.expires_in,
            "displayName": self.display_name,
            "globalPriority": self.global_priority,
            "defaultModel": self.default_model,
            "tokenType": self.token_type,
            "consecutiveUseCount": self.consecutive_use_count,
            "rateLimitProtection": self.rate_limit_protection,
            "lastUsedAt": self.last_used_at,
            "group": self.group,
            "maxConcurrent": self.max_concurrent,
            "proxyEnabled": self.proxy_enabled,
            "perKeyProxyEnabled": self.per_key_proxy_enabled,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
            "credentialDecryptFailed": self.credential_decrypt_failed,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderNode {
    pub id: String,
    pub node_type: String,
    pub name: String,
    pub prefix: String,
    pub api_type: Option<String>,
    pub base_url: String,
    pub chat_path: Option<String>,
    pub models_path: Option<String>,
    pub custom_headers: Value,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub icon_url: Option<String>,
    pub daily_quota_reset_timezone: Option<String>,
    pub daily_quota_reset_hour: Option<i64>,
    pub custom_json_config: Value,
}

impl ProviderNode {
    pub fn to_api_json(&self) -> Value {
        json!({
            "id": self.id,
            "type": self.node_type,
            "name": self.name,
            "prefix": self.prefix,
            "apiType": self.api_type,
            "baseUrl": self.base_url,
            "chatPath": self.chat_path,
            "modelsPath": self.models_path,
            "customHeaders": self.custom_headers,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
            "iconUrl": self.icon_url,
            "dailyQuotaResetTimezone": self.daily_quota_reset_timezone,
            "dailyQuotaResetHour": self.daily_quota_reset_hour,
            "customJsonConfig": self.custom_json_config,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiKeyRecord {
    pub id: String,
    pub name: String,
    pub key_decrypted: Option<String>,
    pub key_prefix: Option<String>,
    pub key_hash: Option<String>,
    pub machine_id: Option<String>,
    pub allowed_models: Vec<String>,
    pub blocked_models: Vec<String>,
    pub allowed_combos: Vec<String>,
    pub allowed_connections: Vec<String>,
    pub preferred_connections: Vec<String>,
    pub model_access_mode: String,
    pub scopes: Vec<String>,
    pub no_log: bool,
    pub auto_resolve: bool,
    pub is_active: bool,
    pub is_banned: bool,
    pub forced_model: Option<String>,
    pub created_at: Option<String>,
    pub revoked_at: Option<String>,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
}

impl ApiKeyRecord {
    pub fn to_api_json(&self, reveal: bool) -> Value {
        let display_key = if reveal {
            self.key_decrypted
                .clone()
                .or_else(|| self.key_prefix.clone())
                .unwrap_or_default()
        } else if let Some(k) = &self.key_decrypted {
            mask_secret(k)
        } else {
            self.key_prefix
                .as_deref()
                .map(|p| format!("{}••••", p))
                .unwrap_or_default()
        };
        json!({
            "id": self.id,
            "name": self.name,
            "key": display_key,
            "keyPrefix": self.key_prefix,
            "machineId": self.machine_id,
            "allowedModels": self.allowed_models,
            "blockedModels": self.blocked_models,
            "allowedCombos": self.allowed_combos,
            "allowedConnections": self.allowed_connections,
            "preferredConnections": self.preferred_connections,
            "modelAccessMode": self.model_access_mode,
            "scopes": self.scopes,
            "noLog": self.no_log,
            "autoResolve": self.auto_resolve,
            "isActive": self.is_active,
            "isBanned": self.is_banned,
            "forcedModel": self.forced_model,
            "createdAt": self.created_at,
            "revokedAt": self.revoked_at,
            "expiresAt": self.expires_at,
            "lastUsedAt": self.last_used_at,
        })
    }
}

pub struct CallLogInsert {
    pub method: String,
    pub path: String,
    pub status: i64,
    pub model: String,
    pub requested_model: String,
    pub provider: String,
    pub account: Option<String>,
    pub connection_id: Option<String>,
    pub duration_ms: i64,
    pub ttft_ms: Option<i64>,
    pub tokens_in: i64,
    pub tokens_out: i64,
    pub tokens_reasoning: i64,
    pub tokens_cached: i64,
    pub request_type: String,
    pub source_format: String,
    pub target_format: String,
    pub api_key_id: Option<String>,
    pub api_key_name: Option<String>,
    pub combo_name: Option<String>,
    pub error_summary: Option<String>,
    pub correlation_id: Option<String>,
}

impl DbStore {
    pub fn new(db_path: PathBuf, crypto: CryptoEngine) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let store = Self { db_path, crypto };
        store.ensure_base_schema()?;
        Ok(store)
    }

    pub fn conn(&self) -> Result<Connection> {
        let conn = Connection::open(&self.db_path)
            .with_context(|| format!("Failed to open SQLite DB at {}", self.db_path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;",
        )?;
        Ok(conn)
    }

    fn ensure_base_schema(&self) -> Result<()> {
        let conn = self.conn()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS key_value (
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                PRIMARY KEY (namespace, key)
            );
            CREATE TABLE IF NOT EXISTS provider_connections (
                id TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                auth_type TEXT NOT NULL DEFAULT 'apikey',
                name TEXT,
                email TEXT,
                priority INTEGER NOT NULL DEFAULT 1,
                is_active INTEGER NOT NULL DEFAULT 1,
                access_token TEXT,
                refresh_token TEXT,
                expires_at TEXT,
                token_expires_at TEXT,
                scope TEXT,
                project_id TEXT,
                test_status TEXT,
                error_code TEXT,
                last_error TEXT,
                last_error_at TEXT,
                last_error_type TEXT,
                last_error_source TEXT,
                backoff_level INTEGER NOT NULL DEFAULT 0,
                rate_limited_until TEXT,
                health_check_interval INTEGER,
                last_health_check_at TEXT,
                last_tested TEXT,
                api_key TEXT,
                id_token TEXT,
                provider_specific_data TEXT,
                expires_in INTEGER,
                display_name TEXT,
                global_priority INTEGER,
                default_model TEXT,
                token_type TEXT,
                consecutive_use_count INTEGER DEFAULT 0,
                rate_limit_protection INTEGER DEFAULT 0,
                last_used_at TEXT,
                \"group\" TEXT,
                max_concurrent INTEGER DEFAULT 0,
                proxy_enabled INTEGER DEFAULT 0,
                per_key_proxy_enabled INTEGER DEFAULT 0,
                quota_window_thresholds_json TEXT,
                rate_limit_overrides_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_ping_at TEXT,
                last_pinged_reset_key TEXT,
                quota_visible INTEGER DEFAULT 1,
                synced_models_at TEXT
            );
            CREATE TABLE IF NOT EXISTS provider_nodes (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                name TEXT NOT NULL,
                prefix TEXT NOT NULL,
                api_type TEXT,
                base_url TEXT NOT NULL,
                chat_path TEXT,
                models_path TEXT,
                custom_headers_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                icon_url TEXT,
                daily_quota_reset_timezone TEXT,
                daily_quota_reset_hour INTEGER,
                custom_json_config_json TEXT
            );
            CREATE TABLE IF NOT EXISTS combos (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                data TEXT NOT NULL,
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                system_message TEXT,
                tool_filter_regex TEXT,
                context_cache_protection INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                key TEXT NOT NULL,
                machine_id TEXT,
                allowed_models TEXT DEFAULT '[]',
                no_log INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                revoked_at TEXT,
                expires_at TEXT,
                last_used_at TEXT,
                key_prefix TEXT,
                ip_allowlist TEXT DEFAULT '[]',
                scopes TEXT DEFAULT '[]',
                allowed_combos TEXT DEFAULT '[]',
                throttle_delay_ms INTEGER,
                stream_default_mode TEXT DEFAULT 'legacy',
                allowed_quotas TEXT DEFAULT '[]',
                disable_non_public_models INTEGER DEFAULT 0,
                usage_limit_enabled INTEGER DEFAULT 0,
                daily_usage_limit_usd REAL,
                weekly_usage_limit_usd REAL,
                cache_default_mode TEXT DEFAULT 'legacy',
                model_access_mode TEXT DEFAULT 'all',
                compression_enabled INTEGER DEFAULT 0,
                codex_service_mode TEXT DEFAULT 'auto',
                preferred_connections TEXT DEFAULT '[]',
                source TEXT,
                five_hour_usage_limit_usd REAL,
                blocked_models TEXT DEFAULT '[]',
                allowed_connections TEXT DEFAULT '[]',
                auto_resolve INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                access_schedule TEXT,
                max_requests_per_day INTEGER,
                max_requests_per_minute INTEGER,
                max_sessions INTEGER DEFAULT 0,
                rate_limits TEXT,
                is_banned INTEGER DEFAULT 0,
                key_hash TEXT,
                proxy_id TEXT,
                allowed_endpoints TEXT DEFAULT '[]',
                allow_usage_command INTEGER DEFAULT 0,
                chaos_mode_enabled INTEGER DEFAULT 0,
                allow_auto_combos INTEGER DEFAULT 1,
                allow_cc_discovery_aliases INTEGER DEFAULT 1,
                catalog_scope TEXT DEFAULT 'all',
                forced_model TEXT
            );",
        )?;
        Ok(())
    }

    pub fn get_kv_raw(&self, namespace: &str, key: &str) -> Result<Option<String>> {
        let conn = self.conn()?;
        let val: Option<String> = conn
            .query_row(
                "SELECT value FROM key_value WHERE namespace = ?1 AND key = ?2",
                params![namespace, key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(val)
    }

    pub fn get_kv_json(&self, namespace: &str, key: &str) -> Result<Option<Value>> {
        let Some(raw) = self.get_kv_raw(namespace, key)? else {
            return Ok(None);
        };
        let parsed = serde_json::from_str::<Value>(&raw).unwrap_or(Value::String(raw));
        Ok(Some(parsed))
    }

    pub fn set_kv_json(&self, namespace: &str, key: &str, val: &Value) -> Result<()> {
        let conn = self.conn()?;
        let serialized = serde_json::to_string(val)?;
        conn.execute(
            "INSERT INTO key_value (namespace, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT(namespace, key) DO UPDATE SET value = excluded.value",
            params![namespace, key, serialized],
        )?;
        Ok(())
    }

    pub fn get_namespace_json_map(&self, namespace: &str) -> Result<Map<String, Value>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT key, value FROM key_value WHERE namespace = ?1")?;
        let rows = stmt.query_map(params![namespace], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut map = Map::new();
        for r in rows {
            let (k, v) = r?;
            let parsed = serde_json::from_str::<Value>(&v).unwrap_or(Value::String(v));
            map.insert(k, parsed);
        }
        Ok(map)
    }

    pub fn get_persisted_secret(&self, key: &str) -> Option<String> {
        let raw = self.get_kv_raw("secrets", key).ok()??;
        let stored = serde_json::from_str::<String>(&raw).unwrap_or(raw);
        self.crypto.decrypt(&stored)
    }

    pub fn is_feature_flag_enabled(&self, key: &str, default_val: bool) -> bool {
        match self.get_kv_json("feature_flags", key).ok().flatten() {
            Some(Value::Bool(b)) => b,
            Some(Value::String(s)) => matches!(s.to_lowercase().as_str(), "true" | "1" | "yes"),
            Some(Value::Number(n)) => n.as_i64().unwrap_or(0) != 0,
            _ => default_val,
        }
    }

    pub fn list_provider_connections(
        &self,
        provider_filter: Option<&str>,
        only_active: bool,
    ) -> Result<Vec<ProviderConnection>> {
        let conn = self.conn()?;
        let mut sql = String::from(
            "SELECT id, provider, auth_type, name, email, priority, is_active,
                    access_token, refresh_token, expires_at, token_expires_at,
                    scope, project_id, test_status, error_code, last_error,
                    last_error_at, last_error_type, last_error_source,
                    COALESCE(backoff_level, 0), rate_limited_until,
                    health_check_interval, last_health_check_at, last_tested,
                    api_key, id_token, provider_specific_data, expires_in,
                    display_name, global_priority, default_model, token_type,
                    COALESCE(consecutive_use_count, 0), COALESCE(rate_limit_protection, 0),
                    last_used_at, \"group\", max_concurrent,
                    COALESCE(proxy_enabled, 0), COALESCE(per_key_proxy_enabled, 0),
                    created_at, updated_at
             FROM provider_connections WHERE 1=1",
        );
        if only_active {
            sql.push_str(" AND is_active = 1");
        }
        if provider_filter.is_some() {
            sql.push_str(" AND provider = ?1");
        }
        sql.push_str(" ORDER BY priority ASC, created_at ASC");

        let mut stmt = conn.prepare(&sql)?;
        let mapper = |row: &rusqlite::Row<'_>| -> rusqlite::Result<ProviderConnection> {
            let raw_access: Option<String> = row.get(7)?;
            let raw_refresh: Option<String> = row.get(8)?;
            let raw_api_key: Option<String> = row.get(24)?;
            let raw_id_token: Option<String> = row.get(25)?;
            let raw_psd: Option<String> = row.get(26)?;

            let (access_token, f1) = self.crypto.decrypt_opt(raw_access);
            let (refresh_token, f2) = self.crypto.decrypt_opt(raw_refresh);
            let (api_key, f3) = self.crypto.decrypt_opt(raw_api_key);
            let (id_token, f4) = self.crypto.decrypt_opt(raw_id_token);

            let mut psd = raw_psd
                .as_deref()
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
                .unwrap_or_else(|| json!({}));
            self.crypto.decrypt_json_secrets(&mut psd);

            Ok(ProviderConnection {
                id: row.get(0)?,
                provider: row.get(1)?,
                auth_type: row.get::<_, Option<String>>(2)?.unwrap_or_else(|| "apikey".to_string()),
                name: row.get(3)?,
                email: row.get(4)?,
                priority: row.get::<_, Option<i64>>(5)?.unwrap_or(1),
                is_active: row.get::<_, Option<i64>>(6)?.unwrap_or(1) != 0,
                access_token,
                refresh_token,
                expires_at: row.get(9)?,
                token_expires_at: row.get(10)?,
                scope: row.get(11)?,
                project_id: row.get(12)?,
                test_status: row.get(13)?,
                error_code: row.get(14)?,
                last_error: row.get(15)?,
                last_error_at: row.get(16)?,
                last_error_type: row.get(17)?,
                last_error_source: row.get(18)?,
                backoff_level: row.get(19)?,
                rate_limited_until: row.get(20)?,
                health_check_interval: row.get(21)?,
                last_health_check_at: row.get(22)?,
                last_tested: row.get(23)?,
                api_key,
                id_token,
                provider_specific_data: psd,
                expires_in: row.get(27)?,
                display_name: row.get(28)?,
                global_priority: row.get(29)?,
                default_model: row.get(30)?,
                token_type: row.get(31)?,
                consecutive_use_count: row.get(32)?,
                rate_limit_protection: row.get::<_, i64>(33)? != 0,
                last_used_at: row.get(34)?,
                group: row.get(35)?,
                max_concurrent: row.get(36)?,
                proxy_enabled: row.get::<_, i64>(37)? != 0,
                per_key_proxy_enabled: row.get::<_, i64>(38)? != 0,
                created_at: row.get(39)?,
                updated_at: row.get(40)?,
                credential_decrypt_failed: f1 || f2 || f3 || f4,
            })
        };

        let mut out = Vec::new();
        if let Some(pf) = provider_filter {
            let rows = stmt.query_map(params![pf], mapper)?;
            for r in rows {
                out.push(r?);
            }
        } else {
            let rows = stmt.query_map([], mapper)?;
            for r in rows {
                out.push(r?);
            }
        }
        Ok(out)
    }

    pub fn get_provider_connection_by_id(&self, id: &str) -> Result<Option<ProviderConnection>> {
        let all = self.list_provider_connections(None, false)?;
        Ok(all.into_iter().find(|c| c.id == id))
    }

    pub fn create_provider_connection(&self, payload: &Value) -> Result<ProviderConnection> {
        let conn = self.conn()?;
        let id = payload
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let provider = payload
            .get("provider")
            .and_then(Value::as_str)
            .unwrap_or("openai")
            .to_string();
        let auth_type = payload
            .get("authType")
            .or_else(|| payload.get("auth_type"))
            .and_then(Value::as_str)
            .unwrap_or("apikey")
            .to_string();
        let name = payload
            .get("name")
            .and_then(Value::as_str)
            .map(String::from);
        let email = payload
            .get("email")
            .and_then(Value::as_str)
            .map(String::from);
        let priority = payload
            .get("priority")
            .and_then(Value::as_i64)
            .unwrap_or(1);
        let is_active = payload
            .get("isActive")
            .or_else(|| payload.get("is_active"))
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let project_id = payload
            .get("projectId")
            .or_else(|| payload.get("project_id"))
            .and_then(Value::as_str)
            .map(String::from);
        let default_model = payload
            .get("defaultModel")
            .or_else(|| payload.get("default_model"))
            .and_then(Value::as_str)
            .map(String::from);
        let group = payload
            .get("group")
            .and_then(Value::as_str)
            .map(String::from);

        let api_key_enc = payload
            .get("apiKey")
            .or_else(|| payload.get("api_key"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(|s| self.crypto.encrypt(s));
        let access_token_enc = payload
            .get("accessToken")
            .or_else(|| payload.get("access_token"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(|s| self.crypto.encrypt(s));
        let refresh_token_enc = payload
            .get("refreshToken")
            .or_else(|| payload.get("refresh_token"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(|s| self.crypto.encrypt(s));
        let id_token_enc = payload
            .get("idToken")
            .or_else(|| payload.get("id_token"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(|s| self.crypto.encrypt(s));

        let mut psd = payload
            .get("providerSpecificData")
            .or_else(|| payload.get("provider_specific_data"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        self.crypto.encrypt_json_secrets(&mut psd);
        let psd_str = serde_json::to_string(&psd)?;

        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO provider_connections (
                id, provider, auth_type, name, email, priority, is_active,
                api_key, access_token, refresh_token, id_token, project_id,
                default_model, \"group\", provider_specific_data, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?16)",
            params![
                id,
                provider,
                auth_type,
                name,
                email,
                priority,
                if is_active { 1 } else { 0 },
                api_key_enc,
                access_token_enc,
                refresh_token_enc,
                id_token_enc,
                project_id,
                default_model,
                group,
                psd_str,
                now
            ],
        )?;

        self.get_provider_connection_by_id(&id)?
            .context("Created connection not found")
    }

    pub fn update_provider_connection(
        &self,
        id: &str,
        payload: &Value,
    ) -> Result<Option<ProviderConnection>> {
        let Some(existing) = self.get_provider_connection_by_id(id)? else {
            return Ok(None);
        };
        let conn = self.conn()?;
        let name = payload
            .get("name")
            .and_then(Value::as_str)
            .map(String::from)
            .or(existing.name);
        let email = payload
            .get("email")
            .and_then(Value::as_str)
            .map(String::from)
            .or(existing.email);
        let priority = payload
            .get("priority")
            .and_then(Value::as_i64)
            .unwrap_or(existing.priority);
        let is_active = payload
            .get("isActive")
            .or_else(|| payload.get("is_active"))
            .and_then(Value::as_bool)
            .unwrap_or(existing.is_active);
        let project_id = payload
            .get("projectId")
            .or_else(|| payload.get("project_id"))
            .and_then(Value::as_str)
            .map(String::from)
            .or(existing.project_id);
        let default_model = payload
            .get("defaultModel")
            .or_else(|| payload.get("default_model"))
            .and_then(Value::as_str)
            .map(String::from)
            .or(existing.default_model);
        let group = payload
            .get("group")
            .and_then(Value::as_str)
            .map(String::from)
            .or(existing.group);

        let api_key_plain = payload
            .get("apiKey")
            .or_else(|| payload.get("api_key"))
            .and_then(Value::as_str)
            .map(String::from)
            .or(existing.api_key);
        let access_token_plain = payload
            .get("accessToken")
            .or_else(|| payload.get("access_token"))
            .and_then(Value::as_str)
            .map(String::from)
            .or(existing.access_token);
        let refresh_token_plain = payload
            .get("refreshToken")
            .or_else(|| payload.get("refresh_token"))
            .and_then(Value::as_str)
            .map(String::from)
            .or(existing.refresh_token);

        let api_key_enc = api_key_plain
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| self.crypto.encrypt(s));
        let access_token_enc = access_token_plain
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| self.crypto.encrypt(s));
        let refresh_token_enc = refresh_token_plain
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| self.crypto.encrypt(s));

        let mut psd = payload
            .get("providerSpecificData")
            .or_else(|| payload.get("provider_specific_data"))
            .cloned()
            .unwrap_or(existing.provider_specific_data);
        self.crypto.encrypt_json_secrets(&mut psd);
        let psd_str = serde_json::to_string(&psd)?;
        let now = Utc::now().to_rfc3339();

        conn.execute(
            "UPDATE provider_connections
             SET name = ?1, email = ?2, priority = ?3, is_active = ?4,
                 project_id = ?5, default_model = ?6, \"group\" = ?7,
                 api_key = ?8, access_token = ?9, refresh_token = ?10,
                 provider_specific_data = ?11, updated_at = ?12
             WHERE id = ?13",
            params![
                name,
                email,
                priority,
                if is_active { 1 } else { 0 },
                project_id,
                default_model,
                group,
                api_key_enc,
                access_token_enc,
                refresh_token_enc,
                psd_str,
                now,
                id
            ],
        )?;
        self.get_provider_connection_by_id(id)
    }

    pub fn delete_provider_connection(&self, id: &str) -> Result<bool> {
        let conn = self.conn()?;
        let affected = conn.execute("DELETE FROM provider_connections WHERE id = ?1", params![id])?;
        Ok(affected > 0)
    }

    pub fn update_connection_tokens(
        &self,
        id: &str,
        access_token: &str,
        refresh_token: Option<&str>,
        expires_in_secs: Option<i64>,
    ) -> Result<()> {
        let conn = self.conn()?;
        let enc_access = self.crypto.encrypt(access_token);
        let now = Utc::now();
        let expires_at = expires_in_secs
            .map(|secs| (now + chrono::Duration::seconds(secs)).to_rfc3339());
        let now_str = now.to_rfc3339();

        if let Some(rt) = refresh_token.filter(|s| !s.is_empty()) {
            let enc_refresh = self.crypto.encrypt(rt);
            conn.execute(
                "UPDATE provider_connections
                 SET access_token = ?1, refresh_token = ?2, expires_at = COALESCE(?3, expires_at),
                     token_expires_at = COALESCE(?3, token_expires_at), expires_in = COALESCE(?4, expires_in),
                     updated_at = ?5
                 WHERE id = ?6",
                params![enc_access, enc_refresh, expires_at, expires_in_secs, now_str, id],
            )?;
        } else {
            conn.execute(
                "UPDATE provider_connections
                 SET access_token = ?1, expires_at = COALESCE(?2, expires_at),
                     token_expires_at = COALESCE(?2, token_expires_at), expires_in = COALESCE(?3, expires_in),
                     updated_at = ?4
                 WHERE id = ?5",
                params![enc_access, expires_at, expires_in_secs, now_str, id],
            )?;
        }
        Ok(())
    }

    pub fn mark_connection_result(
        &self,
        id: &str,
        success: bool,
        status_code: Option<u16>,
        error_msg: Option<&str>,
    ) {
        let Ok(conn) = self.conn() else { return };
        let now = Utc::now().to_rfc3339();
        if success {
            let _ = conn.execute(
                "UPDATE provider_connections
                 SET test_status = 'active', error_code = NULL, last_error = NULL,
                     backoff_level = 0, rate_limited_until = NULL,
                     last_used_at = ?1, updated_at = ?1
                 WHERE id = ?2",
                params![now, id],
            );
        } else {
            let code_str = status_code.map(|c| c.to_string());
            let _ = conn.execute(
                "UPDATE provider_connections
                 SET error_code = ?1, last_error = ?2, last_error_at = ?3, updated_at = ?3
                 WHERE id = ?4",
                params![code_str, error_msg, now, id],
            );
        }
    }

    pub fn list_provider_nodes(&self) -> Result<Vec<ProviderNode>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, type, name, prefix, api_type, base_url, chat_path, models_path,
                    custom_headers_json, created_at, updated_at, icon_url,
                    daily_quota_reset_timezone, daily_quota_reset_hour, custom_json_config_json
             FROM provider_nodes ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let ch_raw: Option<String> = row.get(8)?;
            let cjc_raw: Option<String> = row.get(14)?;
            Ok(ProviderNode {
                id: row.get(0)?,
                node_type: row.get(1)?,
                name: row.get(2)?,
                prefix: row.get(3)?,
                api_type: row.get(4)?,
                base_url: row.get(5)?,
                chat_path: row.get(6)?,
                models_path: row.get(7)?,
                custom_headers: ch_raw
                    .as_deref()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or_else(|| json!({})),
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
                icon_url: row.get(11)?,
                daily_quota_reset_timezone: row.get(12)?,
                daily_quota_reset_hour: row.get(13)?,
                custom_json_config: cjc_raw
                    .as_deref()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(Value::Null),
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn create_provider_node(&self, payload: &Value) -> Result<ProviderNode> {
        let conn = self.conn()?;
        let node_type = payload
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("openai-compatible")
            .to_string();
        let api_type = payload
            .get("apiType")
            .or_else(|| payload.get("api_type"))
            .and_then(Value::as_str)
            .unwrap_or("chat")
            .to_string();
        let id = payload
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .unwrap_or_else(|| format!("{}-{}-{}", node_type, api_type, Uuid::new_v4()));
        let name = payload
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("Custom Node")
            .to_string();
        let prefix = payload
            .get("prefix")
            .and_then(Value::as_str)
            .unwrap_or("custom")
            .to_string();
        let base_url = payload
            .get("baseUrl")
            .or_else(|| payload.get("base_url"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let chat_path = payload
            .get("chatPath")
            .or_else(|| payload.get("chat_path"))
            .and_then(Value::as_str)
            .map(String::from);
        let models_path = payload
            .get("modelsPath")
            .or_else(|| payload.get("models_path"))
            .and_then(Value::as_str)
            .map(String::from);
        let custom_headers = payload
            .get("customHeaders")
            .or_else(|| payload.get("custom_headers"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        let now = Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO provider_nodes (
                id, type, name, prefix, api_type, base_url, chat_path, models_path,
                custom_headers_json, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
            params![
                id,
                node_type,
                name,
                prefix,
                api_type,
                base_url,
                chat_path,
                models_path,
                serde_json::to_string(&custom_headers)?,
                now
            ],
        )?;

        self.list_provider_nodes()?
            .into_iter()
            .find(|n| n.id == id)
            .context("Created provider node not found")
    }

    pub fn delete_provider_node(&self, id: &str) -> Result<bool> {
        let conn = self.conn()?;
        let affected = conn.execute("DELETE FROM provider_nodes WHERE id = ?1", params![id])?;
        Ok(affected > 0)
    }

    pub fn list_combos(&self) -> Result<Vec<Value>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, data, sort_order, created_at, updated_at,
                    system_message, tool_filter_regex, COALESCE(context_cache_protection, 0)
             FROM combos ORDER BY sort_order ASC, created_at ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            let name: String = row.get(1)?;
            let data_str: String = row.get(2)?;
            let sort_order: i64 = row.get(3)?;
            let created_at: String = row.get(4)?;
            let updated_at: String = row.get(5)?;
            let system_message: Option<String> = row.get(6)?;
            let tool_filter_regex: Option<String> = row.get(7)?;
            let ccp: i64 = row.get(8)?;

            let mut obj = serde_json::from_str::<Value>(&data_str).unwrap_or_else(|_| json!({}));
            if let Some(map) = obj.as_object_mut() {
                map.insert("id".to_string(), json!(id));
                map.insert("name".to_string(), json!(name));
                map.insert("sortOrder".to_string(), json!(sort_order));
                map.insert("createdAt".to_string(), json!(created_at));
                map.insert("updatedAt".to_string(), json!(updated_at));
                if let Some(sm) = system_message {
                    map.insert("systemMessage".to_string(), json!(sm));
                }
                if let Some(tfr) = tool_filter_regex {
                    map.insert("toolFilterRegex".to_string(), json!(tfr));
                }
                map.insert("contextCacheProtection".to_string(), json!(ccp != 0));
            }
            Ok(obj)
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn get_combo_by_name(&self, name: &str) -> Result<Option<Value>> {
        let combos = self.list_combos()?;
        Ok(combos.into_iter().find(|c| {
            c.get("name")
                .and_then(Value::as_str)
                .map(|n| n.eq_ignore_ascii_case(name))
                .unwrap_or(false)
        }))
    }

    pub fn get_combo_by_id(&self, id: &str) -> Result<Option<Value>> {
        let combos = self.list_combos()?;
        Ok(combos
            .into_iter()
            .find(|c| c.get("id").and_then(Value::as_str) == Some(id)))
    }

    pub fn create_combo(&self, payload: &Value) -> Result<Value> {
        let conn = self.conn()?;
        let id = payload
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let name = payload
            .get("name")
            .and_then(Value::as_str)
            .context("Combo name is required")?
            .to_string();
        let sort_order = payload
            .get("sortOrder")
            .or_else(|| payload.get("sort_order"))
            .and_then(Value::as_i64)
            .unwrap_or(1);
        let now = Utc::now().to_rfc3339();

        let mut data_obj = payload.clone();
        if let Some(map) = data_obj.as_object_mut() {
            map.insert("id".to_string(), json!(id));
            map.insert("name".to_string(), json!(name));
            map.insert("sortOrder".to_string(), json!(sort_order));
            map.insert("createdAt".to_string(), json!(now));
            map.insert("updatedAt".to_string(), json!(now));
            map.entry("strategy".to_string()).or_insert_with(|| json!("priority"));
            map.entry("models".to_string()).or_insert_with(|| json!([]));
        }

        conn.execute(
            "INSERT INTO combos (id, name, data, sort_order, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![id, name, serde_json::to_string(&data_obj)?, sort_order, now],
        )?;
        Ok(data_obj)
    }

    pub fn update_combo(&self, id: &str, payload: &Value) -> Result<Option<Value>> {
        let Some(mut existing) = self.get_combo_by_id(id)? else {
            return Ok(None);
        };
        let conn = self.conn()?;
        let now = Utc::now().to_rfc3339();

        if let (Some(ex_map), Some(patch_map)) = (existing.as_object_mut(), payload.as_object()) {
            for (k, v) in patch_map {
                ex_map.insert(k.clone(), v.clone());
            }
            ex_map.insert("id".to_string(), json!(id));
            ex_map.insert("updatedAt".to_string(), json!(now));
        }

        let name = existing
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("Combo")
            .to_string();
        let sort_order = existing
            .get("sortOrder")
            .and_then(Value::as_i64)
            .unwrap_or(1);

        conn.execute(
            "UPDATE combos SET name = ?1, data = ?2, sort_order = ?3, updated_at = ?4 WHERE id = ?5",
            params![name, serde_json::to_string(&existing)?, sort_order, now, id],
        )?;
        Ok(Some(existing))
    }

    pub fn delete_combo(&self, id: &str) -> Result<bool> {
        let conn = self.conn()?;
        let affected = conn.execute("DELETE FROM combos WHERE id = ?1", params![id])?;
        Ok(affected > 0)
    }

    pub fn list_api_keys(&self) -> Result<Vec<ApiKeyRecord>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, key, key_prefix, key_hash, machine_id,
                    allowed_models, blocked_models, allowed_combos,
                    allowed_connections, preferred_connections,
                    COALESCE(model_access_mode, 'all'), scopes,
                    COALESCE(no_log, 0), COALESCE(auto_resolve, 0),
                    COALESCE(is_active, 1), COALESCE(is_banned, 0),
                    forced_model, created_at, revoked_at, expires_at, last_used_at
             FROM api_keys ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let raw_key: Option<String> = row.get(2)?;
            let (key_decrypted, _) = self.crypto.decrypt_opt(raw_key);
            Ok(ApiKeyRecord {
                id: row.get(0)?,
                name: row.get(1)?,
                key_decrypted,
                key_prefix: row.get(3)?,
                key_hash: row.get(4)?,
                machine_id: row.get(5)?,
                allowed_models: parse_json_string_vec(row.get::<_, Option<String>>(6)?),
                blocked_models: parse_json_string_vec(row.get::<_, Option<String>>(7)?),
                allowed_combos: parse_json_string_vec(row.get::<_, Option<String>>(8)?),
                allowed_connections: parse_json_string_vec(row.get::<_, Option<String>>(9)?),
                preferred_connections: parse_json_string_vec(row.get::<_, Option<String>>(10)?),
                model_access_mode: row.get(11)?,
                scopes: parse_json_string_vec(row.get::<_, Option<String>>(12)?),
                no_log: row.get::<_, i64>(13)? != 0,
                auto_resolve: row.get::<_, i64>(14)? != 0,
                is_active: row.get::<_, i64>(15)? != 0,
                is_banned: row.get::<_, i64>(16)? != 0,
                forced_model: row.get(17)?,
                created_at: row.get(18)?,
                revoked_at: row.get(19)?,
                expires_at: row.get(20)?,
                last_used_at: row.get(21)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn verify_client_api_key(&self, presented_key: &str) -> Result<Option<ApiKeyRecord>> {
        let trimmed = presented_key.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let hash = opaque_token_fingerprint(trimmed);
        let keys = self.list_api_keys()?;
        for k in keys {
            if !k.is_active || k.is_banned || k.revoked_at.is_some() {
                continue;
            }
            if let Some(exp) = &k.expires_at {
                if let Ok(exp_dt) = chrono::DateTime::parse_from_rfc3339(exp) {
                    if exp_dt.with_timezone(&Utc) <= Utc::now() {
                        continue;
                    }
                }
            }
            let hash_matches = k
                .key_hash
                .as_deref()
                .map(|kh| kh.eq_ignore_ascii_case(&hash))
                .unwrap_or(false);
            let plain_matches = k
                .key_decrypted
                .as_deref()
                .map(|pk| pk == trimmed)
                .unwrap_or(false);
            if hash_matches || plain_matches {
                return Ok(Some(k));
            }
        }
        Ok(None)
    }

    pub fn create_api_key(&self, payload: &Value) -> Result<(ApiKeyRecord, String)> {
        let conn = self.conn()?;
        let id = Uuid::new_v4().to_string();
        let name = payload
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("API Key")
            .to_string();
        let raw_key = payload
            .get("key")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .unwrap_or_else(|| {
                let mut bytes = [0u8; 16];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
                format!("sk-{}", hex::encode(bytes))
            });
        let key_prefix = raw_key.chars().take(12).collect::<String>();
        let key_hash = opaque_token_fingerprint(&raw_key);
        let key_enc = self.crypto.encrypt(&raw_key);
        let now = Utc::now().to_rfc3339();
        let scopes = payload
            .get("scopes")
            .cloned()
            .unwrap_or_else(|| json!([]));

        conn.execute(
            "INSERT INTO api_keys (id, name, key, key_prefix, key_hash, scopes, is_active, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)",
            params![
                id,
                name,
                key_enc,
                key_prefix,
                key_hash,
                serde_json::to_string(&scopes)?,
                now
            ],
        )?;

        let rec = self
            .list_api_keys()?
            .into_iter()
            .find(|k| k.id == id)
            .context("Created API key not found")?;
        Ok((rec, raw_key))
    }

    pub fn delete_api_key(&self, id: &str) -> Result<bool> {
        let conn = self.conn()?;
        let affected = conn.execute("DELETE FROM api_keys WHERE id = ?1", params![id])?;
        Ok(affected > 0)
    }

    pub fn get_model_aliases(&self) -> HashMap<String, String> {
        let mut out = HashMap::new();
        if let Ok(map) = self.get_namespace_json_map("modelAliases") {
            for (k, v) in map {
                if let Some(target) = v.as_str() {
                    out.insert(k, target.to_string());
                }
            }
        }
        out
    }

    pub fn get_thought_signature(
        &self,
        connection_id: Option<&str>,
        model: &str,
        tool_call_id: &str,
    ) -> Option<String> {
        let family = if model.to_lowercase().contains("claude") {
            Some("claude")
        } else if model.to_lowercase().contains("gemini") {
            Some("gemini")
        } else {
            None
        };
        let mut candidate_keys = Vec::new();
        if let Some(cid) = connection_id {
            if let Some(fam) = family {
                candidate_keys.push(format!("{}:{}:{}", cid, fam, tool_call_id));
            }
            candidate_keys.push(format!("{}:{}", cid, tool_call_id));
        }
        candidate_keys.push(tool_call_id.to_string());

        for key in candidate_keys {
            if let Ok(Some(val)) = self.get_kv_json("gemini_thought_signatures", &key) {
                if let Some(sig) = val.get("signature").and_then(Value::as_str) {
                    if !sig.is_empty() {
                        return Some(sig.to_string());
                    }
                } else if let Some(sig) = val.as_str() {
                    if !sig.is_empty() {
                        return Some(sig.to_string());
                    }
                }
            }
        }
        None
    }

    pub fn store_thought_signature(
        &self,
        connection_id: Option<&str>,
        model: &str,
        tool_call_id: &str,
        signature: &str,
    ) {
        if tool_call_id.is_empty() || signature.is_empty() {
            return;
        }
        let family = if model.to_lowercase().contains("claude") {
            Some("claude")
        } else if model.to_lowercase().contains("gemini") {
            Some("gemini")
        } else {
            None
        };
        let key = match (connection_id, family) {
            (Some(cid), Some(fam)) => format!("{}:{}:{}", cid, fam, tool_call_id),
            (Some(cid), None) => format!("{}:{}", cid, tool_call_id),
            _ => tool_call_id.to_string(),
        };
        let now_ms = Utc::now().timestamp_millis();
        let ttl_ms = 30i64 * 24 * 60 * 60 * 1000;
        let payload = json!({
            "signature": signature,
            "createdAt": now_ms,
            "expiresAt": now_ms + ttl_ms,
        });
        let _ = self.set_kv_json("gemini_thought_signatures", &key, &payload);
    }

    pub fn insert_call_log(&self, entry: &CallLogInsert) {
        let Ok(conn) = self.conn() else { return };
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let _ = conn.execute(
            "INSERT INTO call_logs (
                id, timestamp, method, path, status, model, requested_model,
                provider, account, connection_id, duration, ttft_ms,
                tokens_in, tokens_out, tokens_reasoning, tokens_cache_read,
                request_type, source_format, target_format,
                api_key_id, api_key_name, combo_name, error_summary, correlation_id
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16,
                ?17, ?18, ?19,
                ?20, ?21, ?22, ?23, ?24
             )",
            params![
                id,
                now,
                entry.method,
                entry.path,
                entry.status,
                entry.model,
                entry.requested_model,
                entry.provider,
                entry.account,
                entry.connection_id,
                entry.duration_ms,
                entry.ttft_ms,
                entry.tokens_in,
                entry.tokens_out,
                entry.tokens_reasoning,
                entry.tokens_cached,
                entry.request_type,
                entry.source_format,
                entry.target_format,
                entry.api_key_id,
                entry.api_key_name,
                entry.combo_name,
                entry.error_summary,
                entry.correlation_id,
            ],
        );

        let usage_id = Uuid::new_v4().to_string();
        let success = if (200..300).contains(&entry.status) {
            1
        } else {
            0
        };
        let _ = conn.execute(
            "INSERT INTO usage_history (
                id, provider, model, connection_id, api_key_id, api_key_name,
                tokens_input, tokens_output, tokens_cache_read, tokens_reasoning,
                status, success, latency_ms, ttft_ms, timestamp, endpoint
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6,
                ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14, ?15, ?16
             )",
            params![
                usage_id,
                entry.provider,
                entry.model,
                entry.connection_id,
                entry.api_key_id,
                entry.api_key_name,
                entry.tokens_in,
                entry.tokens_out,
                entry.tokens_cached,
                entry.tokens_reasoning,
                entry.status.to_string(),
                success,
                entry.duration_ms,
                entry.ttft_ms,
                now,
                entry.path,
            ],
        );
    }

    pub fn list_call_logs(&self, limit: i64, offset: i64) -> Result<(Vec<Value>, i64)> {
        let conn = self.conn()?;
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM call_logs", [], |r| r.get(0))
            .unwrap_or(0);
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, method, path, status, model, requested_model,
                    provider, account, connection_id, duration, ttft_ms,
                    tokens_in, tokens_out, tokens_reasoning, tokens_cache_read,
                    api_key_id, api_key_name, combo_name, error_summary, correlation_id
             FROM call_logs ORDER BY timestamp DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit, offset], |row| {
            Ok(json!({
                "id": row.get::<_, Option<String>>(0)?,
                "timestamp": row.get::<_, Option<String>>(1)?,
                "method": row.get::<_, Option<String>>(2)?,
                "path": row.get::<_, Option<String>>(3)?,
                "status": row.get::<_, Option<i64>>(4)?,
                "model": row.get::<_, Option<String>>(5)?,
                "requestedModel": row.get::<_, Option<String>>(6)?,
                "provider": row.get::<_, Option<String>>(7)?,
                "account": row.get::<_, Option<String>>(8)?,
                "connectionId": row.get::<_, Option<String>>(9)?,
                "duration": row.get::<_, Option<i64>>(10)?,
                "ttftMs": row.get::<_, Option<i64>>(11)?,
                "tokensIn": row.get::<_, Option<i64>>(12)?,
                "tokensOut": row.get::<_, Option<i64>>(13)?,
                "tokensReasoning": row.get::<_, Option<i64>>(14)?,
                "tokensCacheRead": row.get::<_, Option<i64>>(15)?,
                "apiKeyId": row.get::<_, Option<String>>(16)?,
                "apiKeyName": row.get::<_, Option<String>>(17)?,
                "comboName": row.get::<_, Option<String>>(18)?,
                "errorSummary": row.get::<_, Option<String>>(19)?,
                "correlationId": row.get::<_, Option<String>>(20)?,
            }))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok((out, total))
    }

    pub fn get_usage_summary(&self) -> Result<Value> {
        let conn = self.conn()?;
        let (total_requests, total_in, total_out, avg_latency): (i64, i64, i64, f64) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(tokens_in), 0), COALESCE(SUM(tokens_out), 0),
                        COALESCE(AVG(duration), 0.0)
                 FROM call_logs",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap_or((0, 0, 0, 0.0));

        let mut stmt = conn.prepare(
            "SELECT provider, model, COUNT(*) as requests,
                    SUM(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) as successes,
                    COALESCE(SUM(tokens_in), 0) as tokens_in,
                    COALESCE(SUM(tokens_out), 0) as tokens_out,
                    COALESCE(AVG(duration), 0.0) as avg_duration
             FROM call_logs
             GROUP BY provider, model
             ORDER BY requests DESC LIMIT 50",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(json!({
                "provider": r.get::<_, Option<String>>(0)?,
                "model": r.get::<_, Option<String>>(1)?,
                "requests": r.get::<_, i64>(2)?,
                "successes": r.get::<_, i64>(3)?,
                "tokensIn": r.get::<_, i64>(4)?,
                "tokensOut": r.get::<_, i64>(5)?,
                "avgLatencyMs": r.get::<_, f64>(6)?.round() as i64,
            }))
        })?;
        let mut by_model = Vec::new();
        for r in rows {
            by_model.push(r?);
        }

        Ok(json!({
            "totalRequests": total_requests,
            "totalTokensIn": total_in,
            "totalTokensOut": total_out,
            "totalTokens": total_in + total_out,
            "avgLatencyMs": avg_latency.round() as i64,
            "byModel": by_model,
        }))
    }
}

fn parse_json_string_vec(raw: Option<String>) -> Vec<String> {
    let Some(s) = raw else { return Vec::new() };
    serde_json::from_str::<Vec<String>>(&s).unwrap_or_default()
}
