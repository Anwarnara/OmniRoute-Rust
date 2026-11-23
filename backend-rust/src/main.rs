#![recursion_limit = "512"]

mod auth;
mod config;
mod crypto;
mod db;
mod handlers;
mod providers;
mod router_engine;
mod translator;

use crate::config::AppConfig;
use crate::crypto::CryptoEngine;
use crate::db::DbStore;
use crate::router_engine::AppState;
use axum::routing::{delete, get, post};
use axum::Router;
use reqwest::Client;
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = AppConfig::load();

    let crypto = CryptoEngine::new(
        config.storage_encryption_key.as_deref(),
        config.storage_encryption_key_before_fix.as_deref(),
    );
    let db = DbStore::new(config.db_path.clone(), crypto)?;

    let http = Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(32)
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(960))
        .tcp_nodelay(true)
        .build()?;

    let active_conns = db
        .list_provider_connections(None, true)
        .map(|v| v.len())
        .unwrap_or(0);
    let combos = db.list_combos().map(|v| v.len()).unwrap_or(0);

    info!(
        "OmniRoute Rust Gateway v{} starting on {}:{} (db={}, active_connections={}, combos={})",
        config.app_version,
        config.host,
        config.port,
        config.db_path.display(),
        active_conns,
        combos
    );

    let bind_addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let state = Arc::new(AppState {
        config,
        db,
        http,
        started_at: Instant::now(),
        rr_counter: AtomicUsize::new(0),
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        // OpenAI / Anthropic / Responses Gateway Endpoints (/v1/* & /api/v1/*)
        .route("/v1/models", get(handlers::get_models_handler))
        .route("/api/v1/models", get(handlers::get_models_handler))
        .route(
            "/v1/chat/completions",
            post(handlers::post_chat_completions_handler),
        )
        .route(
            "/api/v1/chat/completions",
            post(handlers::post_chat_completions_handler),
        )
        .route("/v1/messages", post(handlers::post_messages_handler))
        .route("/api/v1/messages", post(handlers::post_messages_handler))
        .route(
            "/v1/messages/count_tokens",
            post(handlers::post_messages_count_tokens_handler),
        )
        .route(
            "/api/v1/messages/count_tokens",
            post(handlers::post_messages_count_tokens_handler),
        )
        .route("/v1/responses", post(handlers::post_responses_handler))
        .route("/api/v1/responses", post(handlers::post_responses_handler))
        .route("/v1/embeddings", post(handlers::post_embeddings_handler))
        .route(
            "/api/v1/embeddings",
            post(handlers::post_embeddings_handler),
        )
        // Health & Auth
        .route("/health", get(handlers::get_health_handler))
        .route("/api/health", get(handlers::get_health_handler))
        .route("/api/auth/login", post(handlers::post_auth_login_handler))
        .route("/api/auth/logout", post(handlers::post_auth_logout_handler))
        .route("/api/auth/status", get(handlers::get_auth_status_handler))
        .route(
            "/api/settings/require-login",
            get(handlers::get_auth_status_handler),
        )
        // Settings
        .route(
            "/api/settings",
            get(handlers::get_settings_handler)
                .patch(handlers::patch_settings_handler)
                .put(handlers::patch_settings_handler),
        )
        // Provider Connections
        .route(
            "/api/providers",
            get(handlers::list_providers_handler).post(handlers::create_provider_handler),
        )
        .route(
            "/api/providers/:id",
            get(handlers::get_provider_by_id_handler)
                .put(handlers::update_provider_by_id_handler)
                .patch(handlers::update_provider_by_id_handler)
                .delete(handlers::delete_provider_by_id_handler),
        )
        .route(
            "/api/providers/:id/test",
            post(handlers::test_provider_by_id_handler),
        )
        // Custom Provider Nodes
        .route(
            "/api/provider-nodes",
            get(handlers::list_provider_nodes_handler)
                .post(handlers::create_provider_node_handler),
        )
        .route(
            "/api/provider-nodes/:id",
            delete(handlers::delete_provider_node_handler),
        )
        // Combos
        .route(
            "/api/combos",
            get(handlers::list_combos_handler).post(handlers::create_combo_handler),
        )
        .route(
            "/api/combos/:id",
            get(handlers::get_combo_by_id_handler)
                .put(handlers::update_combo_by_id_handler)
                .patch(handlers::update_combo_by_id_handler)
                .delete(handlers::delete_combo_by_id_handler),
        )
        // Client API Keys
        .route(
            "/api/keys",
            get(handlers::list_keys_handler).post(handlers::create_key_handler),
        )
        .route("/api/keys/:id", delete(handlers::delete_key_handler))
        .route("/api/keys/:id/reveal", get(handlers::reveal_key_handler))
        // Call Logs & Usage Telemetry
        .route("/api/logs", get(handlers::list_logs_handler))
        .route("/api/call-logs", get(handlers::list_logs_handler))
        .route("/api/usage", get(handlers::get_usage_handler))
        .route("/api/stats", get(handlers::get_usage_handler))
        .route("/api/telemetry/summary", get(handlers::get_usage_handler))
        // Model Aliases
        .route(
            "/api/models/aliases",
            get(handlers::get_model_aliases_handler).put(handlers::put_model_aliases_handler),
        )
        .fallback(handlers::fallback_handler)
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
