# OmniRoute Rust Backend (`omniroute-rust`)

Native Rust backend engine for OmniRoute (`v3.8.54`), Drop-in compatible with the production SQLite database (`storage.sqlite`), `enc:v1:` AES-256-GCM (16-byte & 12-byte IV) + `scrypt` field-level encryption, OAuth token auto-refresh, Combo routing (`Omni2`, `Omni3`), Google Cloud Code (`agy` / `antigravity`), custom `openai-compatible` provider nodes (`inferhub`), OpenAI/Anthropic/Responses translators, and management REST APIs.

## Architecture & Modules

- `src/main.rs` — Axum HTTP/SSE server, CORS layer, and route registration (`/v1/*`, `/api/v1/*`, `/api/*`, `/health`).
- `src/config.rs` — CLI argument & `.env` parser (`DATA_DIR`, `PORT`, `STORAGE_ENCRYPTION_KEY`, `JWT_SECRET`, `API_KEY_SECRET`, `NEXT_UPSTREAM_URL`) and embedded OAuth client credentials.
- `src/crypto.rs` — `enc:v1:<iv_hex>:<ciphertext_hex>:<tag_hex>` AES-256-GCM (16-byte `U16` & 12-byte `U12` nonces) with `scrypt` (`N=16384, r=8, p=1`) static salt (`omniroute-field-encryption-v1`) and legacy dynamic salt fallback, recursive `provider_specific_data` secret encryption/decryption, and SHA-256 `opaque_token_fingerprint`.
- `src/db.rs` — Bundled SQLite (`rusqlite` with WAL mode & `busy_timeout = 5000`) layer for `provider_connections`, `provider_nodes`, `combos`, `api_keys`, `key_value`, `call_logs`, and `usage_history`.
- `src/auth.rs` — Client API key verification (`Bearer` / `x-api-key` / `x-goog-api-key` via SHA-256 `key_hash` & `enc:v1:`), Dashboard HS256 JWT session cookie (`auth_token`), and bcrypt password authentication.
- `src/providers.rs` — Built-in provider registry, custom `provider_nodes` resolution, prefix stripping, and Google Cloud Code OAuth2 refresh token flow (`https://oauth2.googleapis.com/token`).
- `src/translator.rs` — Bidirectional request/response & SSE streaming translators for OpenAI Chat Completions, Antigravity Cloud Code (`v1internal:streamGenerateContent?alt=sse`, including `#9030` system-prompt relocation and `gemini_thought_signatures` persistence), Anthropic Messages (`/v1/messages`), and OpenAI Responses (`/v1/responses`).
- `src/router_engine.rs` — Combo execution planner (`priority` & `round-robin`), multi-provider failover, streaming SSE relay, and telemetry logging.
- `src/handlers.rs` — Gateway and Management HTTP handlers + optional Next.js UI reverse-proxy fallback (`--next-upstream`).

## Build

```bash
cargo build --release --manifest-path /var/www/OmniRoute-Rust/backend-rust/Cargo.toml
```

Binary output:
`/var/www/OmniRoute-Rust/backend-rust/target/release/omniroute-rust`

## Run

```bash
/var/www/OmniRoute-Rust/backend-rust/target/release/omniroute-rust \
  --port 20130 \
  --data-dir /root/.omniroute
```
