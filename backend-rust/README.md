# OmniRoute Rust Backend (`omniroute-rust`)

Native Rust backend engine for OmniRoute (`v3.8.54`), drop-in compatible with the production SQLite database (`storage.sqlite`), `enc:v1:` AES-256-GCM (16-byte & 12-byte IV) + `scrypt` field-level encryption, OAuth token auto-refresh, Combo routing (`Omni2`, `Omni3`), Google Cloud Code (`agy` / `antigravity`), custom `openai-compatible` provider nodes (`inferhub`), OpenAI/Anthropic/Responses translators (both JSON and streaming SSE), and management REST APIs.

## Zero-Dependency Native Compilation

- Uses `rusqlite` with `bundled` SQLite (no system `libsqlite3-dev` needed).
- Uses `reqwest` with `rustls-tls` (no system `libssl-dev` / `pkg-config` needed).

## Quick Install (1 Command)

From the repository root:

```bash
chmod +x ./install-rust.sh
./install-rust.sh
```

Or build directly with Cargo:

```bash
cargo build --release --manifest-path backend-rust/Cargo.toml
```

Binary output:
`backend-rust/target/release/omniroute-rust`

## Fresh Install Auto-Bootstrap

On first startup against a new `--data-dir` (default `~/.omniroute`):
1. Automatically creates `<DATA_DIR>/.env` (`0600`) with a generated 32-byte (64-hex) `STORAGE_ENCRYPTION_KEY` if not already set.
2. Automatically creates `<DATA_DIR>/storage.sqlite` (WAL mode) with all required tables (`key_value`, `provider_connections`, `provider_nodes`, `combos`, `api_keys`, `call_logs`, `usage_history`).
3. Automatically generates and encrypts `jwtSecret` and `apiKeySecret` in `key_value (namespace='secrets')`.
4. Automatically creates an initial `Default Key` in `api_keys` (if the table is empty) and saves the plaintext key once to `<DATA_DIR>/initial_api_key.txt` (`0600`).
5. Management login (`POST /api/auth/login`) works immediately using `INITIAL_PASSWORD` env var (or default `123456` until changed via `PATCH /api/settings`).

## Run

```bash
omniroute-rust --port 20129 --data-dir ~/.omniroute
```

Check CLI options:

```bash
omniroute-rust --help
```
