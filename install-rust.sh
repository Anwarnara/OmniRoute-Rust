#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_PATH="${SCRIPT_DIR}/backend-rust/Cargo.toml"

if ! command -v cargo >/dev/null 2>&1; then
  echo "[omniroute-rust] Rust toolchain (cargo) not found. Installing via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

echo "[omniroute-rust] Building release binary..."
cargo build --release --manifest-path "$MANIFEST_PATH"

BIN_SRC="${SCRIPT_DIR}/backend-rust/target/release/omniroute-rust"
if [ ! -x "$BIN_SRC" ]; then
  echo "[omniroute-rust] Error: binary not found at $BIN_SRC" >&2
  exit 1
fi

INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

cp -f "$BIN_SRC" "${INSTALL_DIR}/omniroute-rust"
chmod +x "${INSTALL_DIR}/omniroute-rust"

echo "[omniroute-rust] Installed to ${INSTALL_DIR}/omniroute-rust"
"${INSTALL_DIR}/omniroute-rust" --version
echo "[omniroute-rust] Run with: ${INSTALL_DIR}/omniroute-rust --port 20129 --data-dir ~/.omniroute"
