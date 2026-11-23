use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
    pub data_dir: PathBuf,
    pub db_path: PathBuf,
    pub storage_encryption_key: Option<String>,
    pub storage_encryption_key_before_fix: Option<String>,
    pub jwt_secret_env: Option<String>,
    pub api_key_secret_env: Option<String>,
    pub next_upstream_url: Option<String>,
    pub app_version: String,
}

const PUBLIC_CRED_MASK: &[u8] = b"omniroute-public-v1";

const ANTIGRAVITY_ID_BYTES: &[u8] = &[
    94, 93, 89, 88, 66, 95, 67, 68, 83, 29, 69, 76, 83, 65, 29, 14, 69, 5, 66, 6, 3, 92, 1, 64, 94,
    25, 23, 23, 72, 66, 70, 87, 26, 29, 12, 65, 25, 91, 7, 89, 9, 93, 66, 92, 16, 4, 75, 76, 0, 5,
    17, 66, 14, 12, 66, 17, 93, 10, 24, 29, 12, 0, 12, 26, 26, 17, 72, 30, 1, 76, 15, 6, 14,
];

const ANTIGRAVITY_ALT_BYTES: &[u8] = &[
    40, 34, 45, 58, 34, 55, 88, 63, 80, 21, 54, 34, 48, 88, 81, 85, 97, 18, 125, 37, 92, 3, 37, 48,
    87, 6, 44, 38, 25, 10, 67, 19, 40, 40, 5,
];

const GEMINI_ID_BYTES: &[u8] = &[
    89, 85, 95, 91, 71, 90, 77, 68, 92, 30, 73, 64, 79, 3, 6, 91, 75, 2, 3, 0, 29, 28, 13, 0, 1, 5,
    77, 0, 30, 17, 4, 4, 90, 8, 21, 30, 30, 92, 11, 4, 12, 88, 65, 90, 31, 90, 4, 93, 0, 6, 76, 11,
    6, 12, 74, 26, 84, 26, 30, 11, 27, 17, 0, 27, 0, 0, 67, 4, 91, 1, 3, 4,
];

const GEMINI_ALT_BYTES: &[u8] = &[
    40, 34, 45, 58, 34, 55, 88, 64, 16, 101, 23, 56, 50, 1, 68, 82, 66, 65, 98, 4, 64, 9, 12, 36,
    89, 54, 1, 80, 78, 28, 45, 36, 31, 17, 15,
];

fn unmask_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .enumerate()
        .map(|(i, b)| (b ^ PUBLIC_CRED_MASK[i % PUBLIC_CRED_MASK.len()]) as char)
        .collect()
}

pub fn builtin_google_oauth_client(provider: &str) -> (String, String) {
    if provider == "gemini" {
        let id = env::var("GEMINI_OAUTH_CLIENT_ID")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| unmask_bytes(GEMINI_ID_BYTES));
        let secret = env::var("GEMINI_OAUTH_CLIENT_SECRET")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| unmask_bytes(GEMINI_ALT_BYTES));
        (id, secret)
    } else {
        let id = env::var("ANTIGRAVITY_OAUTH_CLIENT_ID")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| unmask_bytes(ANTIGRAVITY_ID_BYTES));
        let secret = env::var("ANTIGRAVITY_OAUTH_CLIENT_SECRET")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| unmask_bytes(ANTIGRAVITY_ALT_BYTES));
        (id, secret)
    }
}

pub fn parse_env_value(raw: &str) -> String {
    let val = raw.trim();
    if val.len() >= 2 {
        let first = val.as_bytes()[0];
        if first == b'"' || first == b'\'' {
            let quote = first as char;
            if let Some(end_idx) = val[1..].rfind(quote) {
                let after = val[1 + end_idx + 1..].trim();
                if after.is_empty() || after.starts_with('#') {
                    return val[1..1 + end_idx].to_string();
                }
            }
        }
    }
    if let Some(comment_idx) = val.find(" #").or_else(|| val.find("\t#")) {
        val[..comment_idx].trim().to_string()
    } else {
        val.to_string()
    }
}

fn read_value_before_first_equals_fix(trimmed: &str) -> Option<String> {
    if !trimmed.starts_with("STORAGE_ENCRYPTION_KEY=") {
        return None;
    }
    let parts: Vec<&str> = trimmed.splitn(3, '=').collect();
    if parts.len() < 2 {
        return None;
    }
    let mut val = parts[1].trim().to_string();
    if val.len() >= 2
        && ((val.starts_with('"') && val.ends_with('"'))
            || (val.starts_with('\'') && val.ends_with('\'')))
    {
        val = val[1..val.len() - 1].to_string();
    }
    if val.is_empty() {
        None
    } else {
        Some(val)
    }
}

pub fn default_data_dir() -> PathBuf {
    if let Ok(dir) = env::var("DATA_DIR") {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home).join(".omniroute");
    }
    PathBuf::from("/root/.omniroute")
}

impl AppConfig {
    pub fn load() -> Self {
        let mut args = env::args().skip(1);
        let mut cli_port: Option<u16> = None;
        let mut cli_host: Option<String> = None;
        let mut cli_data_dir: Option<PathBuf> = None;
        let mut cli_next_upstream: Option<String> = None;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--port" | "-p" => {
                    if let Some(v) = args.next() {
                        cli_port = v.parse::<u16>().ok();
                    }
                }
                "--host" | "-H" => {
                    if let Some(v) = args.next() {
                        cli_host = Some(v);
                    }
                }
                "--data-dir" => {
                    if let Some(v) = args.next() {
                        cli_data_dir = Some(PathBuf::from(v));
                    }
                }
                "--next-upstream" => {
                    if let Some(v) = args.next() {
                        cli_next_upstream = Some(v);
                    }
                }
                "--version" | "-v" | "-V" => {
                    println!("{}", env!("CARGO_PKG_VERSION"));
                    std::process::exit(0);
                }
                _ => {
                    if let Some(p) = arg.strip_prefix("--port=") {
                        cli_port = p.parse::<u16>().ok();
                    } else if let Some(d) = arg.strip_prefix("--data-dir=") {
                        cli_data_dir = Some(PathBuf::from(d));
                    } else if let Some(u) = arg.strip_prefix("--next-upstream=") {
                        cli_next_upstream = Some(u.to_string());
                    }
                }
            }
        }

        let data_dir = cli_data_dir.unwrap_or_else(default_data_dir);
        let mut file_vars: HashMap<String, String> = HashMap::new();
        let mut before_fix_key: Option<String> = None;

        let candidate_envs = [
            data_dir.join(".env"),
            data_dir.join("server.env"),
            env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(".env"),
        ];

        for env_path in &candidate_envs {
            if let Some((vars, bf)) = read_env_file(env_path) {
                if before_fix_key.is_none() {
                    before_fix_key = bf;
                }
                for (k, v) in vars {
                    file_vars.entry(k).or_insert(v);
                }
            }
        }

        let get_var = |key: &str| -> Option<String> {
            env::var(key)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .or_else(|| file_vars.get(key).cloned().filter(|v| !v.trim().is_empty()))
        };

        let port = cli_port
            .or_else(|| get_var("PORT").and_then(|v| v.parse::<u16>().ok()))
            .unwrap_or(20129);

        let host = cli_host
            .or_else(|| get_var("HOSTNAME"))
            .or_else(|| get_var("HOST"))
            .unwrap_or_else(|| "0.0.0.0".to_string());

        let storage_encryption_key = get_var("STORAGE_ENCRYPTION_KEY");
        let storage_encryption_key_before_fix = match (&storage_encryption_key, before_fix_key) {
            (Some(curr), Some(bf)) if bf.trim() != curr.trim() && !bf.trim().is_empty() => Some(bf),
            _ => None,
        };

        let jwt_secret_env = get_var("JWT_SECRET");
        let api_key_secret_env = get_var("API_KEY_SECRET");
        let next_upstream_url = cli_next_upstream.or_else(|| get_var("NEXT_UPSTREAM_URL"));

        let db_path = get_var("SQLITE_DB_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("storage.sqlite"));

        Self {
            host,
            port,
            data_dir,
            db_path,
            storage_encryption_key,
            storage_encryption_key_before_fix,
            jwt_secret_env,
            api_key_secret_env,
            next_upstream_url,
            app_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

fn read_env_file(path: &Path) -> Option<(HashMap<String, String>, Option<String>)> {
    let content = fs::read_to_string(path).ok()?;
    let mut map = HashMap::new();
    let mut before_fix = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if before_fix.is_none() {
            before_fix = read_value_before_first_equals_fix(trimmed);
        }
        if let Some(eq_idx) = trimmed.find('=') {
            if eq_idx > 0 {
                let key = trimmed[..eq_idx].trim().to_string();
                let val = parse_env_value(&trimmed[eq_idx + 1..]);
                if !val.is_empty() {
                    map.entry(key).or_insert(val);
                }
            }
        }
    }
    Some((map, before_fix))
}
