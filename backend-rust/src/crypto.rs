use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aes::Aes256;
use aes_gcm::{Aes256Gcm, AesGcm, Nonce};
use rand::RngCore;
use scrypt::{scrypt, Params as ScryptParams};
use serde_json::Value;
use sha2::{Digest, Sha256};

type Aes256Gcm16 = AesGcm<Aes256, U16>;
type Aes256Gcm12 = Aes256Gcm;

const PREFIX: &str = "enc:v1:";
const STATIC_SALT: &[u8] = b"omniroute-field-encryption-v1";
const PROVIDER_SPECIFIC_SECRET_KEYS: &[&str] = &[
    "apiKey",
    "accessToken",
    "refreshToken",
    "idToken",
    "clientSecret",
    "secretAccessKey",
    "sessionToken",
    "cookie",
    "cookies",
    "password",
    "webhookSecret",
];

#[derive(Clone)]
pub struct CryptoEngine {
    static_key: Option<[u8; 32]>,
    legacy_dynamic_key: Option<[u8; 32]>,
    static_key_before_fix: Option<[u8; 32]>,
    legacy_dynamic_key_before_fix: Option<[u8; 32]>,
}

impl CryptoEngine {
    pub fn new(secret: Option<&str>, secret_before_fix: Option<&str>) -> Self {
        let (static_key, legacy_dynamic_key) = match secret.map(str::trim).filter(|s| !s.is_empty())
        {
            Some(s) => (
                derive_scrypt_key(s.as_bytes(), STATIC_SALT),
                derive_legacy_dynamic_key(s.as_bytes()),
            ),
            None => (None, None),
        };

        let (static_key_before_fix, legacy_dynamic_key_before_fix) =
            match secret_before_fix.map(str::trim).filter(|s| !s.is_empty()) {
                Some(s) => (
                    derive_scrypt_key(s.as_bytes(), STATIC_SALT),
                    derive_legacy_dynamic_key(s.as_bytes()),
                ),
                None => (None, None),
            };

        Self {
            static_key,
            legacy_dynamic_key,
            static_key_before_fix,
            legacy_dynamic_key_before_fix,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.static_key.is_some()
    }

    pub fn looks_encrypted(val: &str) -> bool {
        val.starts_with(PREFIX)
    }

    pub fn encrypt(&self, plaintext: &str) -> String {
        if plaintext.is_empty() || Self::looks_encrypted(plaintext) {
            return plaintext.to_string();
        }
        let Some(key) = &self.static_key else {
            return plaintext.to_string();
        };

        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);

        let cipher = match Aes256Gcm16::new_from_slice(key) {
            Ok(c) => c,
            Err(_) => return plaintext.to_string(),
        };
        let nonce = Nonce::<U16>::from_slice(&iv);
        match cipher.encrypt(nonce, plaintext.as_bytes()) {
            Ok(ct_with_tag) if ct_with_tag.len() >= 16 => {
                let split_at = ct_with_tag.len() - 16;
                let ct = &ct_with_tag[..split_at];
                let tag = &ct_with_tag[split_at..];
                format!(
                    "{}{}:{}:{}",
                    PREFIX,
                    hex::encode(iv),
                    hex::encode(ct),
                    hex::encode(tag)
                )
            }
            _ => plaintext.to_string(),
        }
    }

    pub fn decrypt(&self, ciphertext: &str) -> Option<String> {
        if !Self::looks_encrypted(ciphertext) {
            return Some(ciphertext.to_string());
        }
        let body = &ciphertext[PREFIX.len()..];
        let parts: Vec<&str> = body.split(':').collect();
        if parts.len() != 3 {
            return None;
        }
        let iv = hex::decode(parts[0]).ok()?;
        let ct = hex::decode(parts[1]).ok()?;
        let tag = hex::decode(parts[2]).ok()?;
        if tag.len() != 16 {
            return None;
        }

        let mut combined = Vec::with_capacity(ct.len() + tag.len());
        combined.extend_from_slice(&ct);
        combined.extend_from_slice(&tag);

        let candidate_keys: [Option<&[u8; 32]>; 4] = [
            self.static_key.as_ref(),
            self.static_key_before_fix.as_ref(),
            self.legacy_dynamic_key.as_ref(),
            self.legacy_dynamic_key_before_fix.as_ref(),
        ];

        for candidate in candidate_keys.into_iter().flatten() {
            if let Some(plain) = try_decrypt_aes256_gcm(candidate, &iv, &combined) {
                return Some(plain);
            }
        }
        None
    }

    pub fn decrypt_opt(&self, val: Option<String>) -> (Option<String>, bool) {
        match val {
            None => (None, false),
            Some(s) if s.is_empty() => (Some(s), false),
            Some(s) => {
                if Self::looks_encrypted(&s) {
                    match self.decrypt(&s) {
                        Some(dec) => (Some(dec), false),
                        None => (None, true),
                    }
                } else {
                    (Some(s), false)
                }
            }
        }
    }

    pub fn decrypt_json_secrets(&self, value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (k, v) in map.iter_mut() {
                    if let Value::String(s) = v {
                        if Self::looks_encrypted(s) {
                            if let Some(dec) = self.decrypt(s) {
                                *v = Value::String(dec);
                            }
                        } else if PROVIDER_SPECIFIC_SECRET_KEYS.contains(&k.as_str())
                            && Self::looks_encrypted(s)
                        {
                            if let Some(dec) = self.decrypt(s) {
                                *v = Value::String(dec);
                            }
                        }
                    } else {
                        self.decrypt_json_secrets(v);
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.decrypt_json_secrets(item);
                }
            }
            _ => {}
        }
    }

    pub fn encrypt_json_secrets(&self, value: &mut Value) {
        if !self.is_enabled() {
            return;
        }
        match value {
            Value::Object(map) => {
                for (k, v) in map.iter_mut() {
                    if PROVIDER_SPECIFIC_SECRET_KEYS.contains(&k.as_str()) {
                        if let Value::String(s) = v {
                            if !s.is_empty() && !Self::looks_encrypted(s) {
                                *v = Value::String(self.encrypt(s));
                            }
                        }
                    } else {
                        self.encrypt_json_secrets(v);
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.encrypt_json_secrets(item);
                }
            }
            _ => {}
        }
    }
}

fn derive_scrypt_key(secret: &[u8], salt: &[u8]) -> Option<[u8; 32]> {
    // Node.js scryptSync default parameters: N=16384 (log_n=14), r=8, p=1, dklen=32
    let params = ScryptParams::new(14, 8, 1, 32).ok()?;
    let mut out = [0u8; 32];
    scrypt(secret, salt, &params, &mut out).ok()?;
    Some(out)
}

fn derive_legacy_dynamic_key(secret: &[u8]) -> Option<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    let digest = hasher.finalize();
    derive_scrypt_key(secret, &digest[..16])
}

fn try_decrypt_aes256_gcm(key: &[u8; 32], iv: &[u8], combined_ct_tag: &[u8]) -> Option<String> {
    if iv.len() == 16 {
        let cipher = Aes256Gcm16::new_from_slice(key).ok()?;
        let nonce = Nonce::<U16>::from_slice(iv);
        let pt = cipher.decrypt(nonce, combined_ct_tag).ok()?;
        String::from_utf8(pt).ok()
    } else if iv.len() == 12 {
        let cipher = Aes256Gcm12::new_from_slice(key).ok()?;
        let nonce = Nonce::<U12>::from_slice(iv);
        let pt = cipher.decrypt(nonce, combined_ct_tag).ok()?;
        String::from_utf8(pt).ok()
    } else {
        None
    }
}

pub fn opaque_token_fingerprint(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn mask_secret(secret: &str) -> String {
    if secret.is_empty() {
        return String::new();
    }
    if secret.len() <= 8 {
        return "****".to_string();
    }
    let prefix = &secret[..std::cmp::min(8, secret.len())];
    let suffix = &secret[secret.len().saturating_sub(4)..];
    format!("{}••••{}", prefix, suffix)
}
