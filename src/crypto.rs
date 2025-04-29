use anyhow::{Context, Result};
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::{Aead, generic_array::GenericArray};
use blake3::Hasher;
use serde_json::{Map, Value};
use std::fs;
use std::path::Path;
use base64::prelude::*;
use anyhow::anyhow;

pub fn prepare_tx(
    mut obj: Map<String, Value>,
    public_fields: &[&str],
    dir: &Path,
) -> Result<Value> {
    // 1) grab & decode AES key
    let b64 = fs::read_to_string(dir.join("aes.key"))
        .context("reading aes.key")?;
    let aes_key = BASE64_STANDARD.decode(b64.trim().as_bytes())
        .context("decoding aes.key")?;

    // let key = Key::from_slice(&aes_key);

    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|_| anyhow!("AES-256 key must be 32 bytes"))?;

    // 2) pull out timestamp (we’ll overwrite it)
    let timestamp = chrono::Utc::now().timestamp_millis();
    obj.insert("timestamp".into(), Value::Number(timestamp.into()));

    // 3) split public vs private
    let mut public = Map::new();
    let mut private = Map::new();
    for (k, v) in obj.into_iter() {
        if public_fields.contains(&k.as_str()) {
            public.insert(k, v);
        } else {
            private.insert(k, v);
        }
    }

    // 4) encrypt the private JSON
    let nonce = GenericArray::from_slice(&aes_key[..12]);
    let plaintext = serde_json::to_vec(&private)?;
    let ct = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("encrypting private JSON: {}", e))?;

    // 5) hash the ciphertext
    let mut hasher = Hasher::new();
    hasher.update(&ct);
    let private_hash = hasher.finalize().to_hex().to_string();

    // 6) assemble the resulting JSON
    let mut out = Map::new();
    out.insert("timestamp".into(), Value::Number(timestamp.into()));
    out.insert("public".into(), Value::Object(public));
    out.insert("ciphertext".into(), Value::String(BASE64_STANDARD.encode(&ct)));
    out.insert("private_hash".into(), Value::String(private_hash));

    Ok(Value::Object(out))
}