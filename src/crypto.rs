use crate::{
    utils::json_to_fr,
};
use anyhow::{Context, Result};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
use aes_gcm_siv::aead::{Aead, KeyInit};
use blake3::Hasher;
use serde_json::{Map, Value};
use std::fs;
use std::{
    path::Path,
    collections::HashSet,
};
use base64::prelude::*;
use anyhow::anyhow;
use rand::RngCore;
use ark_bn254::Fr;
use ark_ff::{PrimeField, BigInteger};
use ark_serialize::CanonicalSerialize;
use ark_crypto_primitives::sponge::{
    poseidon::{
        find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge,
    },
    CryptographicSponge,
};
use hex::encode;

pub fn prepare_tx(
    mut obj: Map<String, Value>,
    dir: &Path,
) -> Result<Value> {
    let public_fields = &["event_type", "order_id", "product_id"];

    let b64 = fs::read_to_string(dir.join("aes.key"))
        .context("reading aes.key")?;
    let aes_key = BASE64_STANDARD
        .decode(b64.trim().as_bytes())
        .context("decoding aes.key")?;

    let key     =   Key::<Aes256GcmSiv>::from_slice(&aes_key);
    let cipher  =   Aes256GcmSiv::new(key);

    let timestamp = chrono::Utc::now().timestamp_millis();
    obj.insert("timestamp".into(), Value::Number(timestamp.into()));

    // ------------------------------------------------------------------
    // split public vs private
    // ------------------------------------------------------------------
    let mut public = Map::new();
    let mut private = Map::new();
    for (k, v) in obj.into_iter() {
        if public_fields.contains(&k.as_str()) {
            public.insert(k, v);
        } else {
            private.insert(k, v);
        }
    }

    // ------------------------------------------------------------------
    // create hashed index_tokens (Posedion2) of select private fields
    // ------------------------------------------------------------------
    let index_whitelist: HashSet<&str> = [
        "batch_id",
        "product_id",
        "producer_id",
        "order_id",
        "user_id",
    ]
    .into_iter()
    .collect();
    
    let mut index_tokens = Vec::new();
    for &k in index_whitelist.iter() {
        if let Some(v) = private.get(k) {
            let tok_fr: Fr = hash_index_entry(k, v)?;
    
            let bytes = tok_fr
                .into_bigint()               // PrimeField → BigInt&#8203;:contentReference[oaicite:2]{index=2}
                .to_bytes_le();              // BigInt   → Vec<u8>&#8203;:contentReference[oaicite:3]{index=3}

            index_tokens.push(Value::String(encode(&bytes)));
        }
    }

    // ------------------------------------------------------------------
    // encrypt the private data
    // ------------------------------------------------------------------
    let mut nonce_buf = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_buf);
    let nonce = Nonce::from_slice(&nonce_buf);
    let plaintext = serde_json::to_vec(&private)?;
    let ct = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!(e))
        .context("encrypting private JSON")?;

    // ------------------------------------------------------------------
    // hash the private data + nonce
    // ------------------------------------------------------------------
    let mut hasher = Hasher::new();
    // Domain tag + 8-byte length of the nonce
    hasher.update(b"nonce");
    hasher.update(&(nonce_buf.len() as u64).to_be_bytes());
    hasher.update(&nonce_buf);
    // Domain tag + 8-byte length of the ciphertext + ciphertext
    hasher.update(b"ciphertext");
    hasher.update(&(ct.len() as u64).to_be_bytes());
    hasher.update(&ct);

    let cipher_hash = hasher.finalize().to_hex().to_string();

    // ------------------------------------------------------------------
    // assemble Tx
    // ------------------------------------------------------------------
    let mut out = Map::new();
    out.insert("timestamp".into(), Value::Number(timestamp.into()));
    out.insert("public".into(), Value::Object(public));
    out.insert("ciphertext".into(), Value::String(BASE64_STANDARD.encode(&ct)));
    out.insert("cipher_hash".into(), Value::String(cipher_hash));
    out.insert("index_tokens".into(), Value::Array(index_tokens));

    Ok(Value::Object(out))
}

fn poseidon_bn254_t3() -> PoseidonConfig<Fr> {
    let p_bits = Fr::MODULUS_BIT_SIZE as u64;
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(p_bits, 2, 8, 57, 0);
    PoseidonConfig::new(8, 57, 5, mds, ark, 2, 1)
}

fn hash_index_entry(key: &str, val: &Value) -> Result<Fr> {
    let k_fr = Fr::from_le_bytes_mod_order(key.as_bytes());
    let v_fr = Fr::from_le_bytes_mod_order(serde_json::to_string(val)?.as_bytes());

    let params = poseidon_bn254_t3();
    let mut sponge = PoseidonSponge::<Fr>::new(&params);

    sponge.absorb(&k_fr);
    sponge.absorb(&v_fr);
    Ok(sponge.squeeze_field_elements(1)[0])
}