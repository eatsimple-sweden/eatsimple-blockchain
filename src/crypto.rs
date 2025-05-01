use crate::{
    utils::json_to_fr,
};
use anyhow::{Context, Result};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
use aes_gcm_siv::aead::{Aead, KeyInit};
use blake3::Hasher;
use serde_json::{Map, Value};
use serde::{Serialize, Deserialize};
use std::{
    fs,
    path::Path,
    collections::{
        HashSet, BTreeMap,
    },
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
use ed25519_dalek::{SigningKey, Signer, SECRET_KEY_LENGTH, PUBLIC_KEY_LENGTH, KEYPAIR_LENGTH};
use chrono::Utc;
use serde_jcs;

#[derive(Debug, Serialize, Deserialize)]
pub struct TxConstruction {
    pub node_id:      String,
    pub timestamp:    i64,
    pub public:       Map<String, Value>,
    pub ciphertext:   String,
    pub cipher_hash:  String,
    pub index_tokens: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Tx {
    pub node_id:        String,
    pub timestamp:      i64,
    pub public:         Map<String, Value>,
    pub ciphertext:     String,
    pub cipher_hash:    String,
    pub index_tokens:   Vec<String>,
    pub sig:            String,
}

pub fn prepare_tx(mut obj: Map<String, Value>, dir: &Path) -> Result<Tx> {
    // ----------------------------------------------------------------------
    // load metadata
    // ----------------------------------------------------------------------
    let node_json: Value = serde_json::from_str(
        &fs::read_to_string(dir.join("node.json"))
            .context("reading node.json")?,
    )?;
    let node_id = node_json
        .get("uuid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing or non-string uuid in node.json"))?
        .to_owned();

    let timestamp = Utc::now().timestamp_millis();
    obj.insert("timestamp".into(), Value::Number(timestamp.into()));

    // ----------------------------------------------------------------------
    // split data public/private
    // ----------------------------------------------------------------------
    const PUBLIC_FIELDS: &[&str] = &["event_type"];
    let mut public   = Map::new();
    let mut private  = Map::new();
    for (k, v) in obj.into_iter() {
        if PUBLIC_FIELDS.contains(&k.as_str()) {
            public.insert(k, v);
        } else {
            private.insert(k, v);
        }
    }

    // ----------------------------------------------------------------------
    // index tokens and hash with Poseidon
    // ----------------------------------------------------------------------
    let index_whitelist: HashSet<&str> =
        ["batch_id", "product_id", "producer_id", "order_id", "user_id"].into();
    let mut index_tokens = Vec::new();
    for &k in &index_whitelist {
        if let Some(v) = private.get(k) {
            let tok_fr = hash_index_entry(k, v)?;
            let tok_bytes = tok_fr.into_bigint().to_bytes_le();
            index_tokens.push(hex::encode(tok_bytes));
        }
    }

    // ----------------------------------------------------------------------
    // encrypt private data with AES-GCM-SIV
    // ----------------------------------------------------------------------
    let aes_key = BASE64_STANDARD
        .decode(
            fs::read_to_string(dir.join("aes.key"))
                .context("reading aes.key")?
                .trim()
                .as_bytes(),
        )
        .context("decoding aes.key")?;
    let key = Key::<Aes256GcmSiv>::from_slice(&aes_key);
    let cipher = Aes256GcmSiv::new(key);

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = serde_json::to_vec(&private)?;
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow!(e))
        .context("encrypting private JSON")?;
    let ciphertext_b64 = BASE64_STANDARD.encode(&ciphertext);

    // ----------------------------------------------------------------------
    // make cipher_hash with Nonce, Ciphertext and Ciphertext length
    // ----------------------------------------------------------------------
    let cipher_hash = {
        let mut h = Hasher::new();
        h.update(b"nonce");
        h.update(&(nonce_bytes.len() as u64).to_be_bytes());
        h.update(&nonce_bytes);
        h.update(b"ciphertext");
        h.update(&(ciphertext.len() as u64).to_be_bytes());
        h.update(&ciphertext);
        h.finalize().to_hex().to_string()
    };

    let txc = TxConstruction {
        node_id,
        timestamp,
        public,
        ciphertext: ciphertext_b64,
        cipher_hash,
        index_tokens,
    };

    let canonical_bytes = serde_jcs::to_vec(&txc)
        .context("serialising canonical JSON (JCS)")?;

    let signing_key = load_ed25519_keypair(dir)?;
    let sig = signing_key.sign(&canonical_bytes);
    let sig_b64 = BASE64_STANDARD.encode(sig.to_bytes());

    let TxConstruction {
        node_id,
        timestamp,
        public,
        ciphertext,
        cipher_hash,
        index_tokens,
    } = txc;

    let signed_tx = Tx {
        node_id,
        timestamp,
        public,
        ciphertext,
        cipher_hash,
        index_tokens,
        sig: sig_b64,
    };

    let out: Value = serde_json::to_value(signed_tx)?;
    Ok(serde_json::from_value(out)?)
}

fn load_ed25519_keypair(dir: &Path) -> Result<SigningKey> {
    use std::fs::read;

    let sk_bytes = read(dir.join("node.key"))
        .context("reading node.key (32-byte seed)")?;
    let pk_bytes = read(dir.join("node.pub"))
        .context("reading node.pub (32-byte public)")?;

    if sk_bytes.len() != SECRET_KEY_LENGTH {
        anyhow::bail!("node.key must be {} bytes", SECRET_KEY_LENGTH);
    }
    if pk_bytes.len() != PUBLIC_KEY_LENGTH {
        anyhow::bail!("node.pub must be {} bytes", PUBLIC_KEY_LENGTH);
    }

    let mut pair = [0u8; KEYPAIR_LENGTH];
    pair[..SECRET_KEY_LENGTH].copy_from_slice(&sk_bytes);
    pair[SECRET_KEY_LENGTH..].copy_from_slice(&pk_bytes);
    Ok(SigningKey::from_keypair_bytes(&pair)?)
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