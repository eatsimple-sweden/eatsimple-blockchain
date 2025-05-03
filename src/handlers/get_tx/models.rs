use serde::{Serialize, Deserialize};
use base64::prelude::*;

#[derive(Serialize)]
pub struct TxView {
    pub node_uuid:    String,
    pub timestamp_ms: i64,
    pub public:       serde_json::Value,
    pub ciphertext:   String,             // base64(cipher_bytes)
    pub cipher_hash:  String,             // hex(ciper_hash)
    pub index_tokens: Vec<String>,        // hex each token
    pub signature:    String,             // base64(signature)
}

#[derive(Deserialize)]
pub struct TxParams {
    pub signature_hex: String,
}

impl TryFrom<crate::pb::TxRequest> for TxView {
    type Error = anyhow::Error;

    fn try_from(tx: crate::pb::TxRequest) -> Result<Self, Self::Error> {
        Ok(TxView {
            node_uuid:    tx.node_uuid,
            timestamp_ms: tx.timestamp_ms,
            public:       serde_json::from_slice(&tx.public_json)?,
            ciphertext:   BASE64_STANDARD.encode(&tx.cipher_bytes),
            cipher_hash:  hex::encode(&tx.cipher_hash),
            index_tokens: tx.index_tokens
                              .into_iter()
                              .map(hex::encode)
                              .collect(),
            signature:    BASE64_STANDARD.encode(&tx.signature),
        })
    }
}