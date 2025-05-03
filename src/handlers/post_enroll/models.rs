use serde::{Serialize, Deserialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct EnrollReq {
    pub enroll_jwt:     String,
    pub pubkey:         String,             // base64
    pub hw_id:          Option<String>,
}

#[derive(Deserialize)]
pub struct EnrollClaims {
    pub sub: String,            // is producer_user_id or user_id, it becomes node.user_id
    pub name: String,
    pub user_type: String,      // “producer” or “user”
    pub exp: usize,
    pub role_flag: String,      // "contributor", "writer", "witness"
}

// JSON we send back
#[derive(Serialize, Deserialize)]
pub struct EnrollResp {
    pub cert_pem:       String,
    pub ca_pem:         String,
    pub aes_key_b64:    String,             // 32 byte symmetric key for AES-256-GCM
    pub det_key_b64:    String,             // 32 byte key for BLAKE3’s “keyed hashing” mode
    pub node_config:    NodeConfig,
}

#[derive(Serialize, Deserialize)]
pub struct NodeConfig {
    pub uuid: Uuid,
    pub role_flag:      String,             // "writer" | "witness" | "both"
    pub expires_at:     i64,                // unix epoch secs
}