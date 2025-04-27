use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct EnrollReq {
    pub enroll_jwt: String,
    pub pubkey:     String,             // base64
    pub hw_id:      Option<String>,
}

// JSON we send back
#[derive(Serialize, Deserialize)]
pub struct EnrollResp {
    pub cert_pem:    String,
    pub ca_pem:      String,
    pub node_config: NodeConfig,
}

#[derive(Serialize, Deserialize)]
pub struct NodeConfig {
    pub uuid: String,
    pub role_flag: String,              // "writer" | "witness" | "both"
    pub expires_at:  i64,               // unix epoch secs
}