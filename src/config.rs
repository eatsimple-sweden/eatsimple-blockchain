use crate::pb::{
    TxRequest,
};

use serde::{
    Deserialize,
    de::DeserializeOwned,
};
use std::fs;
use anyhow::{Context, Result};
use tokio::sync::mpsc::Sender;

#[cfg(feature = "sequencer")]
use sqlx::PgPool;

#[cfg(feature = "sequencer")]
#[derive(Clone, Debug, Deserialize)]
pub struct SequencerConfig {
    pub mode: String,                       // should be "sequencer"
    pub listen: String,                     // ex 0.0.0.0:8443
    pub grpc_listen: String,                // ex 0.0.0.0:50051

    pub https_cert: String,                 // "/etc/mychain/origin.crt"
    pub https_key: String,                  // "/etc/mychain/origin.key"
    pub grpc_cert: String,                  // "/etc/mychain/seq.crt"
    pub grpc_key: String,                   // "/etc/mychain/seq.key"

    pub ca_root: String,                    // "/etc/mychain/ca.pem"
    pub ca_key:  String,                    // path to CA private key (PEM)
    pub block_db_dir: String,               // "/var/lib/mychain/blocks"
    pub max_block_entries: usize,           // ex 100
    pub max_block_age_ms: u64,              // ex 200
    pub anchor_interval: u64,               // ex 1000
    pub enroll_ttl_days: u64,               // ex 7
    pub witness_threshold: usize,           // ex 2
    pub witness_endpoints: Vec<String>,
    pub sequencer_node_uuid: String,
    pub database_url: String,
    pub enroll_jwt_secret: String,          // from the main API
}

#[cfg(feature = "contributor")]
#[derive(Clone, Debug, Deserialize)]
pub struct ContributorConfig {
    pub sequencer_http_domain: String,          // "mydomain.com"
    pub sequencer_grpc_domain: String,          // "grpc.mydomain.com"
    pub max_retry_ms: u64,
    pub state_dir: String,
}

#[cfg(feature = "sequencer")]
#[derive(Clone)]
pub struct SequencerAppState { // idiomatic pattern to merge multiple shared contexts here
    pub cfg:        SequencerConfig,
    pub db:         PgPool,
    pub tx_ingest:  Sender<TxRequest>,
}

pub fn load_toml<T: DeserializeOwned>(path: &str) -> Result<T> {
    let s = fs::read_to_string(path)
        .with_context(|| format!("reading config file `{}`", path))?;
    toml::from_str(&s)
        .with_context(|| format!("parsing `{}` as TOML", path))
}

#[cfg(feature = "sequencer")]
impl SequencerConfig {
    pub fn load(path: &str) -> Result<Self> {
        load_toml(path)
    }
}

#[cfg(feature = "contributor")]
impl ContributorConfig {
    pub fn load(path: &str) -> Result<Self> {
        load_toml(path)
    }
}