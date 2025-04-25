use crate::pb::{
    TxRequest,
};

use serde::Deserialize;
use std::fs;
use anyhow::{Context, Result};
use tokio::sync::mpsc::Sender;

#[derive(Clone, Debug, Deserialize)]
pub struct SequencerConfig {
    pub mode: String,                       // should be "sequencer"
    pub listen: String,                     // ex 0.0.0.0:8443
    pub grpc_listen: String,                // ex 0.0.0.0:50051
    pub https_cert: String,                 // "/etc/eatsimple/origin.crt"
    pub https_key: String,                  // "/etc/eatsimple/origin.key"
    pub grpc_cert: String,                  // "/etc/eatsimple/seq.crt"
    pub grpc_key: String,                   // "/etc/eatsimple/seq.key"
    pub ca_root: String,                    // "/etc/eatsimple/ca.pem"
    pub ca_key:  String,                    // path to CA private key (PEM)
    pub rocksdb_path: String,               // "/var/lib/mychain/blocks"
    pub max_block_entries: usize,           // ex 100
    pub max_block_age_ms: u64,              // ex 200
    pub anchor_interval: u64,               // ex 1000
    pub enroll_ttl_days: u64,               // ex 7
    pub witness_threshold: usize,           // ex 2
    pub witness_endpoints: Vec<String>,
}

#[derive(Clone)]
pub struct SequencerAppState { // idiomatic pattern to merge multiple shared contexts here
    pub cfg:        SequencerConfig,
    pub tx_ingest:  Sender<TxRequest>,
}

impl SequencerConfig {
    pub fn load(path: &str) -> Result<Self> {
        let s = fs::read_to_string(path)
            .with_context(|| format!("reading config file `{}`", path))?;
        let cfg: SequencerConfig = toml::from_str(&s)
            .with_context(|| format!("parsing `{}` as TOML", path))?;
        
        //  could validate here - assert!(cfg.mode == "sequencer")
        Ok(cfg)
    }
}

pub fn load(path: &str) -> Result<SequencerConfig> {
    SequencerConfig::load(path)
}