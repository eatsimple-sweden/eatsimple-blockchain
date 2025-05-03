use crate::{
    batch::Sealed,
    pb::TxRequest,
    config::SequencerConfig,
    block::{Block, BlockHeader},
};

use tracing::{info, warn, debug, error, info_span, Instrument};
use prost::Message;
use anyhow::Context;
use sled::Db;
use byteorder::{BigEndian, ByteOrder};
use bincode::{
    config::standard,
    serde::encode_to_vec,
};

pub async fn persist_block(sealed: &Sealed, db: &sled::Db) -> anyhow::Result<()> {
    let blk = &sealed.block;
    
    tracing::info!(
        height       = blk.header.height,
        merkle_root  = %hex::encode(blk.header.merkle_root),
        entries      = blk.header.entries,
        sig_count    = sealed.sigs.len(),
        "committing block"
    );

    // bincode-encode the entire structure
    let val = encode_to_vec(blk, standard())?;
    db.open_tree("chain")?
        .insert(blk.header.height.to_be_bytes(), val)?;
    db.flush()?;

    Ok(())
}

pub fn init_genesis(db: &sled::Db) -> anyhow::Result<()> {
    let chain = db.open_tree("chain")
        .context("opening sled tree `chain`")?;

    if chain.is_empty() {
        let header = BlockHeader {
            height:       0,
            prev_hash:    [0u8; 32],
            merkle_root:  [0u8; 32],
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            entries:      0,
        };
        let genesis = Block { header: header.clone(), txs: vec![] };

        let mut buf = Vec::new();
        buf.extend_from_slice(&header.height.to_be_bytes());
        buf.extend_from_slice(&header.prev_hash);
        buf.extend_from_slice(&header.merkle_root);
        buf.extend_from_slice(&header.timestamp_ms.to_be_bytes());
        buf.extend_from_slice(&header.entries.to_be_bytes());

        let key = header.height.to_be_bytes(); // u64 key
        chain.insert(key, buf)
            .context("inserting genesis into sled")?;
        chain.flush()
            .context("flushing sled after genesis")?;

        tracing::info!("genesis block written");
    }

    Ok(())
}