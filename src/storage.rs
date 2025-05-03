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

pub async fn persist_block(sealed: &Sealed, block_db: &sled::Db) -> anyhow::Result<()> {
    let header = &sealed.block.header;

    tracing::info!(
        height      = header.height,
        merkle_root = hex::encode(header.merkle_root),
        entries     = header.entries,
        sig_count   = sealed.sigs.len(),
        "committing block"
    );

    let mut buf = Vec::new();

    // serialize header fields by hand
    buf.extend_from_slice(&header.height.to_be_bytes());
    buf.extend_from_slice(&header.prev_hash);
    buf.extend_from_slice(&header.merkle_root);
    buf.extend_from_slice(&header.timestamp_ms.to_be_bytes());
    buf.extend_from_slice(&header.entries.to_be_bytes());

    // serialize each TxRequest via prost
    for tx in &sealed.block.txs {
        let mut tx_buf = Vec::new();
        tx.encode(&mut tx_buf)
            .context("prost encode TxRequest")?;
        let len = (tx_buf.len() as u32).to_be_bytes();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(&tx_buf);
    }

    // insert into sled keyed by block‐height
    let key = header.height.to_be_bytes();
    block_db.insert(key, buf)?;
    block_db.flush()?; // make sure it hits disk

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