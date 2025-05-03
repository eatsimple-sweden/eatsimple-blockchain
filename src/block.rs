use crate::{
    pb::{TxRequest, BlockHeader as PbHeader},
};

use blake3::Hasher;
use bincode::{
    serde::{decode_from_slice, encode_to_vec},
    config::standard,
};
use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Result, Context, bail};
use byteorder::{BigEndian, ReadBytesExt};
use prost::Message;
use std::io::{Cursor, Read};

// Merkle tree over `blake3(tx_serialised)` leaves.
// Returns (root, vec<leaf_hashes>)
pub fn merkle_root(leaves: &[TxRequest]) -> ([u8;32], Vec<[u8;32]>) {
    if leaves.is_empty() {
        return ([0u8; 32], vec![]);
    }

    // produce one 32-byte leaf hash per TxRequest
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|tx| {
        let mut h = Hasher::new();

        h.update(tx.node_uuid.as_bytes());
        h.update(&tx.timestamp_ms.to_be_bytes());
        h.update(&tx.public_json);
        h.update(&tx.cipher_hash);

        for token in &tx.index_tokens {
            h.update(token);
        }

        h.finalize().into()
    }).collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len()+1)/2);
        for pair in level.chunks(2) {
            let mut h = Hasher::new();
            h.update(&pair[0]);
            h.update(if pair.len()==2 { &pair[1] } else { &pair[0] });
            next.push(h.finalize().into());
        }
        level = next;
    }

    (level[0], level)
}

// blake3 hash helper
pub fn hash_header(header: &BlockHeader) -> [u8; 32] {
    let bytes = encode_to_vec(header, standard())
        .expect("bincode encode header");
    let mut h = Hasher::new();
    h.update(&bytes);
    h.finalize().into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height:       u64,
    pub prev_hash:    [u8; 32],
    pub merkle_root:  [u8; 32],
    pub timestamp_ms: i64,
    pub entries:      u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs:    Vec<TxRequest>,
}

impl From<&BlockHeader> for PbHeader {      // for sending block header
    fn from(h: &BlockHeader) -> PbHeader {
        PbHeader {
            height:       h.height,
            prev_hash:    h.prev_hash.to_vec(),
            merkle_root:  h.merkle_root.to_vec(),
            timestamp_ms: h.timestamp_ms,
            entries:      h.entries,
        }
    }
}

pub fn decode_block(buf: &[u8]) -> anyhow::Result<Block> {
    // decode_from_slice returns (T, bytes_read)
    let (blk, _): (Block, _) =
        decode_from_slice(buf, standard())
            .context("bincode decode Block")?;
    Ok(blk)
}