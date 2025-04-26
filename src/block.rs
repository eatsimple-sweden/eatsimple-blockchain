use crate::{
    pb::{TxRequest, BlockHeader as PbHeader},
};

use blake3::Hasher;
use std::time::Instant;
use prost::Message;
use bincode::config::standard;
use bincode::serde::encode_to_vec;
use serde::{Deserialize, Serialize};

/// Merkle tree over `blake3(tx_serialised)` leaves.
/// Returns (root, vec<leaf_hashes>)
pub fn merkle_root(leaves: &[TxRequest]) -> ([u8; 32], Vec<[u8; 32]>) {
    if leaves.is_empty() {
        return ([0u8; 32], vec![]);
    }

    // hash each leaf via Prost::Message::encode
    let mut level: Vec<[u8; 32]> = leaves
        .iter()
        .map(|tx| {
            let mut buf = Vec::new();
            tx.encode(&mut buf)         // Prost encode into a Vec<u8>
              .expect("prost encode leaf");
            let mut h = Hasher::new();
            h.update(&buf);
            h.finalize().into()
        })
        .collect();

    // pair-wise “hash-up” to root
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            let mut h = Hasher::new();
            h.update(&pair[0]);
            h.update(if pair.len() == 2 { &pair[1] } else { &pair[0] });
            next.push(h.finalize().into());
        }
        level = next;
    }

    (level[0], level)
}

/// blake3 hash helper
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

#[derive(Clone, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub txs:    Vec<TxRequest>,
}

pub enum Pending { // state machine for incoming transactions
    None,
    Building {
        txs:   Vec<TxRequest>,
        start: Instant,
        height: u64,
        prev_hash: [u8; 32],
    },
    Proposed {
        block:    Block,
        sigs:     Vec<Vec<u8>>,          // collected witness sigs
        sent_at:  Instant,
    },
    Confirmed { 
        block: Block, 
        sigs: Vec<Vec<u8>>, 
        confirmed_at: Instant 
    },
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