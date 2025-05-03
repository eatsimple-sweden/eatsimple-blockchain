use crate::{
    pb::{TxRequest, BlockHeader as PbHeader},
};

use blake3::Hasher;
use bincode::config::standard;
use bincode::serde::encode_to_vec;
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

const MAX_TX_BYTES: usize = 1 * 1024 * 1024;
pub fn decode_block(buf: &[u8]) -> anyhow::Result<Block> {
    let mut cur = Cursor::new(buf);

    let height       = cur.read_u64::<BigEndian>()?;
    let mut prev_hash = [0; 32];
    cur.read_exact(&mut prev_hash)?;
    let mut merkle    = [0; 32];
    cur.read_exact(&mut merkle)?;
    let timestamp_ms = cur.read_i64::<BigEndian>()?;
    let entries      = cur.read_u32::<BigEndian>()?;

    let mut txs = Vec::with_capacity(entries as usize);
    for _ in 0..entries {
        let len = cur.read_u32::<BigEndian>()? as usize;

        // sanity-check the length -------------------------
        if len == 0 || len > MAX_TX_BYTES {
            bail!("invalid Tx length {len} B (cap {MAX_TX_BYTES} B)");
        }
        let start = cur.position() as usize;
        let end   = start.checked_add(len)
            .filter(|&e| e <= buf.len())
            .context("Tx length exceeds block buffer")?;

        let slice = &buf[start..end];
        let tx = TxRequest::decode(slice)
            .context("prost decode TxRequest")?;

        txs.push(tx);
        cur.set_position(end as u64);
    }

    Ok(Block {
        header: BlockHeader {
            height,
            prev_hash,
            merkle_root: merkle,
            timestamp_ms,
            entries,
        },
        txs,
    })
}