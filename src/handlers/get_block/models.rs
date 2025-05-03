use crate::block::{Block, BlockHeader};
use serde::{Serialize, Deserialize};

#[derive(Serialize)]
pub struct BlockResponse {
    pub header: BlockHeader,
    pub txs: Vec<serde_json::Value>,
}

impl From<Block> for BlockResponse {
    fn from(b: Block) -> Self {
        let txs = b.txs.into_iter()
            .map(|tx| {
                serde_json::from_slice(&tx.public_json).unwrap_or_default()
            })
            .collect();
        BlockResponse { header: b.header, txs }
    }
}

#[derive(Deserialize)]
pub struct BlockParams {
    pub height: u64,
}