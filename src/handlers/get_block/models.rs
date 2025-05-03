use crate::block::{Block, BlockHeader};
use serde::{Serialize, Deserialize};
use crate::handlers::get_tx::models::TxView;

#[derive(Serialize)]
pub struct BlockResponse {
    pub header: BlockHeader,
    pub txs: Vec<TxView>,
}

impl From<Block> for BlockResponse {
    fn from(b: crate::block::Block) -> Self {
        BlockResponse {
            header: b.header,
            txs:    b.txs.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Deserialize)]
pub struct BlockParams {
    pub height: u64,
}