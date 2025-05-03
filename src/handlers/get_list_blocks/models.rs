use serde::{Serialize, Deserialize};

#[derive(Deserialize)]
pub struct ListBlocksReq {
    pub start: Option<u64>,
    pub limit: Option<usize>,
}

#[derive(Serialize)]
pub struct BlockSummary {
    pub height: u64,
    pub merkle_root: String,
    pub entries: u32,
}