use serde::Serialize;

#[derive(Serialize)]
pub struct ChainTip {
    pub height: u64,
    pub merkle_root: String,
}