use crate::{
    config::{SequencerAppState},
    block::decode_block,
};
use super::models::{ChainTip};
use axum::{
    Json,
    http::StatusCode,
    extract::{State}
};
use byteorder::{ByteOrder, BigEndian, ReadBytesExt};

pub async fn get_chain_tip_handler(
    State(state): State<SequencerAppState>,
) -> Result<Json<ChainTip>, (StatusCode, String)> {
    let tree = state
        .block_db
        .open_tree("chain")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (k, v) = tree
        .last()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "no blocks in chain".into()))?;

    let height = BigEndian::read_u64(&k);
    let blk = decode_block(&v)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let tip = ChainTip {
        height,
        merkle_root: hex::encode(blk.header.merkle_root),
    };
    Ok(Json(tip))
}