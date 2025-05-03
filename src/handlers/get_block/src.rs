use crate::{
    config::{SequencerAppState},
    block::decode_block,
};
use super::models::{BlockResponse};
use axum::{
    Json,
    extract::{State, Path},
    http::StatusCode,
};

pub async fn get_block_handler(
    State(state): State<SequencerAppState>,
    Path(height): Path<u64>,
) -> Result<Json<BlockResponse>, (StatusCode, String)> {
    let tree = state
        .block_db
        .open_tree("chain")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let raw = tree
        .get(&height.to_be_bytes())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, format!("block {} not found", height)))?;

    let blk = decode_block(&raw)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // assume you have `impl From<Block> for BlockResponse`
    Ok(Json(BlockResponse::from(blk)))
}