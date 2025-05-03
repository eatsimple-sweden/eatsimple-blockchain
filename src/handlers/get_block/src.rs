use crate::{
    config::{SequencerAppState},
    block::decode_block,
};
use super::models::{BlockResponse, BlockParams};
use axum::{
    Json,
    extract::{State, Query},
    http::StatusCode,
};

pub async fn get_block_handler(
    State(state): State<SequencerAppState>,
    Query(params): Query<BlockParams>,
) -> Result<Json<BlockResponse>, (StatusCode, String)> {
    let tree = state
        .block_db
        .open_tree("chain")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let raw = tree
        .get(&params.height.to_be_bytes())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, format!("block {} not found", params.height)))?;

    let blk = decode_block(&raw)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(BlockResponse::from(blk)))
}