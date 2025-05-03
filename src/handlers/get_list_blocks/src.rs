use crate::{
    config::{SequencerAppState},
    block::decode_block,
};
use super::models::{ListBlocksReq, BlockSummary};
use axum::{
    Json,
    http::StatusCode,
    extract::{State, Query}
};
use byteorder::{BigEndian, ByteOrder};

pub async fn get_list_blocks_handler(
    State(state): State<SequencerAppState>,
    Query(params): Query<ListBlocksReq>,
) -> Result<Json<Vec<BlockSummary>>, (StatusCode, String)> {
    // open sled tree
    let tree = state
        .block_db
        .open_tree("chain")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // default start=0, limit=50 (or whatever makes sense)
    let start = params.start.unwrap_or(0) as usize;
    let limit = params.limit.unwrap_or(50);

    let mut out = Vec::with_capacity(limit);

    for item in tree.iter().skip(start).take(limit) {
        let (k, v) = item
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let height = BigEndian::read_u64(&k);

        let blk = decode_block(&v)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        out.push(BlockSummary {
            height,
            merkle_root: hex::encode(blk.header.merkle_root),
            entries: blk.header.entries,
        });
    }

    Ok(Json(out))
}