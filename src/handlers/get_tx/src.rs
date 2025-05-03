use crate::{
    config::{SequencerAppState},
    block::decode_block,
};
use super::models::{TxView, TxParams};
use axum::{
    Json,
    extract::{State, Query},
    http::StatusCode,
};

// we need to maintain a secondary index mapping sig (height, offset)
// in that instance we would lookup sig in tree `"tx_index"` to get a block height + byte offset then load that block from `"chain"`, seek into the bytes, prost::decode that one TxRequest
// For now we scan every block (inefficient af) until you we get it
pub async fn get_tx_handler(
    State(state): State<SequencerAppState>,
    Query(params): Query<TxParams>,
) -> Result<Json<TxView>, (StatusCode, String)> {
    let sig = hex::decode(&params.signature_hex)
        .map_err(|_| (StatusCode::BAD_REQUEST, "bad hex".into()))?;

    let tree = state.block_db.open_tree("chain").unwrap();
    for result in tree.iter() {
        let (_k, v) = result.unwrap();
        let blk = decode_block(&v)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        for tx in blk.txs {
            if tx.signature == sig {
                let view = TxView::try_from(tx)
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                return Ok(Json(view));
            }
        }
    }

    Err((StatusCode::NOT_FOUND, "tx not found".into()))
}