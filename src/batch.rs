use crate::{
    config::SequencerConfig,
    pb::TxRequest,
};
use anyhow::Result;
use tokio::sync::mpsc::Receiver;

pub async fn batch_loop(
    _cfg: SequencerConfig,
    _rx: Receiver<TxRequest>,
) -> Result<()> {
    loop {
        // stub: sleep so we don’t hot‑spin
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}