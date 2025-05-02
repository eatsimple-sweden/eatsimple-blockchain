use anyhow::Result;
use eatsimple_blockchain::config;
use eatsimple_blockchain::mode;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = config::SequencerConfig::load("config/sequencer.toml")?;

    rustls::crypto::aws_lc_rs::install_default();
    
    mode::sequencer::run(cfg).await
}