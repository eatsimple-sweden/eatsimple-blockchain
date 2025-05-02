use anyhow::Result;
use eatsimple_blockchain::config;
use eatsimple_blockchain::mode;
use tracing_subscriber::fmt;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = config::SequencerConfig::load("config/sequencer.toml")?;

    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install default crypto provider");
    
    mode::sequencer::run(cfg).await
}