use anyhow::Result;
use eatsimple_blockchain::config;
use eatsimple_blockchain::mode;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = config::SequencerConfig::load("config/sequencer.toml")?;

    unsafe {
        std::env::set_var("RUST_LOG", "rustls=trace,webpki=trace");
    }
    tracing_subscriber::fmt::init();

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install default crypto provider");
    
    mode::sequencer::run(cfg).await
}