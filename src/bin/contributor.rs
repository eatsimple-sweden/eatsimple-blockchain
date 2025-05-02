use anyhow::Result;
use eatsimple_blockchain::config;
use eatsimple_blockchain::mode;

#[tokio::main]
async fn main() -> Result<()> {
    let contributor_cfg = config::ContributorConfig::load("config/contributor.toml")?;

    unsafe {
        std::env::set_var("RUST_LOG", "rustls=trace,webpki=trace");
    }
    tracing_subscriber::fmt::init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install ring provider");
    
    mode::contributor::run(contributor_cfg).await
}