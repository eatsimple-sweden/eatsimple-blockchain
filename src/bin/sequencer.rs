use anyhow::Result;
use eatsimple_blockchain::config;
use eatsimple_blockchain::mode;

#[tokio::main]
async fn main() -> Result<()> {
    // load the config
    let cfg = config::load("config/sequencer.toml")?;
    
    // hand off to sequencer logic (in /mode)
    mode::sequencer::run(cfg).await
}