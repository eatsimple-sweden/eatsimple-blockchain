use anyhow::Result;
use eatsimple_blockchain::config;
use eatsimple_blockchain::mode;

#[tokio::main]
async fn main() -> Result<()> {
    let contributor_cfg = config::ContributorConfig::load("config/contributor.toml")?;
    
    mode::contributor::run(contributor_cfg).await
}