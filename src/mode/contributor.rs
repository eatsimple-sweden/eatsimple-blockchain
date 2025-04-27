use crate::{
    config::{ContributorConfig},
    handlers::enroll::models::{EnrollReq, EnrollResp, NodeConfig},
};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as b64, Engine};
use ed25519_dalek::{
    SigningKey,
    VerifyingKey,
    SECRET_KEY_LENGTH,
    PUBLIC_KEY_LENGTH,
};
use rand::rngs::OsRng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{fs, path::{Path, PathBuf}};
use tokio::fs as async_fs;

fn file(p: &Path, name: &str) -> PathBuf { p.join(name) }

pub async fn run(cfg: ContributorConfig) -> anyhow::Result<()> {
    let dir: PathBuf = {
        let p = Path::new(&cfg.state_dir);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
            manifest_dir.join(p)
        }
    };
    
    fs::create_dir_all(&dir)
        .with_context(|| format!("creating state_dir `{}`", dir.display()))?;
    println!("[Contributor] using state_dir: {}", dir.display());

    // ------------------------------------------------------------------
    // check if we already have every artefact -> nothing to do
    // ------------------------------------------------------------------
    let have_everything = ["node.key", "node.pub", "seq.crt", "ca.pem", "node.json"]
        .into_iter()
        .all(|f| file(&dir, f).exists());

    if have_everything {
        println!("[Contributor] state already initialised");
        return Ok(());
    }

    // ------------------------------------------------------------------
    // generate key-pair on first run
    // ------------------------------------------------------------------
    let mut csprng = OsRng;

    let (priv_bytes, pub_bytes) = if !file(&dir, "node.key").exists() {
        let signing_key:   SigningKey   = SigningKey::generate(&mut csprng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        let sk_bytes = signing_key.to_bytes();           // [u8; 32]
        let pk_bytes = verifying_key.to_bytes();         // [u8; 32]

        fs::write(file(&dir, "node.key"), &sk_bytes)
            .context("writing node.key")?;
        fs::write(file(&dir, "node.pub"), &pk_bytes)
            .context("writing node.pub")?;

        println!("🔑  generated new key-pair in {:?}", dir);
        (sk_bytes.to_vec(), pk_bytes.to_vec())
    } else {
        let sk = fs::read(file(&dir, "node.key"))?;
        let pk = fs::read(file(&dir, "node.pub"))?;
        anyhow::ensure!(sk.len() == SECRET_KEY_LENGTH, "node.key wrong length");
        anyhow::ensure!(pk.len() == PUBLIC_KEY_LENGTH, "node.pub wrong length");
        (sk, pk)
    };

    let pub_key_b64 = base64::engine::general_purpose::STANDARD.encode(&pub_bytes);

    // ------------------------------------------------------------------
    // enrol with sequencer
    // ------------------------------------------------------------------
    let req = EnrollReq {
        enroll_jwt: "let-me-in".to_string(),
        pubkey: pub_key_b64,
        hw_id: None,
    };

    println!("enrolling with sequencer");

    let client = Client::builder()
        .timeout(std::time::Duration::from_millis(cfg.max_retry_ms))
        .build()?;

    let url = format!("https://{}/enroll", cfg.sequencer_http_domain);
    let resp: EnrollResp = client
        .post(url)
        .json(&req)
        .send()
        .await
        .context("HTTP POST /enroll")?
        .json()
        .await
        .context("decoding /enroll response")?;


    // ------------------------------------------------------------------
    // persist the response
    // ------------------------------------------------------------------
    async_fs::write(file(&dir, "seq.crt"), resp.cert_pem).await?;
    async_fs::write(file(&dir, "ca.pem"),  resp.ca_pem).await?;
    async_fs::write(
        file(&dir, "node.json"),
        serde_json::to_string_pretty(&resp.node_config)?,
    )
    .await?;

    println!("✅  enrolment complete – state written to {:?}", dir);
    println!("    assigned uuid = {}", resp.node_config.uuid);

    Ok(())
}