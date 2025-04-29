use crate::{
    config::ContributorConfig,
    handlers::enroll::models::{EnrollReq, EnrollResp},
    crypto::prepare_tx,
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as b64, Engine};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use reqwest::Client;
use serde_json::{json, Value, Map};
use std::{
    fs,
    io::{Write, stdout},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::TcpListener,
    fs as async_fs,
    sync::Mutex,
    task::JoinHandle,
};
use once_cell::sync::Lazy;
use tracing::debug;

fn file(p: &Path, name: &str) -> PathBuf {
    p.join(name)
}

static JSON_SERVER: Lazy<Mutex<Option<JoinHandle<()>>>> =
    Lazy::new(|| Mutex::new(None));

pub async fn run(cfg: ContributorConfig) -> Result<()> {
    let dir: PathBuf = {
        let p = Path::new(&cfg.state_dir);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            Path::new(env!("CARGO_MANIFEST_DIR")).join(p)
        }
    };
    fs::create_dir_all(&dir)
        .with_context(|| format!("creating state_dir `{}`", dir.display()))?;
    println!("[Contributor] using state_dir: {}", dir.display());

    // ------------------------------------------------------------------
    // check if we already have everything for state -> nothing to do
    // ------------------------------------------------------------------
    let is_enrolled = || {
        ["node.key", "node.pub", "seq.crt", "ca.pem", "aes.key", "det.key", "node.json"]
            .iter()
            .all(|f| file(&dir, f).exists())
    };

    if is_enrolled() {
        println!("[Contributor] state already initialised, ready.");
        start_json_server(&dir).await?;
    } else {
        println!("[Contributor] not yet enrolled; type `enroll` to get started.");
    }

    let mut reader = BufReader::new(tokio::io::stdin()).lines();
    loop {
        print!("> ");
        stdout().flush().ok();

        let line = match reader.next_line().await? {
            Some(l) => l.trim().to_string(),
            None => break, // EOF
        };

        match line.as_str() {
            "" => continue,

            "exit" | "quit" => {
                println!("bye!");
                break;
            }

            "clear" => {
                stop_json_server().await;
                
                if dir.exists() {
                    fs::remove_dir_all(&dir)
                        .with_context(|| format!("removing state_dir `{}`", dir.display()))?;
                    println!("[Contributor] cleared `{}`", dir.display());
                    fs::create_dir_all(&dir)?;
                    println!("[Contributor] recreated empty state_dir");
                } else {
                    println!("[Contributor] nothing to clear");
                }
            }

            "enroll" => {
                if is_enrolled() {
                    println!("[Contributor] already enrolled");
                } else {
                    if let Err(e) = do_enroll(&cfg, &dir).await {
                        eprintln!("[Contributor] enroll failed: {:?}", e);
                    } else {
                        println!("[Contributor] enroll succeeded");
                        
                        start_json_server(&dir).await?;
                    }
                }
            }

            other => {
                println!("unknown command `{}`; available: enroll, clear, exit", other);
            }
        }
    }

    Ok(())
}

async fn do_enroll(cfg: &ContributorConfig, dir: &Path) -> Result<()> {
    // ------------------------------------------------------------------
    // generate key-pair on first run if no state
    // ------------------------------------------------------------------
    let mut csprng = OsRng;
    let (priv_bytes, pub_bytes) = if !file(dir, "node.key").exists() {
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let sk = signing_key.to_bytes();
        let pk = verifying_key.to_bytes();
        fs::write(file(dir, "node.key"), &sk)?;
        fs::write(file(dir, "node.pub"), &pk)?;
        println!("🔑 generated new key-pair");
        (sk.to_vec(), pk.to_vec())
    } else {
        (fs::read(file(dir, "node.key"))?, fs::read(file(dir, "node.pub"))?)
    };

    let mut spki_der = Vec::with_capacity(43);
    spki_der.extend_from_slice(&[
        0x30, 0x2a,
        0x30, 0x05,
          0x06, 0x03, 0x2b, 0x65, 0x70,
        0x03, 0x21, 0x00,
    ]);
    spki_der.extend_from_slice(&pub_bytes);
    let pub_key_b64 = b64.encode(&spki_der);

    // ------------------------------------------------------------------
    // enrol with sequencer (EXAMPLE JWT)
    // ------------------------------------------------------------------
    let req = EnrollReq {
        enroll_jwt:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwidXNlcl90eXBlIjoidXNlciIsImV4cCI6MTkxNjIzOTAyMiwicm9sZV9mbGFnIjoiY29udHJpYnV0b3IifQ.1JJfDFVHl_FpQK6yKwi8ZFUwZxmUQGoacXng8CDF-OE".to_string(),
        pubkey:         pub_key_b64,
        hw_id:          None,   // TODO
    };

    println!("enrolling with sequencer at {}", cfg.sequencer_http_domain);
    let client = Client::builder()
        .timeout(std::time::Duration::from_millis(cfg.max_retry_ms))
        .build()?;
    let url = format!("https://{}/enroll", cfg.sequencer_http_domain);
    let resp: EnrollResp = client
        .post(&url)
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
    async_fs::write(file(dir, "seq.crt"),   resp.cert_pem).await?;
    async_fs::write(file(dir, "ca.pem"),    resp.ca_pem).await?;
    async_fs::write(file(dir, "aes.key"),   resp.aes_key_b64).await?;
    async_fs::write(file(dir, "det.key"),   resp.det_key_b64).await?;
    async_fs::write(
        file(dir, "node.json"),
        serde_json::to_string_pretty(&resp.node_config)?,
    )
    .await?;

    println!("[Contributor] enrollment complete; uuid = {}", resp.node_config.uuid);
    Ok(())
}

async fn start_json_server(dir: &Path) -> anyhow::Result<()> {
    let dir = dir.to_path_buf();
    let mut guard = JSON_SERVER.lock().await;
    if guard.is_some() {
        return Ok(());
    }

    let handle = tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:4000")
            .await
            .expect("JSON server bind failed");
        println!("[JSON server] listening on 127.0.0.1:4000");

        loop {
            let (socket, peer) = match listener.accept().await {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[JSON server] accept error: {}", e);
                    continue;
                }
            };
            debug!("[JSON server] new connection from {}", peer);

            let dir = dir.clone(); 
            tokio::spawn(async move {
                let mut reader = tokio::io::BufReader::new(socket);
                let mut buf = String::new();

                loop {
                    match reader.read_line(&mut buf).await {
                        Ok(0) => break, // EOF
                        Ok(_) => {
                            let line = buf.trim_end();
                            match serde_json::from_str::<Map<String, Value>>(line) {
                                Ok(obj) => {
                                    if obj.contains_key("event_type") && obj.len() >= 2 {
                                        
                                        let public_fields = &["event_type", "order_id", "product_id"];
                                        match prepare_tx(obj, public_fields, &dir) {
                                            Ok(tx_json) => println!("[JSON server] -> Tx: {:#}", tx_json),
                                            Err(e)     => eprintln!("[JSON server] prepare_tx error: {:?}", e),
                                        }
                                    } else {
                                        eprintln!(
                                            "[JSON server] missing `event_type` or too few fields: {}",
                                            line
                                        );
                                    }
                                }
                                Err(err) => {
                                    eprintln!(
                                        "[JSON server] invalid JSON: {}  (parse error: {})",
                                        line, err
                                    );
                                }
                            }
                            buf.clear();
                        }
                        Err(e) => {
                            eprintln!("[JSON server] read error: {}", e);
                            break;
                        }
                    }
                }

                debug!("[JSON server] connection closed");
            });
        }
    });

    *guard = Some(handle);
    Ok(())
}

async fn stop_json_server() {
    let mut guard = JSON_SERVER.lock().await;
    if let Some(handle) = guard.take() {
        println!("[JSON server] shutting down");
        handle.abort();
    }
}