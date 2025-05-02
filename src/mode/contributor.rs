use crate::{
    config::ContributorConfig,
    handlers::enroll::models::{EnrollReq, EnrollResp},
    crypto::prepare_tx,
    grpc::send_tx,
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as b64, Engine};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use reqwest::Client;
use serde_json::{Value, Map};
use std::{
    fs,
    io::{Write, stdout},
    path::{Path, PathBuf},
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
use pkcs8::{EncodePrivateKey, DecodePrivateKey, LineEnding};
use openssl::{
    ec::{EcGroup, EcKey},
    pkey::PKey,
    nid::Nid,
};

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
        ["aes.key", "ca.pem", "client.key", "client.pem", "det.key", "node.json", "node.key", "node.pub"]
            .iter()
            .all(|f| file(&dir, f).exists())
    };

    if is_enrolled() {
        println!("[Contributor] state already initialised, ready.");
        start_json_server(
            dir.clone(),
            cfg.sequencer_grpc_domain.clone(),
            cfg.sequencer_http_domain.clone(),
        ).await?;
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
                        
                        start_json_server(
                            dir.clone(),
                            cfg.sequencer_grpc_domain.clone(),
                            cfg.sequencer_http_domain.clone(),
                        ).await?;
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
    let sk_path = file(dir, "node.key");
    let pk_path = file(dir, "node.pub");
    if !sk_path.exists() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = VerifyingKey::from(&sk);
        let sk_bytes = sk.to_bytes();
        let pk_bytes = pk.to_bytes();
        // write 32‐byte seed
        async_fs::write(&sk_path, &sk_bytes)
            .await
            .context("persist node.key")?;
        // write 32‐byte pub
        async_fs::write(&pk_path, &pk_bytes)
            .await
            .context("persist node.pub")?;
    }

    // -------------------- TLS keypair (P-256) --------------------
    let ec_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let (pkey, spki_der) = if !file(dir, "client.key").exists() {
        // generate new key
        let ec = EcKey::generate(&ec_group)?;
        let pkey = PKey::from_ec_key(ec)?;
        // ----- write PKCS#8 PEM -----
        let pkcs8_pem = pkey.private_key_to_pem_pkcs8()?;
        async_fs::write(file(dir, "client.key"), &pkcs8_pem).await?;
        // return SPKI DER for enroll
        let spki = pkey.public_key_to_der()?;
        (pkey, spki)
    } else {
        // ----- read PKCS#8 PEM back -----
        let pem = async_fs::read(file(dir, "client.key")).await?;
        let pkey = PKey::private_key_from_pem(&pem)?;
        let spki = pkey.public_key_to_der()?;
        (pkey, spki)
    };

    let pub_key_b64 = base64::engine::general_purpose::STANDARD.encode(&spki_der);

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
    async_fs::write(file(dir, "client.pem"), resp.cert_pem).await?;
    async_fs::write(file(dir, "ca.pem"),     resp.ca_pem).await?;

    async_fs::write(file(dir, "aes.key"), resp.aes_key_b64).await?;
    async_fs::write(file(dir, "det.key"), resp.det_key_b64).await?;
    async_fs::write(
        file(dir, "node.json"),
        serde_json::to_string_pretty(&resp.node_config)?,
    ).await?;

    println!("[Contributor] enrollment complete; uuid = {}", resp.node_config.uuid);
    Ok(())
}

async fn start_json_server(
    dir: PathBuf,
    grpc_domain: String,
    http_domain: String,
) -> anyhow::Result<()> {
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

            let dir         = dir.to_path_buf(); 
            let grpc_domain = grpc_domain.to_owned();
            let http_domain = http_domain.to_owned(); 
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
                                        
                                        match prepare_tx(obj, &dir) {
                                            Ok(tx) => {
                                                #[cfg(debug_assertions)]
                                                match serde_json::to_string_pretty(&tx) {
                                                    Ok(s)  => println!("[JSON server] -> Tx:\n{}", s),
                                                    Err(e) => eprintln!("[JSON server] JSON pretty‐print error: {}", e),
                                                }
                                        
                                                if let Err(e) = send_tx(&tx, &dir, &grpc_domain, &http_domain).await {
                                                    eprintln!("[JSON server] gRPC send error: {e:?}");
                                                }
                                            }
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