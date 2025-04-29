use crate::{
    config::ContributorConfig,
    handlers::enroll::models::{EnrollReq, EnrollResp, NodeConfig},
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as b64, Engine};
use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH, PUBLIC_KEY_LENGTH};
use rand::rngs::OsRng;
use reqwest::Client;
use serde_json::{json, Value};
use std::{
    fs,
    io::{Write, stdout},
    path::{Path, PathBuf},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::TcpListener,
    sync::OnceCell,
    fs as async_fs,
};

fn file(p: &Path, name: &str) -> PathBuf {
    p.join(name)
}

static JSON_SERVER_STARTED: OnceCell<()> = OnceCell::const_new();

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
        start_json_server().await?;
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
                    match do_enroll(&cfg, &dir).await {
                        Ok(()) => {
                            println!("[Contributor] enroll succeeded");
                            start_json_server().await?;
                        }
                        Err(e) => eprintln!("[Contributor] enroll failed: {:?}", e),
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

async fn start_json_server() -> Result<()> {
    JSON_SERVER_STARTED
        .get_or_try_init(|| async {
            tokio::spawn(async {
                let listener = TcpListener::bind("127.0.0.1:4000")
                    .await
                    .expect("cannot bind JSON server");
                println!("[JSON server] listening on 127.0.0.1:4000");

                loop {
                    let (socket, addr) = match listener.accept().await {
                        Ok(pair) => pair,
                        Err(e) => {
                            eprintln!("[JSON server] accept error: {}", e);
                            continue;
                        }
                    };
                    println!("[JSON server] new connection from {}", addr);

                    tokio::spawn(async move {
                        let mut rd = BufReader::new(socket);
                        let mut line = String::new();
                        while let Ok(n) = rd.read_line(&mut line).await {
                            if n == 0 { break; }
                            // try to parse JSON just for demo
                            match serde_json::from_str::<Value>(&line) {
                                Ok(v) => println!("[JSON server] → {:?}", v),
                                Err(_) => println!("[JSON server] (invalid JSON) {}", line.trim()),
                            }
                            line.clear();
                        }
                        println!("[JSON server] connection closed");
                    });
                }
            });
            Ok(())
        })
        .await
        .map(|_| ())
}