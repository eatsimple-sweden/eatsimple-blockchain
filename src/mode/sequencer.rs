use crate::{
    batch::batch_loop,
    config::{SequencerConfig, SequencerAppState},
    grpc::{make_server},
    pb::{TxRequest},
    handlers::enroll::src::enroll_handler,
    utils::{
        load_certs, load_key, init_genesis,
    },
};

use std::{
    net::SocketAddr,
    sync::Arc,
};
use anyhow::Context;
use axum::{routing::post, Router};
use axum_server::tls_rustls::RustlsConfig;
use tokio::sync::mpsc;
use tonic::transport::{ServerTlsConfig, Identity, Certificate};
use sqlx::PgPool;
use rustls::{
    ServerConfig,
};
use sled::Db;

pub async fn run(cfg: SequencerConfig) -> anyhow::Result<()> {
    println!("[Sequencer] Starting setup...");

    // --------------------------------------------------------------
    //  Init Sled DB
    // --------------------------------------------------------------
    let block_db: Db = sled::open(&cfg.block_db_dir)
        .context("opening sled database")?;

    init_genesis(&block_db).context("initialising genesis block")?;

    // --------------------------------------------------------------
    //  Build a config WITHOUT client-auth for HTTPS
    // --------------------------------------------------------------
    let certs = load_certs(&cfg.https_cert)?;
    let key   = load_key(&cfg.https_key)?;

    let scfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("public TLS config")?; 
    
    let public_tls = RustlsConfig::from_config(Arc::new(scfg));
    
    // --------------------------------------------------------------
    //  Build a config WITH client-auth for gRPC
    // --------------------------------------------------------------
    let cert_pem = std::fs::read_to_string(&cfg.grpc_cert)?;
    let key_pem  = std::fs::read_to_string(&cfg.grpc_key)?;
    let ca_pem   = std::fs::read_to_string(&cfg.ca_root)?;

    let db = PgPool::connect(&cfg.database_url).await?;

    let server_identity = Identity::from_pem(cert_pem, key_pem);
    let client_ca_root = Certificate::from_pem(ca_pem);

    let mtls = ServerTlsConfig::new()
        .identity(server_identity)
        .client_ca_root(client_ca_root);

    let (tx_ingest, rx_ingest) = mpsc::channel::<TxRequest>(10_000);
    let state = SequencerAppState { cfg: cfg.clone(), db, tx_ingest };
    tokio::spawn(batch_loop(cfg.clone(), rx_ingest, block_db));

    // --------------------------------------------------------------
    //  start Axum (public) on 0.0.0.0:8443 or 443
    // --------------------------------------------------------------
    let axum_addr: SocketAddr = cfg.listen.parse()?;
    println!("[Sequencer] Starting HTTPS server at {}", axum_addr);
    let axum_app = Router::new()
        .route("/enroll", post(enroll_handler))
        .with_state(state.clone());

    let http_srv = axum_server::bind_rustls(axum_addr, public_tls)
        .serve(axum_app.into_make_service());

    // --------------------------------------------------------------
    //  start gRPC (private) on 0.0.0.0:50051 with mTLS
    // --------------------------------------------------------------
    let grpc_addr: SocketAddr = cfg.grpc_listen.parse()?;
    println!("[Sequencer] Starting gRPC server at {}", grpc_addr);
    let grpc_srv = tonic::transport::Server::builder()
        .tls_config(mtls)?                 // << the mTLS config
        .add_service(make_server(state))
        .serve(grpc_addr);

    // --------------------------------------------------------------
    //  Start server and propagate errors
    // --------------------------------------------------------------
    println!("[Sequencer] Starting servers…");
    let (http_res, grpc_res) = tokio::join!(http_srv, grpc_srv);

    http_res  
        .context("HTTPS server terminated unexpectedly")?;

    grpc_res
        .context("gRPC server terminated unexpectedly")?;

    Ok(())
}
