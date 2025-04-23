use crate::{
    batch::batch_loop,
    config::{SequencerConfig, SequencerAppState},
    grpc::{make_server},
    pb::{TxRequest},
    handlers::enroll::enroll_handler,
    utils::{
        load_certs, load_key, load_ca,
    },
};

use std::{
    net::SocketAddr,
    sync::Arc,
};
use anyhow::Context;
use axum::{routing::post, Router};
use axum_server::tls_rustls::RustlsConfig;
use rustls::{
    server::AllowAnyAuthenticatedClient,
    ServerConfig as RustlsServerConfig,
};
use tokio::sync::mpsc;

pub async fn run(cfg: SequencerConfig) -> anyhow::Result<()> {
    println!("[Sequencer] Starting setup...");

    let cert_chain  = load_certs(&cfg.server_cert).context("reading server certificate")?;
    let priv_key    = load_key(&cfg.server_key).context("reading server private key")?;
    let ca_store    = load_ca(&cfg.ca_root).context("reading CA root cert")?;
    let verifier    = AllowAnyAuthenticatedClient::new(ca_store);
    let srv_cfg     = RustlsServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(cert_chain, priv_key)
        .context("invalid TLS cert/key combo")?;
    let tls_config = RustlsConfig::from_config(Arc::new(srv_cfg));

    let (tx_ingest, rx_ingest) = mpsc::channel::<TxRequest>(10_000);
    let state = SequencerAppState { cfg: cfg.clone(), tx_ingest };
    tokio::spawn(batch_loop(cfg.clone(), rx_ingest));
    
    /* ---------- HTTP(Axum) server ---------- */
    let http_addr: SocketAddr = cfg.listen.parse().context("listen addr")?;
    let http_app = Router::new()
        .route("/enroll", post(enroll_handler))
        .with_state(state.clone());
        
    println!("[Sequencer] Starting HTTPS server at {}", http_addr);
    let http_srv = axum_server::bind_rustls(http_addr, tls_config)
        .serve(http_app.into_make_service());

    /* ---------- gRPC server ---------- */
    // let grpc_addr = "0.0.0.0:50051".parse()?;
    let grpc_addr: SocketAddr = cfg.grpc_listen.parse()?;
    
    println!("[Sequencer] Starting gRPC server at {}", grpc_addr);
    let grpc_srv = tonic::transport::Server::builder()
        .add_service(make_server(state))
        .serve(grpc_addr);

    tokio::join!(http_srv, grpc_srv);
    Ok(())
}
