use crate::{
    batch::batch_loop,
    config::{
        SequencerConfig, SequencerAppState
    },
    grpc::TxRequest,
    handlers::enroll::enroll_handler,
};
use crate::utils::{
    load_certs, load_key, load_ca,
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
    tokio::spawn(batch_loop(cfg.clone(), rx_ingest));

    let state = SequencerAppState { cfg: cfg.clone(), tx_ingest };
    
    let app = Router::new()
        .route("/enroll", post(enroll_handler))
        // .route("/ingest", post(ingest-handler))
        .with_state(state);

    let addr: SocketAddr = cfg.listen
        .parse()
        .context("invalid listen address")?;

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
