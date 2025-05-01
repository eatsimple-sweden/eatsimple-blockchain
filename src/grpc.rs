use crate::{
    pb::{
        ingest_service_server::{IngestService, IngestServiceServer},
        ingest_service_client::IngestServiceClient,
        TxRequest, IngestResponse,
    },
    crypto::{Tx},
};

use tonic::{Request, Response, Status};
use tonic::transport::{Channel, ClientTlsConfig, Certificate, Identity};
use std::path::Path;
use base64::{decode, encode};  

#[cfg(feature = "sequencer")]
use crate::config::SequencerAppState;

#[cfg(feature = "sequencer")]
#[derive(Clone)]
pub struct IngestSvc { pub state: SequencerAppState }

#[cfg(feature = "sequencer")]
#[tonic::async_trait]
impl IngestService for IngestSvc {
    
	async fn ingest(
        &self,
        req: Request<TxRequest>,
    ) -> Result<Response<IngestResponse>, Status> {
        let tx = req.into_inner();
        self.state.tx_ingest
            .send(tx)
            .await
            .map_err(|_| Status::internal("queue closed"))?;
        Ok(Response::new(IngestResponse { ok: true, message: "queued".into() }))
    }
}

#[cfg(feature = "sequencer")]
pub fn make_server(state: SequencerAppState) -> IngestServiceServer<IngestSvc> {
    IngestServiceServer::new(IngestSvc { state })
}

#[cfg(feature = "contributor")]
pub async fn send_tx(tx: &Tx, dir: &Path, sequencer_url: &str) -> anyhow::Result<()> {
    let client_cert = tokio::fs::read(dir.join("client.pem")).await?;
    let client_key  = tokio::fs::read(dir.join("client.key")).await?;
    let ca_cert     = tokio::fs::read(dir.join("ca.pem")).await?;

    let tls = ClientTlsConfig::new()
        .domain_name("sequencer.example.com")
        .identity(Identity::from_pem(client_cert, client_key))
        .ca_certificate(Certificate::from_pem(ca_cert));

    let channel = Channel::from_shared(sequencer_url.to_owned())?
        .tls_config(tls)?
        .connect()
        .await?;

    let mut client = IngestServiceClient::connect(sequencer_url.to_owned()).await?;

    let req = TxRequest {
        node_uuid:    tx.node_id.clone(),
        timestamp_ms: tx.timestamp,
        public_json:  serde_json::to_vec(&tx.public)?,
        nonce:        tx.nonce.to_vec(),
        cipher_bytes: decode(&tx.ciphertext)?,
        cipher_hash:  hex::decode(&tx.cipher_hash)?,
        index_tokens: tx.index_tokens
                          .iter()
                          .map(|h| hex::decode(h).unwrap())
                          .collect(),
        signature:    decode(&tx.sig)?,
    };

    client.ingest(Request::new(req)).await?;
    Ok(())
}