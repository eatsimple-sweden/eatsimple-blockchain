use tonic::{Request, Response, Status};
use crate::{
    pb::{
        ingest_service_server::{IngestService, IngestServiceServer},
        TxRequest, IngestResponse,
    },
    #[cfg(feature = "sequencer")]
    config::SequencerAppState,
};

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
