use tonic::{Request, Response, Status};
use crate::{
    pb::{
        ingest_service_server::{IngestService, IngestServiceServer},
        TxRequest, IngestResponse,
    },
    config::SequencerAppState,
};

#[derive(Clone)]
pub struct IngestSvc { pub state: SequencerAppState }

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

pub fn make_server(state: SequencerAppState) -> IngestServiceServer<IngestSvc> {
    IngestServiceServer::new(IngestSvc { state })
}
