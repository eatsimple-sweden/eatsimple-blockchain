use crate::{
    block::{Pending, merkle_root, hash_header, Block, BlockHeader},
    config::SequencerConfig,
    pb::{
        TxRequest,
        witness_service_client::WitnessServiceClient,
        BlockProposal,
        ProposeResponse,
    },
};
use anyhow::{Result, Context};
use chrono::Utc;
use tokio::{sync::mpsc::Receiver, time::{self, Duration, Instant}};
use std::time::Instant as StdInstant;
use openssl::{
    pkey::PKey,
    sign::Signer,
};
use tonic::Request;
use futures::{
    stream::FuturesUnordered,
    StreamExt,
};

// frequency we check the buffer for flush conditions
const TICK_MS: u64 = 50;

pub async fn batch_loop(
    cfg:        SequencerConfig, 
    mut rx:     Receiver<TxRequest>
) -> Result<()> {
    // buffer for the block we are currently building
    let mut building: Option<(
        Vec<TxRequest>,     // transactions
        Instant,            // started time
        u64,                // height
        [u8;32]             // prev_hash
    )> = None;
    
    let mut proposed_blocks: Vec<Pending> = Vec::new(); // keep proposed blocks around until their sigs collected

    // helper function to check if we should flush
    let should_flush = |txs: &[TxRequest], start: Instant| -> bool {
        txs.len() >= cfg.max_block_entries ||
        start.elapsed().as_millis() as u64 >= cfg.max_block_age_ms
    };

    loop {
        tokio::select! {
            // --------------------------------------------------------------
            //  Handling incoming tx
            // --------------------------------------------------------------
            Some(tx) = rx.recv() => {
                // ensure we have a building buffer
                let (txs, start, height, prev_hash) = building
                    .get_or_insert_with(|| (Vec::new(), Instant::now(), 0 /* TODO DB */, [0u8;32] /* TODO DB */));
                
                txs.push(tx);

                if should_flush(txs, *start) {
                    let (txs_to_flush, started, height, prev_hash) = building.take().unwrap();
                    let new_pending = build_and_broadcast(
                        txs_to_flush, started, height, prev_hash, cfg.clone()
                    ).await?;
                    proposed_blocks.push(new_pending);

                    // start new batch immediately
                    let prev_hdr = match proposed_blocks.last().unwrap() {
                        crate::block::Pending::Proposed { block, .. } => &block.header,
                        _ => unreachable!(),
                    };
                    building = Some((
                        Vec::new(),
                        Instant::now(),
                        height + 1,
                        hash_previous_root(prev_hdr),
                    ));
                }
            }

            // --------------------------------------------------------------
            //  Periodic check of the building buffer
            // --------------------------------------------------------------
            _ = time::sleep(Duration::from_millis(TICK_MS)) => {
                if let Some((txs, start, height, prev_hash)) = &mut building {
                    if should_flush(txs, *start) {
                        let (txs_to_flush, started, height, prev_hash) = building.take().unwrap();
                        let new_pending = build_and_broadcast(
                            txs_to_flush, started, height, prev_hash, cfg.clone()
                        ).await?;
                        proposed_blocks.push(new_pending);

                        let prev_hdr = match proposed_blocks.last().unwrap() {
                            crate::block::Pending::Proposed { block, .. } => &block.header,
                            _ => unreachable!(),
                        };
                        building = Some((
                            Vec::new(),
                            Instant::now(),
                            height + 1,
                            hash_previous_root(prev_hdr),
                        ));
                    }
                }
            }
        }
    }
}

// --------------------------------------------------------------
//  Turn buffered txs into a `Block`, sign it, broadcast ONLY header to witnesses
// --------------------------------------------------------------
async fn build_and_broadcast(
    txs:        Vec<TxRequest>,
    started:    Instant,
    height:     u64,            // TODO
    prev_hash:  [u8; 32],       // TODO
    cfg:        SequencerConfig,
) -> Result<Pending> {

    // build header
    let (root, _leaves) = merkle_root(&txs);
    let header = BlockHeader {
        height,
        prev_hash,
        merkle_root:    root,
        timestamp_ms:   Utc::now().timestamp_millis(),
        entries:        txs.len() as u32,
    };
    let block = Block { header: header.clone(), txs };

    // sequencer’s own signature over header hash
    let hdr_hash = hash_header(&block.header);
    let my_sig   = sign_with_node_key(&hdr_hash, &cfg)?; 

    // --------------------------------------------------------------
    //  collect all witness‐propose futures
    // --------------------------------------------------------------
    let mut futs = FuturesUnordered::new();
    for url in &cfg.witness_endpoints {
        let hdr = header.clone();
        let sig = my_sig.clone();
        let url = url.clone();
        futs.push(async move {
            send_proposal(url, hdr, sig).await // returns the witness’s signature on success
        });
    }

    // --------------------------------------------------------------
    //  gather responses until threshold, starting with the sequencers
    // --------------------------------------------------------------
    let mut gathered: Vec<(String, Vec<u8>)> = vec![(cfg.sequencer_node_uuid.clone(), my_sig.clone())];

    while let Some(res) = futs.next().await {
        match res {
            Ok((w_uuid, w_sig)) => {
                gathered.push((w_uuid, w_sig));
                if gathered.len() >= cfg.witness_threshold + 1 {
                    break;
                }
            }
            Err(e) => tracing::warn!("witness proposal failed: {}", e),
        }
    }

    // --------------------------------------------------------------
    //  seal the block
    // --------------------------------------------------------------
    Ok(Pending::Confirmed {
        block,
        sigs: vec![my_sig],
        confirmed_at: StdInstant::now(),
    })
}

fn sign_with_node_key(msg: &[u8], cfg: &SequencerConfig) -> Result<Vec<u8>> {
    // load Ed25519 private key (PEM) from disk
    let key_pem = std::fs::read(&cfg.grpc_key)
        .context("reading node private key for signing")?;
    let pkey = PKey::private_key_from_pem(&key_pem)
        .context("parsing node private key PEM")?;

    // for Ed25519: create a no-digest signer
    let mut signer =
        Signer::new_without_digest(&pkey).context("creating Ed25519 signer")?;
    signer.update(msg).context("feeding message to signer")?;
    let sig = signer
        .sign_to_vec()
        .context("finalising Ed25519 signature")?;
    Ok(sig)
}

fn hash_previous_root(header: &BlockHeader) -> [u8; 32] {
    // stub: in real code, hash the header to get prev_hash for next block
    hash_header(header)
}

// --------------------------------------------------------------
//  Sends proposed block header to witnesses
// --------------------------------------------------------------
pub async fn send_proposal(
    url: String,
    hdr: BlockHeader,
    sig: Vec<u8>,
) -> anyhow::Result<(String, Vec<u8>)> {
    let mut client = WitnessServiceClient::connect(url)
        .await
        .context("connecting to witness gRPC endpoint")?;

    let proposal = BlockProposal {
        header:    Some((&hdr).into()),  
        signature: sig.clone(),
    };

    let response = client
        .propose(Request::new(proposal))
        .await
        .context("witness.Propose RPC failed")?;

    let resp: ProposeResponse = response.into_inner();
    if !resp.ok {
        anyhow::bail!("witness rejected proposal: {}", resp.error);
    }

    Ok((resp.node_uuid, resp.signature))
}