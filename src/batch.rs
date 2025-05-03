use crate::{
    block::{merkle_root, hash_header, Block, BlockHeader},
    config::SequencerConfig,
    pb::{
        TxRequest,
        witness_service_client::WitnessServiceClient,
        BlockProposal,
        ProposeResponse,
    },
    storage::persist_block,
};
use anyhow::{Result, Context};
use std::{
    sync::{Arc},
    collections::BTreeMap,
};
use tonic::Request;
use futures::{
    stream::FuturesUnordered,
    StreamExt,
};
use tokio::{
    sync::{mpsc, mpsc::Receiver},
    time::{self, Duration, Instant},
};
use openssl::{
    pkey::PKey,
    sign::Signer,
};
use tracing::{warn, debug, info_span, Instrument};
use byteorder::{ByteOrder, BigEndian};
use bincode::{
    serde::decode_from_slice,
    config::standard,
};

// frequency we check the buffer for flush conditions
const TICK_MS: u64 = 50;

pub async fn batch_loop(
    cfg: SequencerConfig,
    mut rx: Receiver<TxRequest>,
    block_db: sled::Db,
) -> anyhow::Result<()> {
    let cfg = Arc::new(cfg); // shared – cheap to clone

    // ----------------------------------------------------------
    //  init chain info
    // ----------------------------------------------------------
    let chain = block_db
        .open_tree("chain")
        .context("opening sled tree `chain`")?;

    let (mut next_height, mut prev_hash) = match chain.last()? {
        Some((key_bytes, val_bytes)) => {
            let height = BigEndian::read_u64(&key_bytes);
            let (blk, _) = decode_from_slice::<Block, _>(&val_bytes, standard())
                .context("decoding last block from sled")?;
            let h = hash_header(&blk.header);

            tracing::info!(
                tip_height=height,
                merkle_root=%hex::encode(blk.header.merkle_root),
                "loaded chain tip from sled"
            );
            (height, h)
        }
        None => {
            tracing::warn!("chain empty, defaulting to tip=0");
            (0, [0u8; 32])
        }
    };

    // ----------------------------------------------------------
    //  current building buffer
    // ----------------------------------------------------------
    let mut buffer:     Vec<TxRequest> = Vec::new();
    let mut started_at: Instant        = Instant::now();

    // ----------------------------------------------------------
    //  finished proposal tasks report here
    // ----------------------------------------------------------
    let (seal_tx, mut seal_rx) = mpsc::channel::<Sealed>(32);

    // ----------------------------------------------------------
    //  commit buffer – keeps Sealed blocks that arrived early
    // ----------------------------------------------------------
    let mut commit_q: BTreeMap<u64, Sealed> = BTreeMap::new();

    let should_flush = |buf: &[TxRequest], start: Instant, cfg: &SequencerConfig| {
        !buf.is_empty() && (                       // never flush an empty buffer
            buf.len() >= cfg.max_block_entries ||
            start.elapsed().as_millis() as u64 >= cfg.max_block_age_ms
        )
    };

    loop {
        tokio::select! {
            Some(tx) = rx.recv() => {                               // ingest task passed us a new Tx
                if buffer.is_empty() {
                    started_at = Instant::now();
                }
                buffer.push(tx);
            }

            _ = time::sleep(Duration::from_millis(TICK_MS)) => {}   // periodic tick – just falls through to flush check

            Some(sealed) = seal_rx.recv() => {                      // a proposal task finished (may be *any* height)
                let h = sealed.block.header.height;
                commit_q.insert(h, sealed);

                while let Some(sealed) = commit_q.remove(&(next_height + 1)) { // while a proposal task is running, no other task will ever be started for the same height
                    persist_block(&sealed, &block_db).await?;
                    next_height += 1;
                    prev_hash    = hash_header(&sealed.block.header);
                }
            }
        }

        if should_flush(&buffer, started_at, &cfg) { // decide whether to flush current buffer
            let txs   = std::mem::take(&mut buffer);
            let h_cur = next_height + 1;
            let p_hash = prev_hash;
            let cfg_cloned = cfg.clone();
            let seal_tx_cloned = seal_tx.clone();

            tracing::info!(
                height = h_cur,
                entries = txs.len(),
                "flushing txs into new block, spawning make_local_header",
            );

            tokio::spawn({
                let span = info_span!("seal_task", height = h_cur);
                async move {
                    let res = async {
                        let (block, my_sig) =
                            make_local_header(txs, h_cur, p_hash, &cfg_cloned)
                                .context("make_local_header")?;
            
                        let sigs =
                            collect_witness_sigs(block.header.clone(), my_sig, &cfg_cloned)
                                .await
                                .context("collect_witness_sigs")?;
            
                        seal_tx_cloned
                            .send(Sealed { block, sigs })
                            .await
                            .context("seal_tx send")?;
            
                        Ok::<_, anyhow::Error>(())
                    }
                    .instrument(span)
                    .await;
            
                    if let Err(e) = res {
                        warn!("seal task aborted: {e:#}");
                    } else {
                        debug!("seal task finished and queued for commit");
                    }
                }
            });

            started_at = Instant::now();
        }
    }
}

// Build header and our own sig – synchronous + fast
fn make_local_header(
    txs: Vec<TxRequest>,
    height: u64,
    prev_hash: [u8; 32],
    cfg: &SequencerConfig,
) -> anyhow::Result<(Block, Vec<u8>)> {
    let (root, _) = merkle_root(&txs);
    tracing::debug!(height, root = hex::encode(root), entries = txs.len(), "compute merkle root");

    let header = BlockHeader {
        height,
        prev_hash,
        merkle_root: root,
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
        entries: txs.len() as u32,
    };
    let block  = Block { header: header.clone(), txs };
    let my_sig = sign_with_node_key(&hash_header(&header), cfg)?;
    Ok((block, my_sig))
}

async fn collect_witness_sigs(
    header: BlockHeader,
    my_sig: Vec<u8>,
    cfg: &SequencerConfig,
) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    if cfg.witness_threshold <= 1 {
        tracing::info!(
            threshold = cfg.witness_threshold,
            "witness_threshold ≤ 1, skipping remote witnesses"
        );
        return Ok(vec![(cfg.sequencer_node_uuid.clone(), my_sig)]);
    }

    let mut futs = FuturesUnordered::new();
    for ep in &cfg.witness_endpoints {
        let hdr = header.clone();
        let sig = my_sig.clone();
        let ep  = ep.clone();
        futs.push(send_proposal(ep, hdr, sig));
    }

    let mut gathered = vec![(cfg.sequencer_node_uuid.clone(), my_sig)];
    while let Some(res) = futs.next().await {
        match res {
            Ok((uuid, sig)) => {
                gathered.push((uuid, sig));
                if gathered.len() >= cfg.witness_threshold + 1 {
                    return Ok(gathered);
                }
            }
            Err(e) => tracing::warn!("witness RPC failed: {e}"),
        }
    }
    anyhow::bail!("quorum not reached")
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

fn sign_with_node_key(msg: &[u8], cfg: &SequencerConfig) -> Result<Vec<u8>> {
    // load Ed25519 private key (PEM) from disk
    let key_pem = std::fs::read(&cfg.grpc_key)
        .context("reading node private key for signing")?;
    let pkey = PKey::private_key_from_pem(&key_pem)
        .context("parsing node private key PEM")?;

    let mut signer = Signer::new_without_digest(&pkey)
        .context("creating Ed25519 signer")?;

    let sig = signer
        .sign_oneshot_to_vec(msg)
        .context("Ed25519 one-shot sign")?;

    Ok(sig)
}

// what comes back from a proposal-task once it reaches quorum
pub struct Sealed {
    pub block: Block,                    // header + txs
    pub sigs:  Vec<(String, Vec<u8>)>,   // who signed what
}