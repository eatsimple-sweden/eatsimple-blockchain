pub mod block;          // BlockHeader, Block type, Merkle tree builderpub mod config;
pub mod config;         // loads writer.toml or witness.toml
pub mod crypto;         // hashing (blake3), signing (blst or ed25519)
pub mod pb {
    tonic::include_proto!("eatsimple_blockchain");
}
pub mod grpc;           // common gRPC service definitions (tonic/prost stubs)
pub mod outbox;         // Postgres outbox helper
pub mod storage;        // RocksDB or sled adapters
pub mod utils;          // misc helpers (timestamps, errors, logging)
pub mod mode;           // per‑mode orchestration logic
pub mod batch;          // collecting incoming transactions, batching/merkle roots/gRPC, persistance etc
pub mod handlers;       // handlers for Axum API