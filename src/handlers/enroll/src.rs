use crate::config::{SequencerAppState};
use super::models::{EnrollReq, EnrollResp, NodeConfig};

use axum::{
    extract::{State, Json},
    http::StatusCode,
};
use serde_json::{Value, json};
use uuid::Uuid;
use base64::prelude::*;
use std::convert::TryFrom;
use openssl::{
    x509::{X509, X509Builder, X509NameBuilder},
    pkey::PKey,
    asn1::Asn1Time,
    hash::MessageDigest,
};

fn to_http_err<E: std::fmt::Display>(e: E) -> (StatusCode, Json<Value>) {
    (StatusCode::INTERNAL_SERVER_ERROR,
     Json(json!({ "error": e.to_string() })))
}

type EnrollResult = 
    Result<(StatusCode, Json<EnrollResp>), (StatusCode, Json<Value>)>;

pub async fn enroll_handler(
    State(state): State<SequencerAppState>,
    Json(req): Json<EnrollReq>,
) -> EnrollResult {
    if req.enroll_jwt != "let-me-in" { // stub-verify JWT
        return Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": "bad jwt" }))));
    }

    // TODO, REPLACE
    let node_uuid = Uuid::new_v4().to_string();
    let role_flag = "contributor".to_string();

    let pubkey_der = match BASE64_STANDARD.decode(&req.pubkey) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "pubkey not valid base64" })),
            ));
        }
    };

    let ca_cert_pem = std::fs::read(&state.cfg.ca_root)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))))?;
    let ca_key_pem = std::fs::read(&state.cfg.ca_key)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))))?;
    let ca_cert = X509::from_pem(&ca_cert_pem)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))))?;
    let ca_key = PKey::private_key_from_pem(&ca_key_pem)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() }))))?;

    let mut name_b = X509NameBuilder::new().unwrap();
    name_b.append_entry_by_text("CN", &node_uuid).unwrap();
    if let Some(hw) = &req.hw_id {
        name_b.append_entry_by_text("OU", hw).unwrap();
    }
    let name = name_b.build();

    let mut builder = X509Builder::new().map_err(to_http_err)?;
    builder.set_version(2).map_err(to_http_err)?;
    builder.set_subject_name(&name).map_err(to_http_err)?;
    builder.set_issuer_name(ca_cert.subject_name()).map_err(to_http_err)?;

    let not_before = Asn1Time::days_from_now(0).map_err(to_http_err)?;
    builder.set_not_before(not_before.as_ref()).map_err(to_http_err)?;
    let days: u32 = u32::try_from(state.cfg.enroll_ttl_days).map_err(to_http_err)?;
    let not_after = Asn1Time::days_from_now(days).map_err(to_http_err)?;
    builder.set_not_after(not_after.as_ref()).map_err(to_http_err)?;

    let pubkey = PKey::public_key_from_der(&pubkey_der).map_err(to_http_err)?;
    builder.set_pubkey(&pubkey).map_err(to_http_err)?;
    builder.sign(&ca_key, MessageDigest::null()).map_err(to_http_err)?;

    let node_cert_pem = builder.build().to_pem().map_err(to_http_err)?;
    let node_cert_str = String::from_utf8(node_cert_pem)
        .expect("PEM is valid utf8");

    let resp = EnrollResp {
        cert_pem:       node_cert_str,
        ca_pem:         String::from_utf8(ca_cert_pem).unwrap(),
        node_config:    NodeConfig {
            uuid:               node_uuid,
            role_flag:          role_flag,
            expires_at:         chrono::Utc::now().timestamp() + (state.cfg.enroll_ttl_days*86400) as i64,
        },
    };

    Ok((StatusCode::CREATED, Json(resp)))
}