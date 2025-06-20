use crate::config::{SequencerAppState};
use super::models::{EnrollReq, EnrollClaims, EnrollResp, NodeConfig};

use axum::{
    extract::{State, Json},
    http::StatusCode,
};
use serde_json::{Value, json};
use uuid::Uuid;
use jsonwebtoken::{decode, DecodingKey, Validation};
use base64::prelude::*;
use std::convert::TryFrom;
use openssl::{
    x509::{X509, X509Builder, X509NameBuilder},
    pkey::{PKey, Id as PKeyId},
    asn1::Asn1Time,
    hash::MessageDigest,
};
use rand::RngCore;

fn to_http_err<E: std::fmt::Display>(e: E) -> (StatusCode, Json<Value>) {
    (StatusCode::INTERNAL_SERVER_ERROR,
     Json(json!({ "error": e.to_string() })))
}

type EnrollResult = Result<(StatusCode, Json<EnrollResp>), (StatusCode, Json<Value>)>;

pub async fn post_enroll_handler(
    State(state): State<SequencerAppState>,
    Json(req): Json<EnrollReq>,
) -> EnrollResult {
    let token_data = decode::<EnrollClaims>(
        &req.enroll_jwt,
        &DecodingKey::from_secret(state.cfg.enroll_jwt_secret.as_ref()),
        &Validation::default(),
    ).map_err(|e| {
        let body = Json(json!({ "error": format!("invalid token: {}", e) }));
        (StatusCode::UNAUTHORIZED, body)
    })?;
    let claims = token_data.claims;

    let node_uuid = Uuid::new_v4();
    let mut aes_key = [0u8; 32];
    let mut det_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut aes_key);
    rand::rngs::OsRng.fill_bytes(&mut det_key);
    let aes_key_b64 = BASE64_STANDARD.encode(&aes_key);
    let det_key_b64 = BASE64_STANDARD.encode(&det_key);

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
    name_b.append_entry_by_text("CN", &node_uuid.to_string()).unwrap();
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
    
    let ca_digest = match ca_key.id() {
        PKeyId::ED25519 => MessageDigest::null(),  // Ed25519 - no external hash
        _               => MessageDigest::sha256(),// ECDSA-P256, RSA, etc.
    };
    builder.sign(&ca_key, ca_digest).map_err(to_http_err)?;

    sqlx::query!(
        r#"
        INSERT INTO nodes
          (node_id, user_name, user_type, user_id, hw_id, role_flag,
           aes_key, det_key, pubkey, created_at, expires_at)
        VALUES
          ($1,$2,$3,$4,$5,$6,$7,$8,$9, now(), to_timestamp($10))
        "#,
        node_uuid,
        claims.name,
        claims.user_type,
        claims.sub,
        req.hw_id,
        claims.role_flag,
        &aes_key,
        &det_key,
        &pubkey_der,
        (chrono::Utc::now().timestamp() + (state.cfg.enroll_ttl_days*86400) as i64) as i64,
    ).execute(&state.db).await.map_err(to_http_err)?;

    let node_cert_pem = builder.build().to_pem().map_err(to_http_err)?;
    let node_cert_str = String::from_utf8(node_cert_pem)
        .expect("PEM is valid utf8");

    let resp = EnrollResp {
        cert_pem:       node_cert_str,
        ca_pem:         String::from_utf8(ca_cert_pem).unwrap(),
        aes_key_b64,
        det_key_b64,
        node_config:    NodeConfig {
            uuid:               node_uuid,
            role_flag:          claims.role_flag,
            expires_at:         chrono::Utc::now().timestamp() + (state.cfg.enroll_ttl_days*86400) as i64,
        },
    };

    Ok((StatusCode::CREATED, Json(resp)))
}