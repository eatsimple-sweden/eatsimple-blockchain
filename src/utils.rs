use rustls_pemfile::{read_all, read_one, Item, certs};
use anyhow::{bail, Context, Result};
use std::{
    fs::File,
    io::BufReader,
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};

// reads a cert file and gives back all x509 certs in it (PEM -> rustls::Certificate)
pub fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .with_context(|| format!("opening certificate file `{}`", path))?;
    let mut rd = BufReader::new(file);

    let raw_certs = certs(&mut rd)
        .collect::<std::result::Result<_, _>>()
        .context("reading certificates from PEM")?;

    // 3) done
    Ok(raw_certs)
}

// load a pkcs8 private key from a PEM file (expect one key exactly)
pub fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let mut rd = BufReader::new(File::open(path)
        .with_context(|| format!("opening key file `{}`", path))?);

    loop {
        match read_one(&mut rd)
            .context("reading PEM block")?
        {
            Some(Item::Pkcs8Key(key)) => return Ok(PrivateKeyDer::from(key)),
            Some(Item::Sec1Key(key))  => return Ok(PrivateKeyDer::from(key)),
            Some(_)                   => continue,
            None                      => break,
        }
    }
    anyhow::bail!("no private key found in `{}`", path);
}
// load and add CA certs to a rustls RootCertStore from PEM
pub fn load_ca(path: &str) -> Result<RootCertStore> {
    let mut rd = BufReader::new(File::open(path)
        .with_context(|| format!("opening CA file `{}`", path))?);

    let mut store = RootCertStore::empty();
    loop {
        match read_one(&mut rd)
            .context("reading PEM block")?
        {
            Some(Item::X509Certificate(der)) => {
                store.add_parsable_certificates(std::iter::once(CertificateDer::from(der)));
            }
            Some(_) => continue,
            None    => break,
        }
    }
    Ok(store)
}

pub fn json_to_fr(v: &serde_json::Value) -> anyhow::Result<ark_bn254::Fr> {
    use ark_ff::PrimeField;
    let s = match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b)   => b.to_string(),
        other                        => serde_json::to_string(other)?,
    };
    
    Ok(ark_bn254::Fr::from_le_bytes_mod_order(s.as_bytes()))
}
