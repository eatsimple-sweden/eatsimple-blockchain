use rustls_pemfile::{read_all, read_one, Item};
use rustls::{
    Certificate, PrivateKey, RootCertStore,
};
use anyhow::{bail, Context, Result};
use std::{
    fs::File,
    io::BufReader,
};

// reads a cert file and gives back all x509 certs in it (PEM → rustls::Certificate)
pub fn load_certs(path: &str) -> Result<Vec<Certificate>> {
    // open the cert file and buffer it
    let file = File::open(path)
        .with_context(|| format!("opening certificate file `{}`", path))?;
    let mut rd = BufReader::new(file);

    // parse all PEM blocks
    let items: Vec<Item> = read_all(&mut rd)
        .collect::<std::result::Result<_, _>>()
        .context("reading PEM items from cert file")?;

    // pick only X509 certs and convert to rustls certs
    let certs = items.into_iter().filter_map(|item| {
        if let Item::X509Certificate(der) = item {
            Some(Certificate(der.to_vec()))
        } else {
            None
        }
    }).collect();

    Ok(certs)
}

// load a pkcs8 private key from a PEM file (expect one key exactly)
pub fn load_key(path: &str) -> Result<PrivateKey> {
    let file = File::open(path)
        .with_context(|| format!("opening key file `{}`", path))?;
    let mut rd = BufReader::new(file);

    let mut keys = Vec::<Vec<u8>>::new();

    loop {
        match read_one(&mut rd).context("reading PEM block")? {
            Some(Item::Pkcs8Key(der)) => {
                keys.push(der.secret_pkcs8_der().to_vec());
            }
            Some(_) => continue, // skip other stuff
            None => break,
        }
    }

    if keys.len() != 1 {
        bail!("expected exactly one PKCS#8 key in `{}`", path);
    }
    Ok(PrivateKey(keys.remove(0)))
}

// load and add CA certs to a rustls RootCertStore from PEM
pub fn load_ca(path: &str) -> Result<RootCertStore> {
    let file = File::open(path)
        .with_context(|| format!("opening CA file `{}`", path))?;
    let mut rd = BufReader::new(file);

    let items: Vec<Item> = read_all(&mut rd)
        .collect::<std::result::Result<_, _>>()
        .context("reading PEM items from CA file")?;

    let mut store = RootCertStore::empty();
    for item in items {
        if let Item::X509Certificate(der) = item {
            store
                .add(&Certificate(der.to_vec()))
                .context("adding a CA certificate to the root store")?;
        }
    }
    Ok(store)
}