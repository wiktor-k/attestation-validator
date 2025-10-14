use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader},
};

use x509_parser::{
    pem::Pem,
    prelude::{FromDer, X509Certificate},
};

pub fn check_signature(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
    let issuer_public_key = issuer.public_key();
    cert.verify_signature(Some(issuer_public_key)).is_ok()
}

fn main() -> testresult::TestResult {
    println!("Hello, world!");
    for path in std::fs::read_dir("./")? {
        let path = path?;
        if path.file_name().display().to_string().ends_with(".pem") {
            let buf = std::fs::read(path.path())?;
            for pem in Pem::iter_from_buffer(&buf) {
                let pem = pem?;
                let x509 = pem.parse_x509()?;
                println!("X509: {x509:?}");
            }
        }
    }

    let root = Pem::iter_from_reader(BufReader::new(File::open("yubihsm2-attest-ca-crt-pem")?))
        .next()
        .unwrap()?;
    let root = root.parse_x509()?;
    eprintln!("Root: {root:?}");

    let inter = Pem::iter_from_reader(BufReader::new(File::open("intermediate-pem")?))
        .next()
        .unwrap()?;
    let inter = inter.parse_x509()?;
    eprintln!("Inter: {inter:?}");
    assert!(check_signature(&inter, &root));

    let binding = std::fs::read("attestation-cert.cer")?;
    let device_att_cert = X509Certificate::from_der(&binding)?.1;
    eprintln!("Device: {device_att_cert:?}");
    assert!(check_signature(&device_att_cert, &inter));

    let att = Pem::iter_from_reader(BufReader::new(File::open("attestation-pem")?))
        .next()
        .unwrap()?;
    let att = att.parse_x509()?;
    eprintln!("Att: {att:?}");
    assert!(check_signature(&att, &device_att_cert));

    let ext = att.extensions_map()?;
    let mut keys: Vec<_> = ext.keys().collect();
    keys.sort_by(|left, right| left.to_string().cmp(&right.to_string()));
    // https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#certificate-extensions
    for name in keys {
        let value = ext.get(&name).unwrap();
        eprintln!("Name {name} value {:?}", value.value);
    }
    eprintln!("Pub key: {:?}", att.public_key());

    Ok(())
}
