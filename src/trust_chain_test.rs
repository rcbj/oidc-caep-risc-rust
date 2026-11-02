// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! tlsCa holds iya-sts's whole listener CA trust chain (leaf, TLS Issuing CA,
//! Intermediate, Root). These tests serve HTTPS from such a chain and check
//! that scripts/trust_chain.py (what scripts/configure_iya_sts.py calls) writes
//! all of it to the file tlsCa names, from GET /tls/server-certificate and from
//! the handshake when that is missing; that the library takes that file as its
//! trust store; and that trusting it is not trusting anything that names it:
//! the leaf alone anchors nothing, a leaf another CA signed is refused even
//! when the real CA certificates follow it, and the host name must match the
//! leaf's subjectAltName. The chains are made with the openssl command, which
//! the test image carries.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread;

use serde_json::json;

use crate::http::send;
use crate::resolve_config;

struct Chain {
    /// Leaf first, Root last: what iya-sts publishes and presents.
    pem: String,
    leaf: String,
    leaf_key: String,
    /// The three CA certificates, Issuing CA first.
    cas: String,
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("oidc-trust-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn openssl(dir: &Path, args: &[&str]) {
    let out = Command::new("openssl").args(args).current_dir(dir).output().expect("openssl");
    assert!(out.status.success(), "openssl {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

fn read(dir: &Path, name: &str) -> String {
    std::fs::read_to_string(dir.join(name)).unwrap()
}

fn ext(dir: &Path, san: &str) {
    std::fs::write(
        dir.join("ext.cnf"),
        format!(
            "[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n\
             [leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName={san}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"
        ),
    )
    .unwrap();
}

fn key(dir: &Path, name: &str) {
    openssl(dir, &["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", &format!("{name}.key")]);
}

fn root(dir: &Path, name: &str, cn: &str) {
    key(dir, name);
    openssl(dir, &[
        "req", "-x509", "-new", "-key", &format!("{name}.key"), "-subj", &format!("/CN={cn}"), "-days", "2",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", &format!("{name}.crt"),
    ]);
}

fn issue(dir: &Path, name: &str, cn: &str, parent: &str, section: &str, serial: &str) {
    key(dir, name);
    openssl(dir, &["req", "-new", "-key", &format!("{name}.key"), "-subj", &format!("/CN={cn}"), "-out", &format!("{name}.csr")]);
    openssl(dir, &[
        "x509", "-req", "-in", &format!("{name}.csr"), "-CA", &format!("{parent}.crt"), "-CAkey", &format!("{parent}.key"),
        "-set_serial", serial, "-days", "2", "-extfile", "ext.cnf", "-extensions", section, "-out", &format!("{name}.crt"),
    ]);
}

/// Root -> Intermediate -> TLS Issuing CA -> leaf with subjectAltName `san`,
/// all P-256, in `dir`.
fn chain(dir: &Path, san: &str) -> Chain {
    ext(dir, san);
    root(dir, "root", "test Root CA");
    issue(dir, "intermediate", "test Intermediate CA", "root", "ca", "2");
    issue(dir, "issuing", "test TLS Issuing CA", "intermediate", "ca", "3");
    issue(dir, "leaf", "127.0.0.1", "issuing", "leaf", "4");
    let leaf = read(dir, "leaf.crt");
    let cas = format!("{}{}{}", read(dir, "issuing.crt"), read(dir, "intermediate.crt"), read(dir, "root.crt"));
    Chain { pem: format!("{leaf}{cas}"), leaf, leaf_key: read(dir, "leaf.key"), cas }
}

/// HTTPS on 127.0.0.1 presenting `presented` (leaf first) with `leaf_key`.
/// `published` decides whether GET /tls/server-certificate answers
/// `presented` or 404. GET /metadata answers a small JSON document.
fn serve(presented: &str, leaf_key: &str, published: bool) -> u16 {
    let identity = native_tls::Identity::from_pkcs8(presented.as_bytes(), leaf_key.as_bytes()).expect("identity");
    let acceptor = Arc::new(native_tls::TlsAcceptor::new(identity).expect("acceptor"));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let chain_pem = presented.to_string();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let acceptor = acceptor.clone();
            let chain_pem = chain_pem.clone();
            thread::spawn(move || {
                let Ok(mut tls) = acceptor.accept(stream) else { return };
                let mut request = Vec::new();
                let mut buffer = [0u8; 2048];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut buffer) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buffer[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&request);
                let path = text.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, body) = if path == "/tls/server-certificate" && published {
                    ("200 OK", chain_pem)
                } else if path == "/metadata" {
                    ("200 OK", "{\"issuer\":\"test\"}".to_string())
                } else {
                    ("404 Not Found", String::new())
                };
                let _ = write!(tls, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = tls.flush();
                let _ = tls.shutdown();
            });
        }
    });
    port
}

fn blocks(pem: &str) -> usize {
    pem.matches("-----BEGIN CERTIFICATE-----").count()
}

fn der_bodies(pem: &str) -> Vec<String> {
    pem.split("-----END CERTIFICATE-----")
        .filter_map(|block| block.split("-----BEGIN CERTIFICATE-----").nth(1))
        .map(|body| body.chars().filter(|ch| !ch.is_whitespace()).collect())
        .collect()
}

/// The registrar's save step, run the way the install script runs it: the file
/// tlsCa names in an oidc.json, relative to that file's directory.
fn save_with_registrar(dir: &Path, port: u16) -> String {
    let config = dir.join("oidc.json");
    let doc = json!({
        "metadataUrl": format!("https://127.0.0.1:{port}/.well-known/openid-configuration"),
        "client_id": "oidc-caep-risc-demo",
        "clientSecret": "file:generated/client-secret",
        "tlsCa": "generated/idp-ca.pem",
    });
    std::fs::write(&config, doc.to_string()).unwrap();
    let script = format!("{}/scripts/trust_chain.py", env!("CARGO_MANIFEST_DIR"));
    let out = Command::new("python3")
        .args([script.as_str(), "--config", config.to_str().unwrap()])
        .env_remove("OIDC_CONFIG")
        .output()
        .expect("python3");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success() && stdout.contains("4 certificate(s)"), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("trust anchor CN=test Root CA"), "{stdout}");
    assert!(stdout.contains("sha256 "), "{stdout}");
    read(&dir.join("generated"), "idp-ca.pem")
}

/// tlsCa as the demo's configuration names it, read by the library.
fn tls_ca_of(dir: &Path, port: u16) -> String {
    let doc = json!({
        "clientId": "oidc-caep-risc-demo",
        "clientSecret": "test-secret",
        "redirectUri": "http://localhost:3000/callback",
        "metadataUrl": format!("https://127.0.0.1:{port}/.well-known/openid-configuration"),
        "tlsCa": "file:generated/idp-ca.pem",
    });
    let resolved = resolve_config(doc.as_object().unwrap(), &dir.to_string_lossy()).unwrap_or_else(|err| panic!("{err}"));
    resolved.get("tlsCa").and_then(|v| v.as_str()).expect("tlsCa").to_string()
}

fn get(url: &str, ca: &str) -> Result<u16, String> {
    send(url, "GET", &[], None, Some(ca), "test").map(|answer| answer.status).map_err(|err| err.to_string())
}

fn refused_by_verification(result: Result<u16, String>) {
    let err = result.expect_err("the connection should have been refused");
    assert!(err.to_ascii_lowercase().contains("certificate") || err.to_ascii_lowercase().contains("verif"), "{err}");
}

#[test]
fn the_registrar_writes_the_published_chain_to_tls_ca() {
    let dir = scratch("published");
    let chain = chain(&dir, "IP:127.0.0.1,DNS:localhost");
    let port = serve(&chain.pem, &chain.leaf_key, true);
    let saved = save_with_registrar(&dir, port);
    assert_eq!(blocks(&saved), 4);
    assert_eq!(saved, chain.pem);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_registrar_falls_back_to_the_handshake_chain() {
    let dir = scratch("handshake");
    let chain = chain(&dir, "IP:127.0.0.1,DNS:localhost");
    let port = serve(&chain.pem, &chain.leaf_key, false);
    let saved = save_with_registrar(&dir, port);
    assert_eq!(blocks(&saved), 4);
    assert_eq!(der_bodies(&saved), der_bodies(&chain.pem));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_library_trusts_the_whole_chain_in_tls_ca() {
    let dir = scratch("library");
    let chain = chain(&dir, "IP:127.0.0.1,DNS:localhost");
    let port = serve(&chain.pem, &chain.leaf_key, true);
    std::fs::create_dir_all(dir.join("generated")).unwrap();
    std::fs::write(dir.join("generated").join("idp-ca.pem"), &chain.pem).unwrap();
    let ca = tls_ca_of(&dir, port);
    assert_eq!(blocks(&ca), 4);
    // The IP literal against the IP SAN, and a DNS name against the DNS SAN.
    assert_eq!(get(&format!("https://127.0.0.1:{port}/metadata"), &ca), Ok(200));
    assert_eq!(get(&format!("https://localhost:{port}/metadata"), &ca), Ok(200));

    // The whole file has to be read: its first block alone is the leaf, which
    // anchors nothing, and the connection is refused.
    std::fs::write(dir.join("generated").join("idp-ca.pem"), &chain.leaf).unwrap();
    let leaf_only = tls_ca_of(&dir, port);
    refused_by_verification(get(&format!("https://127.0.0.1:{port}/metadata"), &leaf_only));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_library_checks_the_host_name_against_the_leaf() {
    let dir = scratch("hostname");
    // The right chain for a different name: the leaf names only sts.example.com.
    let chain = chain(&dir, "DNS:sts.example.com");
    let port = serve(&chain.pem, &chain.leaf_key, true);
    refused_by_verification(get(&format!("https://127.0.0.1:{port}/metadata"), &chain.pem));
    refused_by_verification(get(&format!("https://localhost:{port}/metadata"), &chain.pem));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_foreign_leaf_followed_by_the_real_ca_certificates_is_refused() {
    let dir = scratch("forged");
    let chain = chain(&dir, "IP:127.0.0.1,DNS:localhost");
    // Another CA signs a leaf for the same names; the server sends it followed
    // by the real (public) CA certificates the file trusts.
    root(&dir, "other", "other Root CA");
    issue(&dir, "forged", "127.0.0.1", "other", "leaf", "9");
    let presented = format!("{}{}", read(&dir, "forged.crt"), chain.cas);
    let port = serve(&presented, &read(&dir, "forged.key"), true);
    refused_by_verification(get(&format!("https://127.0.0.1:{port}/metadata"), &chain.pem));
    let _ = std::fs::remove_dir_all(&dir);
}
