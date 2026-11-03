// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! Issue #18: DPoP, acr, PAR required by the provider, the ID token algorithm
//! allow-list (and every algorithm it may name verifying), typ and at_hash, the same
//! defaults on every way of creating a client, and the per-session token cache.

use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::Mac;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::b64::b64url_encode;
use crate::idtoken::hash_claim;
use crate::suite::{ath_of, deliver, form, json_res, keys, manual, query_of, read_proof, read_req, start_transmitter, write_res, Req};
use crate::value::JsonMap;
use crate::{
    resolve_config, verify_compact_jws, AuthorizeOptions, Event, Login, MemorySessionStore, ReceiverOptions, RelyingParty, SessionStore, SignalsReceiver, Transaction,
};

const CLIENT: &str = "oidc-caep-risc-demo";
const SECRET: &str = "test-secret-that-is-long-enough-for-hmac-keys";

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

// ---- signing keys for every algorithm --------------------------------------------

struct AlgKeys {
    p256: p256::ecdsa::SigningKey,
    p384: p384::ecdsa::SigningKey,
    p521: p521::ecdsa::SigningKey,
    ed: ed25519_dalek::SigningKey,
    jwks: Vec<Value>,
}

fn ec_jwk(kid: &str, crv: &str, point: &[u8], size: usize) -> Value {
    json!({"kty": "EC", "crv": crv, "kid": kid, "use": "sig", "x": b64url_encode(&point[1..1 + size]), "y": b64url_encode(&point[1 + size..])})
}

fn alg_keys() -> &'static AlgKeys {
    static KEYS: OnceLock<AlgKeys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut rng = rand::rngs::OsRng;
        let p256 = p256::ecdsa::SigningKey::random(&mut rng);
        let p384 = p384::ecdsa::SigningKey::random(&mut rng);
        let p521 = p521::ecdsa::SigningKey::random(&mut rng);
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut seed);
        let ed = ed25519_dalek::SigningKey::from_bytes(&seed);
        let rsa = &keys().provider;
        let jwks = vec![
            json!({"kty": "RSA", "kid": "rsa", "use": "sig", "n": b64url_encode(&rsa.n().to_bytes_be()), "e": b64url_encode(&rsa.e().to_bytes_be())}),
            ec_jwk("p256", "P-256", p256.verifying_key().to_encoded_point(false).as_bytes(), 32),
            ec_jwk("p384", "P-384", p384.verifying_key().to_encoded_point(false).as_bytes(), 48),
            ec_jwk("p521", "P-521", p521::ecdsa::VerifyingKey::from(&p521).to_encoded_point(false).as_bytes(), 66),
            json!({"kty": "OKP", "crv": "Ed25519", "kid": "ed", "use": "sig", "x": b64url_encode(ed.verifying_key().as_bytes())}),
        ];
        AlgKeys { p256, p384, p521, ed, jwks }
    })
}

fn kid_for(alg: &str) -> &'static str {
    match alg {
        "ES256" => "p256",
        "ES384" => "p384",
        "ES512" => "p521",
        "EdDSA" => "ed",
        _ => "rsa",
    }
}

fn sign_raw(alg: &str, input: &[u8]) -> Vec<u8> {
    let k = alg_keys();
    let rsa = keys().provider.clone();
    let mut rng = rand::thread_rng();
    match alg {
        "RS256" => rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa).sign_with_rng(&mut rng, input).to_vec(),
        "RS384" => rsa::pkcs1v15::SigningKey::<Sha384>::new(rsa).sign_with_rng(&mut rng, input).to_vec(),
        "RS512" => rsa::pkcs1v15::SigningKey::<Sha512>::new(rsa).sign_with_rng(&mut rng, input).to_vec(),
        "PS256" => rsa::pss::SigningKey::<Sha256>::new(rsa).sign_with_rng(&mut rng, input).to_vec(),
        "PS384" => rsa::pss::SigningKey::<Sha384>::new(rsa).sign_with_rng(&mut rng, input).to_vec(),
        "PS512" => rsa::pss::SigningKey::<Sha512>::new(rsa).sign_with_rng(&mut rng, input).to_vec(),
        "ES256" => {
            let sig: p256::ecdsa::Signature = k.p256.sign(input);
            sig.to_bytes().to_vec()
        }
        "ES384" => {
            let sig: p384::ecdsa::Signature = k.p384.sign(input);
            sig.to_bytes().to_vec()
        }
        "ES512" => {
            let sig: p521::ecdsa::Signature = k.p521.sign(input);
            sig.to_bytes().to_vec()
        }
        "EdDSA" => ed25519_dalek::Signer::sign(&k.ed, input).to_bytes().to_vec(),
        "HS256" => {
            let mut mac = hmac::Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
            mac.update(input);
            mac.finalize().into_bytes().to_vec()
        }
        other => panic!("no test key for {other}"),
    }
}

fn sign_jwt(alg: &str, typ: Option<&str>, payload: &Value) -> String {
    let mut header = json!({"alg": alg, "kid": kid_for(alg)});
    if let Some(typ) = typ {
        header["typ"] = json!(typ);
    }
    let signing = format!("{}.{}", b64url_encode(&serde_json::to_vec(&header).unwrap()), b64url_encode(&serde_json::to_vec(payload).unwrap()));
    let sig = sign_raw(alg, signing.as_bytes());
    format!("{signing}.{}", URL_SAFE_NO_PAD.encode(sig))
}

// ---- a configurable stub provider -------------------------------------------------

#[derive(Clone)]
struct OpCfg {
    advertised: Vec<String>,
    dpop_algs: Option<Vec<String>>,
    par: bool,
    require_par: bool,
    sign_alg: String,
    typ: Option<String>,
    at_hash: bool,
    acr: Option<String>,
    iat_offset: i64,
    expires_in: i64,
    nonce_as: bool,
    nonce_rs: bool,
    nonce_never_satisfied: bool,
    token_type: Option<String>,
    fail_refresh: bool,
}

impl Default for OpCfg {
    fn default() -> Self {
        Self {
            advertised: vec!["RS256".into()],
            dpop_algs: None,
            par: false,
            require_par: false,
            sign_alg: "RS256".into(),
            typ: Some("JWT".into()),
            at_hash: true,
            acr: None,
            iat_offset: 0,
            expires_in: 300,
            nonce_as: false,
            nonce_rs: false,
            nonce_never_satisfied: false,
            token_type: None,
            fail_refresh: false,
        }
    }
}

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    body: HashMap<String, String>,
    query: HashMap<String, String>,
    authorization: String,
    proof: Option<Value>,
    proof_jkt: Option<String>,
}

struct Op {
    url: String,
    cfg: Mutex<OpCfg>,
    codes: Mutex<HashMap<String, HashMap<String, String>>>,
    refresh: Mutex<HashMap<String, HashMap<String, String>>>,
    access: Mutex<HashMap<String, (Value, String)>>,
    pushed: Mutex<HashMap<String, HashMap<String, String>>>,
    seen: Mutex<Vec<Seen>>,
    nonce_refusals: Mutex<i32>,
    token_calls: Mutex<i32>,
}

const AS_NONCE: &str = "as-nonce-1";
const RS_NONCE: &str = "rs-nonce-1";

fn start_op(cfg: OpCfg) -> &'static Op {
    // Make every key before the stub answers: generating them inside a request (an RSA
    // and a P-521 key in a debug build) can outlast the client's HTTP timeout on a busy machine.
    alg_keys();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let op: &'static Op = Box::leak(Box::new(Op {
        url: format!("http://127.0.0.1:{port}"),
        cfg: Mutex::new(cfg),
        codes: Mutex::new(HashMap::new()),
        refresh: Mutex::new(HashMap::new()),
        access: Mutex::new(HashMap::new()),
        pushed: Mutex::new(HashMap::new()),
        seen: Mutex::new(Vec::new()),
        nonce_refusals: Mutex::new(0),
        token_calls: Mutex::new(0),
    }));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            if let Some(req) = read_req(&mut stream) {
                let (status, headers, body) = op_handle(op, &req);
                let _ = write_res(&mut stream, status, &headers, &body);
            }
        }
    });
    op
}

fn op_metadata(op: &Op) -> Value {
    let cfg = op.cfg.lock().unwrap().clone();
    let mut doc = json!({
        "issuer": op.url,
        "authorization_endpoint": format!("{}/authorize", op.url),
        "token_endpoint": format!("{}/token", op.url),
        "jwks_uri": format!("{}/jwks", op.url),
        "userinfo_endpoint": format!("{}/userinfo", op.url),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": cfg.advertised,
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": true
    });
    if cfg.par {
        doc["pushed_authorization_request_endpoint"] = json!(format!("{}/par", op.url));
    }
    if cfg.require_par {
        doc["require_pushed_authorization_requests"] = json!(true);
    }
    if let Some(algs) = cfg.dpop_algs {
        doc["dpop_signing_alg_values_supported"] = json!(algs);
    }
    doc
}

fn client_ok(req: &Req) -> bool {
    let Some(token) = req.headers.get("authorization").and_then(|h| h.strip_prefix("Basic ")) else {
        return false;
    };
    STANDARD.decode(token).map(|raw| String::from_utf8_lossy(&raw) == format!("{CLIENT}:{SECRET}")).unwrap_or(false)
}

fn op_handle(op: &Op, req: &Req) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let cfg = op.cfg.lock().unwrap().clone();
    let raw_proof = req.headers.get("dpop").cloned();
    let proof = raw_proof.as_deref().and_then(read_proof);
    op.seen.lock().unwrap().push(Seen {
        method: req.method.clone(),
        path: req.path.clone(),
        body: form(&req.body),
        query: req.query.clone(),
        authorization: req.headers.get("authorization").cloned().unwrap_or_default(),
        proof: proof.as_ref().map(|p| p.claims.clone()),
        proof_jkt: proof.as_ref().map(|p| p.jkt.clone()),
    });
    if raw_proof.is_some() && proof.is_none() {
        return json_res(400, json!({"error": "invalid_dpop_proof"}));
    }
    if let Some(proof) = &proof {
        let htu = format!("{}{}", op.url, req.path);
        if proof.claims["htu"].as_str() != Some(htu.as_str()) || proof.claims["htm"].as_str() != Some(req.method.as_str()) {
            return json_res(400, json!({"error": "invalid_dpop_proof", "error_description": "htu or htm"}));
        }
    }
    match req.path.as_str() {
        "/.well-known/openid-configuration" => json_res(200, op_metadata(op)),
        "/jwks" => json_res(200, json!({"keys": alg_keys().jwks})),
        "/par" | "/token" if req.method == "POST" => {
            if !client_ok(req) {
                return json_res(401, json!({"error": "invalid_client"}));
            }
            if let Some(proof) = &proof {
                if proof.claims.get("ath").is_some() {
                    return json_res(400, json!({"error": "invalid_dpop_proof", "error_description": "ath on a token request"}));
                }
                if cfg.nonce_as && proof.claims["nonce"].as_str() != Some(AS_NONCE) {
                    *op.nonce_refusals.lock().unwrap() += 1;
                    return (400, vec![("Content-Type".into(), "application/json".into()), ("DPoP-Nonce".into(), AS_NONCE.into())], serde_json::to_vec(&json!({"error": "use_dpop_nonce"})).unwrap());
                }
            }
            let jkt = proof.as_ref().map(|p| p.jkt.clone()).unwrap_or_default();
            if req.path == "/par" {
                let mut values = form(&req.body);
                values.insert("__proof_jkt".into(), jkt);
                let request_uri = format!("urn:par:{}", now() + rand::random::<u32>() as i64);
                op.pushed.lock().unwrap().insert(request_uri.clone(), values);
                return json_res(201, json!({"request_uri": request_uri, "expires_in": 60}));
            }
            *op.token_calls.lock().unwrap() += 1;
            op_token(op, &cfg, req, &jkt)
        }
        "/authorize" => {
            let mut params = req.query.clone();
            if let Some(uri) = params.get("request_uri").cloned() {
                let Some(got) = op.pushed.lock().unwrap().get(&uri).cloned() else {
                    return json_res(400, json!({"error": "invalid_request"}));
                };
                params = got;
            } else if cfg.require_par {
                return json_res(400, json!({"error": "invalid_request", "error_description": "PAR is required"}));
            }
            let code = format!("code-{}", rand::random::<u64>());
            let mut row = HashMap::new();
            for name in ["nonce", "redirect_uri", "code_challenge", "dpop_jkt", "acr_values"] {
                row.insert(name.to_string(), params.get(name).cloned().unwrap_or_default());
            }
            op.codes.lock().unwrap().insert(code.clone(), row);
            let location = format!("{}?code={code}&state={}&iss={}", params.get("redirect_uri").cloned().unwrap_or_default(), params.get("state").cloned().unwrap_or_default(), op.url);
            (302, vec![("Location".into(), location)], Vec::new())
        }
        "/userinfo" => {
            let auth = req.headers.get("authorization").cloned().unwrap_or_default();
            let (scheme, token) = auth.split_once(' ').unwrap_or(("", ""));
            let Some((claims, bound)) = op.access.lock().unwrap().get(token).cloned() else {
                return json_res(401, json!({"error": "invalid_token"}));
            };
            if bound.is_empty() {
                return if scheme == "Bearer" { json_res(200, claims) } else { json_res(401, json!({"error": "invalid_token"})) };
            }
            let ok = scheme == "DPoP" && proof.as_ref().is_some_and(|p| p.jkt == bound && p.claims["ath"].as_str() == Some(ath_of(token).as_str()));
            if !ok {
                return (401, vec![("WWW-Authenticate".into(), "DPoP error=\"invalid_token\"".into())], Vec::new());
            }
            if cfg.nonce_never_satisfied {
                return (401, vec![("WWW-Authenticate".into(), "DPoP error=\"use_dpop_nonce\"".into()), ("DPoP-Nonce".into(), format!("n-{}", rand::random::<u32>()))], Vec::new());
            }
            if cfg.nonce_rs && proof.as_ref().and_then(|p| p.claims["nonce"].as_str().map(str::to_string)).as_deref() != Some(RS_NONCE) {
                *op.nonce_refusals.lock().unwrap() += 1;
                return (401, vec![("WWW-Authenticate".into(), "DPoP error=\"use_dpop_nonce\", error_description=\"nonce\"".into()), ("DPoP-Nonce".into(), RS_NONCE.into())], Vec::new());
            }
            json_res(200, claims)
        }
        _ => json_res(404, json!({"error": "not_found"})),
    }
}

fn op_token(op: &Op, cfg: &OpCfg, req: &Req, jkt: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let params = form(&req.body);
    let token_type = cfg.token_type.clone().unwrap_or_else(|| if jkt.is_empty() { "Bearer".into() } else { "DPoP".into() });
    match params.get("grant_type").map(String::as_str) {
        Some("client_credentials") => {
            op.access.lock().unwrap().insert("app-token".into(), (json!({"sub": CLIENT}), jkt.to_string()));
            json_res(200, json!({"access_token": "app-token", "token_type": token_type, "expires_in": 300}))
        }
        Some("refresh_token") => {
            if cfg.fail_refresh {
                return json_res(400, json!({"error": "invalid_grant"}));
            }
            let Some(row) = op.refresh.lock().unwrap().remove(params.get("refresh_token").map(String::as_str).unwrap_or("")) else {
                return json_res(400, json!({"error": "invalid_grant"}));
            };
            let mut row = row;
            row.insert("nonce".into(), String::new());
            json_res(200, mint(op, cfg, &row, jkt, &token_type))
        }
        Some("authorization_code") => {
            let Some(row) = op.codes.lock().unwrap().remove(params.get("code").map(String::as_str).unwrap_or("")) else {
                return json_res(400, json!({"error": "invalid_grant"}));
            };
            if params.get("redirect_uri") != row.get("redirect_uri") {
                return json_res(400, json!({"error": "invalid_grant"}));
            }
            let verifier = params.get("code_verifier").cloned().unwrap_or_default();
            if URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) != row["code_challenge"] {
                return json_res(400, json!({"error": "invalid_grant", "error_description": "pkce"}));
            }
            let wanted = row.get("dpop_jkt").cloned().unwrap_or_default();
            if !wanted.is_empty() && wanted != jkt {
                return json_res(400, json!({"error": "invalid_dpop_proof", "error_description": "dpop_jkt"}));
            }
            json_res(200, mint(op, cfg, &row, jkt, &token_type))
        }
        _ => json_res(400, json!({"error": "unsupported_grant_type"})),
    }
}

fn mint(op: &Op, cfg: &OpCfg, row: &HashMap<String, String>, jkt: &str, token_type: &str) -> Value {
    let access = format!("at-{}", rand::random::<u64>());
    let refresh = format!("rt-{}", rand::random::<u64>());
    let mut payload = json!({
        "iss": op.url, "sub": "user-1", "aud": CLIENT, "exp": now() + 300, "iat": now() + cfg.iat_offset,
        "email": "user-1@example.com", "sid": "sid-1"
    });
    if !row.get("nonce").map(String::is_empty).unwrap_or(true) {
        payload["nonce"] = json!(row["nonce"]);
    }
    if cfg.at_hash {
        payload["at_hash"] = json!(hash_claim(&access, &cfg.sign_alg));
    }
    if let Some(acr) = &cfg.acr {
        payload["acr"] = json!(acr);
    }
    let id_token = sign_jwt(&cfg.sign_alg, cfg.typ.as_deref(), &payload);
    op.access.lock().unwrap().insert(access.clone(), (payload, jkt.to_string()));
    op.refresh.lock().unwrap().insert(refresh.clone(), row.clone());
    json!({"access_token": access, "token_type": token_type, "expires_in": cfg.expires_in, "refresh_token": refresh, "id_token": id_token})
}

// ---- helpers ------------------------------------------------------------------------

fn base(op: &Op, over: Value) -> JsonMap {
    let mut doc = json!({
        "metadataUrl": format!("{}/.well-known/openid-configuration", op.url),
        "clientId": CLIENT,
        "clientSecret": SECRET,
        "tokenEndpointAuthMethod": "client_secret_basic",
        "redirectUri": "http://127.0.0.1/callback",
        "allowInsecure": true
    });
    for (k, v) in over.as_object().unwrap() {
        if v.is_null() {
            doc.as_object_mut().unwrap().remove(k);
        } else {
            doc[k] = v.clone();
        }
    }
    doc.as_object().cloned().unwrap()
}

fn rp_for(op: &Op, over: Value) -> RelyingParty {
    RelyingParty::create(base(op, over)).unwrap()
}

fn browse(rp: &RelyingParty, opts: AuthorizeOptions) -> (Transaction, HashMap<String, String>) {
    let txn = rp.authorize_options(opts).unwrap();
    let (_, location) = manual(&txn.url);
    assert!(!location.is_empty(), "the provider did not redirect: {}", txn.url);
    (txn, query_of(&location))
}

fn sign_in(rp: &RelyingParty) -> Result<Login, crate::OidcError> {
    let (txn, query) = browse(rp, AuthorizeOptions::default());
    rp.complete(&query, &txn)
}

fn seen(op: &Op, path: &str) -> Vec<Seen> {
    op.seen.lock().unwrap().iter().filter(|s| s.path == path).cloned().collect()
}

fn last(op: &Op, path: &str) -> Seen {
    seen(op, path).pop().unwrap_or_else(|| panic!("no request to {path}"))
}

fn dpop_cfg() -> OpCfg {
    OpCfg { dpop_algs: Some(vec!["ES256".into(), "RS256".into()]), ..OpCfg::default() }
}

// ---- 1. DPoP ------------------------------------------------------------------------

#[test]
fn dpop_auto_binds_every_token_and_proves_every_request() {
    let op = start_op(dpop_cfg());
    let rp = rp_for(op, json!({}));
    assert!(rp.uses_dpop());
    let jkt = rp.dpop_jkt().unwrap();
    let (txn, query) = browse(&rp, AuthorizeOptions::default());
    assert_eq!(query_of(&txn.url).get("dpop_jkt"), Some(&jkt), "dpop_jkt on the authorization request");
    let login = rp.complete(&query, &txn).unwrap();
    assert_eq!(login.token_type, "DPoP");
    let token = last(op, "/token");
    let claims = token.proof.expect("the code exchange carries a proof");
    assert_eq!(token.proof_jkt.as_deref(), Some(jkt.as_str()));
    assert_eq!(claims["htm"], "POST");
    assert_eq!(claims["htu"], format!("{}/token", op.url));
    assert!(claims.get("ath").is_none());
    assert!(claims["jti"].as_str().is_some_and(|j| !j.is_empty()));
    let iat = claims["iat"].as_i64().unwrap();
    assert!(iat <= now() && iat > now() - 120, "iat is the time the proof was made");
    // UserInfo: DPoP scheme, a proof with ath, and the htu without the query.
    let info = rp.userinfo(&login.access_token, &login.token_type, &login.subject).unwrap();
    assert_eq!(info["sub"], "user-1");
    let call = last(op, "/userinfo");
    assert_eq!(call.authorization, format!("DPoP {}", login.access_token));
    assert_eq!(call.method, "GET");
    let proof = call.proof.unwrap();
    assert_eq!(proof["ath"], ath_of(&login.access_token));
    assert_eq!(proof["htm"], "GET");
    assert_eq!(proof["htu"], format!("{}/userinfo", op.url));
    // Refresh and client credentials carry proofs too.
    let refreshed = rp.refresh(&login.refresh_token, "", Some(&login)).unwrap();
    assert_eq!(refreshed.token_type, "DPoP");
    assert!(last(op, "/token").proof.is_some());
    assert_eq!(last(op, "/token").body["grant_type"], "refresh_token");
    let cc = rp.client_credentials("ssf.manage").unwrap();
    assert_eq!(cc.token_type, "DPoP");
    let call = last(op, "/token");
    assert_eq!(call.body["grant_type"], "client_credentials");
    assert!(call.proof.is_some());
    // Each proof is fresh.
    let jtis: Vec<String> = op.seen.lock().unwrap().iter().filter_map(|s| s.proof.as_ref().map(|p| p["jti"].as_str().unwrap().to_string())).collect();
    let mut unique = jtis.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), jtis.len());
}

#[test]
fn dpop_with_par_proves_the_push_and_sends_dpop_jkt_in_its_body() {
    let op = start_op(OpCfg { par: true, ..dpop_cfg() });
    let rp = rp_for(op, json!({}));
    let (txn, query) = browse(&rp, AuthorizeOptions::default());
    assert!(txn.url.contains("request_uri="));
    assert!(!txn.url.contains("dpop_jkt"));
    let front = last(op, "/authorize");
    assert!(front.query.contains_key("request_uri") && !front.query.contains_key("dpop_jkt"));
    let push = last(op, "/par");
    assert_eq!(push.body.get("dpop_jkt"), rp.dpop_jkt().as_ref());
    let proof = push.proof.expect("the push carries a proof");
    assert_eq!(proof["htu"], format!("{}/par", op.url));
    assert_eq!(push.proof_jkt, rp.dpop_jkt());
    assert_eq!(rp.complete(&query, &txn).unwrap().token_type, "DPoP");
}

#[test]
fn dpop_modes() {
    // never: no proofs, a Bearer token, no dpop_jkt.
    let op = start_op(dpop_cfg());
    let rp = rp_for(op, json!({"dpop": "never"}));
    assert!(!rp.uses_dpop());
    let (txn, query) = browse(&rp, AuthorizeOptions::default());
    assert!(!txn.url.contains("dpop_jkt"));
    assert_eq!(rp.complete(&query, &txn).unwrap().token_type, "Bearer");
    assert!(last(op, "/token").proof.is_none());
    // auto with nothing advertised, and auto with a list without ES256: no DPoP.
    let plain = start_op(OpCfg::default());
    assert!(!rp_for(plain, json!({})).uses_dpop());
    assert_eq!(sign_in(&rp_for(plain, json!({}))).unwrap().token_type, "Bearer");
    let other = start_op(OpCfg { dpop_algs: Some(vec!["PS256".into()]), ..OpCfg::default() });
    assert!(!rp_for(other, json!({"dpop": "auto"})).uses_dpop());
    // always: creation fails unless ES256 is advertised.
    let err = RelyingParty::create(base(plain, json!({"dpop": "always"}))).err().unwrap();
    assert!(err.to_string().contains("dpop_signing_alg_values_supported"), "{err}");
    let err = RelyingParty::create(base(other, json!({"dpop": "always"}))).err().unwrap();
    assert!(err.to_string().contains("ES256"), "{err}");
    assert!(rp_for(op, json!({"dpop": "always"})).uses_dpop());
    let err = RelyingParty::create(base(op, json!({"dpop": "sometimes"}))).err().unwrap();
    assert_eq!(err.to_string(), "dpop must be auto, always, or never");
}

#[test]
fn dpop_key_from_pem() {
    use p256::pkcs8::EncodePrivateKey;
    let op = start_op(dpop_cfg());
    let key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let pem = key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap().to_string();
    let point = key.verifying_key().to_encoded_point(false);
    let canonical = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}", b64url_encode(point.x().unwrap()), b64url_encode(point.y().unwrap()));
    let expected = b64url_encode(&Sha256::digest(canonical.as_bytes()));
    let one = rp_for(op, json!({"dpopKey": pem}));
    let two = rp_for(op, json!({"dpopKey": pem}));
    assert_eq!(one.dpop_jkt(), Some(expected.clone()));
    assert_eq!(two.dpop_jkt(), Some(expected), "two processes share the key");
    assert_eq!(sign_in(&one).unwrap().token_type, "DPoP");
    // Generated keys differ.
    assert_ne!(rp_for(op, json!({})).dpop_jkt(), rp_for(op, json!({})).dpop_jkt());
    // From a file, through resolve_config.
    let dir = std::env::temp_dir().join(format!("oidc-dpop-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("dpop.pem"), &pem).unwrap();
    let resolved = resolve_config(&base(op, json!({"dpopKey": "file:dpop.pem"})), &dir.to_string_lossy()).unwrap();
    assert!(resolved["dpopKey"].as_str().unwrap().contains("BEGIN PRIVATE KEY"));
    let _ = std::fs::remove_dir_all(&dir);
    let err = RelyingParty::create(base(op, json!({"dpopKey": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"}))).err().unwrap();
    assert!(err.to_string().contains("dpopKey"), "{err}");
}

#[test]
fn dpop_nonce_from_the_authorization_server_is_retried_once_and_remembered() {
    let op = start_op(OpCfg { nonce_as: true, nonce_rs: true, ..dpop_cfg() });
    let rp = rp_for(op, json!({}));
    let login = sign_in(&rp).unwrap();
    assert_eq!(login.token_type, "DPoP");
    assert_eq!(*op.nonce_refusals.lock().unwrap(), 1, "one use_dpop_nonce, then a retry");
    let tokens = seen(op, "/token");
    assert_eq!(tokens.len(), 2);
    assert!(tokens[0].proof.as_ref().unwrap().get("nonce").is_none());
    assert_eq!(tokens[1].proof.as_ref().unwrap()["nonce"], AS_NONCE);
    // The next request to the same origin sends the remembered nonce and is not refused.
    rp.client_credentials("ssf.manage").unwrap();
    assert_eq!(*op.nonce_refusals.lock().unwrap(), 1);
    assert_eq!(last(op, "/token").proof.unwrap()["nonce"], AS_NONCE);
    // The resource server's 401 is retried once with its nonce.
    op.cfg.lock().unwrap().nonce_as = false;
    let info = rp.userinfo(&login.access_token, &login.token_type, &login.subject).unwrap();
    assert_eq!(info["sub"], "user-1");
    assert_eq!(*op.nonce_refusals.lock().unwrap(), 2);
    let calls = seen(op, "/userinfo");
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].proof.as_ref().unwrap()["nonce"], RS_NONCE);
}

#[test]
fn a_nonce_is_retried_only_once() {
    let op = start_op(dpop_cfg());
    let rp = rp_for(op, json!({}));
    let login = sign_in(&rp).unwrap();
    op.cfg.lock().unwrap().nonce_never_satisfied = true;
    let before = seen(op, "/userinfo").len();
    let err = rp.userinfo(&login.access_token, &login.token_type, &login.subject).unwrap_err();
    assert_eq!(err.oauth_error, "invalid_token");
    assert_eq!(seen(op, "/userinfo").len() - before, 2, "one request and one retry");
}

#[test]
fn the_token_type_must_match_whether_a_proof_was_sent() {
    let op = start_op(OpCfg { token_type: Some("Bearer".into()), ..dpop_cfg() });
    let err = sign_in(&rp_for(op, json!({}))).unwrap_err();
    assert!(err.to_string().contains("not DPoP"), "{err}");
    let op = start_op(OpCfg { token_type: Some("dpop".into()), ..OpCfg::default() });
    let err = sign_in(&rp_for(op, json!({}))).unwrap_err();
    assert!(err.to_string().contains("DPoP token"), "{err}");
    // DPoP is case-insensitive.
    let op = start_op(OpCfg { token_type: Some("dpop".into()), ..dpop_cfg() });
    assert_eq!(sign_in(&rp_for(op, json!({}))).unwrap().token_type, "dpop");
}

#[test]
fn transmitter_calls_carry_dpop_proofs_and_a_revoked_session_leaves_the_cache() {
    let op = start_op(dpop_cfg());
    let rp = Arc::new(rp_for(op, json!({})));
    let tx = start_transmitter();
    *tx.nonce.lock().unwrap() = Some("tx-nonce".into());
    let login = {
        let (txn, query) = browse(&rp, AuthorizeOptions::default());
        rp.complete_session(&query, &txn, "local-1").unwrap()
    };
    assert_eq!(login.session_id, "local-1");
    assert!(rp.session("local-1").is_some());
    let receiver = SignalsReceiver::new(&tx.url, Arc::new(|_, _| {}), ReceiverOptions { relying_party: Some(Arc::clone(&rp)), poll_interval_ms: 60_000, ..ReceiverOptions::default() }).unwrap();
    receiver.start().unwrap();
    receiver.stop();
    assert_eq!(*tx.nonce_refusals.lock().unwrap(), 1, "one use_dpop_nonce from the transmitter, then a retry");
    assert_eq!(tx.authorization.lock().unwrap().as_str(), "DPoP app-token");
    let proofs = tx.proofs.lock().unwrap().clone();
    assert!(proofs.iter().any(|(m, p, _)| m == "POST" && p == "/ssf/stream"));
    assert!(proofs.iter().all(|(_, _, c)| c["ath"] == ath_of("app-token") && c["nonce"] == "tx-nonce"));
    receiver.track(json!({"local_id": "local-1", "person": "user-1", "idp_session": "sid-1"}).as_object().cloned().unwrap());
    deliver(tx, &Event::get("sessionRevoked"), json!({"format": "complex", "user": {"format": "iss_sub", "iss": tx.url, "sub": "user-1"}, "session": {"format": "opaque", "id": "sid-1"}}), json!({}), None);
    receiver.poll_once().unwrap();
    assert!(rp.session("local-1").is_none(), "session-revoked cleared the cache entry");
    assert!(tx.proofs.lock().unwrap().iter().any(|(_, p, _)| p.starts_with("/ssf/poll/")));
}

// ---- 2. acr -------------------------------------------------------------------------

#[test]
fn acr_is_enforced_when_requested() {
    let op = start_op(OpCfg::default());
    let rp = rp_for(op, json!({"acrValues": "urn:loa:2 urn:loa:3"}));
    let (txn, query) = browse(&rp, AuthorizeOptions::default());
    assert_eq!(txn.acr_values, "urn:loa:2 urn:loa:3");
    assert_eq!(query_of(&txn.url).get("acr_values").map(String::as_str), Some("urn:loa:2 urn:loa:3"));
    let err = rp.complete(&query, &txn).unwrap_err();
    assert!(err.to_string().contains("no acr"), "{err}");
    op.cfg.lock().unwrap().acr = Some("urn:loa:1".into());
    let err = sign_in(&rp).unwrap_err();
    assert!(err.to_string().contains("not one of the requested"), "{err}");
    op.cfg.lock().unwrap().acr = Some("urn:loa:3".into());
    let login = sign_in(&rp).unwrap();
    assert_eq!(login.claims["acr"], "urn:loa:3");
    // The per-request option replaces the setting.
    let (txn, query) = browse(&rp, AuthorizeOptions { acr_values: "urn:loa:1".into(), ..Default::default() });
    assert_eq!(txn.acr_values, "urn:loa:1");
    assert!(rp.complete(&query, &txn).is_err());
    // The refresh path does not re-check acr.
    op.cfg.lock().unwrap().acr = None;
    assert!(rp.refresh(&login.refresh_token, "", Some(&login)).is_ok());
    // Not requested: not checked.
    let plain = rp_for(op, json!({}));
    let (txn, query) = browse(&plain, AuthorizeOptions { acr_values: String::new(), ..Default::default() });
    assert!(txn.acr_values.is_empty());
    assert!(plain.complete(&query, &txn).is_ok());
    // A list is accepted as the setting too.
    let listed = rp_for(op, json!({"acrValues": ["a", "b"]}));
    assert_eq!(listed.config()["acrValues"], "a b");
}

// ---- 3. PAR required ----------------------------------------------------------------

#[test]
fn par_required_by_the_provider() {
    let op = start_op(OpCfg { par: true, require_par: true, ..OpCfg::default() });
    let err = RelyingParty::create(base(op, json!({"par": "never"}))).err().unwrap();
    assert!(err.to_string().contains("requires pushed authorization requests"), "{err}");
    let rp = rp_for(op, json!({"par": "auto"}));
    assert_eq!(rp.metadata()["require_pushed_authorization_requests"], true);
    let (txn, query) = browse(&rp, AuthorizeOptions::default());
    assert!(txn.url.contains("request_uri="));
    assert!(rp.complete(&query, &txn).is_ok());
    let missing = start_op(OpCfg { par: false, require_par: true, ..OpCfg::default() });
    let err = RelyingParty::create(base(missing, json!({}))).err().unwrap();
    assert!(err.to_string().contains("no pushed authorization endpoint"), "{err}");
    let always = start_op(OpCfg::default());
    let err = RelyingParty::create(base(always, json!({"par": "always"}))).err().unwrap();
    assert!(err.to_string().contains("no pushed authorization endpoint"), "{err}");
}

// ---- 4. algorithms ------------------------------------------------------------------

#[test]
fn rs256_only_by_default() {
    let op = start_op(OpCfg { advertised: vec!["RS256".into(), "ES256".into()], sign_alg: "ES256".into(), ..OpCfg::default() });
    let rp = rp_for(op, json!({}));
    assert_eq!(rp.id_token_algs(), ["RS256".to_string()]);
    assert_eq!(rp.config()["idTokenSigningAlgs"], json!(["RS256"]));
    let err = sign_in(&rp).unwrap_err();
    assert!(err.to_string().contains("ES256"), "{err}");
    let wide = rp_for(op, json!({"idTokenSigningAlgs": ["RS256", "ES256"]}));
    assert_eq!(wide.id_token_algs(), ["RS256".to_string(), "ES256".to_string()]);
    assert!(sign_in(&wide).is_ok());
    let pinned = rp_for(op, json!({"idTokenSignedResponseAlg": "ES256"}));
    assert_eq!(pinned.id_token_algs(), ["ES256".to_string()]);
    assert!(sign_in(&pinned).is_ok());
}

#[test]
fn every_allowed_algorithm_verifies() {
    for alg in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"] {
        let op = start_op(OpCfg { advertised: vec![alg.into()], sign_alg: alg.into(), ..OpCfg::default() });
        let rp = rp_for(op, json!({"idTokenSigningAlgs": [alg]}));
        let login = sign_in(&rp).unwrap_or_else(|err| panic!("{alg}: {err}"));
        assert_eq!(login.subject, "user-1", "{alg}");
        // A signature by another key of the same family is refused.
        let mut forged = login.id_token.clone();
        let cut = forged.rfind('.').unwrap();
        let other = if alg.starts_with("ES") || alg == "EdDSA" { "RS256" } else { "ES256" };
        forged.replace_range(cut + 1.., &URL_SAFE_NO_PAD.encode(sign_raw(other, b"x")));
        let checks = crate::idtoken::TokenChecks {
            issuer: op.url.clone(),
            client_id: CLIENT.into(),
            algorithms: vec![alg.into()],
            jwks: alg_keys().jwks.iter().map(|v| v.as_object().cloned().unwrap()).collect(),
            clock_tolerance_sec: 30.0,
            ..Default::default()
        };
        assert!(crate::validate_id_token(&login.id_token, &checks).is_ok(), "{alg}");
        assert!(crate::validate_id_token(&forged, &checks).is_err(), "{alg} forged");
    }
}

#[test]
fn a_set_signed_with_ec_or_eddsa_verifies() {
    let jwks: Vec<JsonMap> = alg_keys().jwks.iter().map(|v| v.as_object().cloned().unwrap()).collect();
    for alg in ["ES256", "ES384", "ES512", "EdDSA", "PS256"] {
        let payload = json!({"a": 1});
        let header = json!({"alg": alg, "kid": kid_for(alg), "typ": "secevent+jwt"});
        let signing = format!("{}.{}", b64url_encode(&serde_json::to_vec(&header).unwrap()), b64url_encode(&serde_json::to_vec(&payload).unwrap()));
        let token = format!("{signing}.{}", URL_SAFE_NO_PAD.encode(sign_raw(alg, signing.as_bytes())));
        verify_compact_jws(&token, &jwks).unwrap_or_else(|err| panic!("{alg}: {err}"));
    }
}

#[test]
fn none_and_unknown_algorithms_are_refused_and_hmac_only_when_named() {
    let op = start_op(OpCfg { advertised: vec!["HS256".into(), "none".into()], sign_alg: "HS256".into(), ..OpCfg::default() });
    for bad in [json!({"idTokenSigningAlgs": ["none"]}), json!({"idTokenSignedResponseAlg": "none"}), json!({"idTokenSigningAlgs": ["RS256", "None"]})] {
        let err = RelyingParty::create(base(op, bad)).err().unwrap();
        assert!(err.to_string().contains("never accepted"), "{err}");
    }
    let err = RelyingParty::create(base(op, json!({"idTokenSigningAlgs": ["XX999"]}))).err().unwrap();
    assert!(err.to_string().contains("cannot be verified"), "{err}");
    // The default does not take HS256 because the provider advertises it.
    let err = RelyingParty::create(base(op, json!({}))).err().unwrap();
    assert!(err.to_string().contains("none of this client's ID token algorithms"), "{err}");
    let named = rp_for(op, json!({"idTokenSigningAlgs": ["HS256"]}));
    assert!(sign_in(&named).is_ok());
    // Allowed and not advertised: not accepted.
    let rs = start_op(OpCfg::default());
    let partly = rp_for(rs, json!({"idTokenSigningAlgs": ["RS256", "ES256"]}));
    assert_eq!(partly.id_token_algs(), ["RS256".to_string()]);
    let err = RelyingParty::create(base(rs, json!({"idTokenSignedResponseAlg": "ES256"}))).err().unwrap();
    assert!(err.to_string().contains("does not advertise"), "{err}");
    // An ES256 header with only an RSA key that matches the kid is refused.
    let mut payload = json!({"iss": rs.url, "sub": "s", "aud": CLIENT, "exp": now() + 60, "iat": now()});
    payload["x"] = json!(1);
    let token = sign_jwt("ES256", Some("JWT"), &payload);
    let rsa_only: Vec<JsonMap> = vec![alg_keys().jwks[0].as_object().cloned().unwrap()];
    let checks = crate::idtoken::TokenChecks { issuer: rs.url.clone(), client_id: CLIENT.into(), algorithms: vec!["ES256".into()], jwks: rsa_only, ..Default::default() };
    assert!(crate::validate_id_token(&token, &checks).is_err());
}

// ---- 5. typ and at_hash -------------------------------------------------------------

#[test]
fn typ_and_at_hash_are_required_by_default() {
    let op = start_op(OpCfg { typ: None, ..OpCfg::default() });
    let rp = rp_for(op, json!({}));
    assert_eq!(rp.config()["requireIdTokenTypAndAtHash"], true);
    let err = sign_in(&rp).unwrap_err();
    assert!(err.to_string().contains("no typ"), "{err}");
    op.cfg.lock().unwrap().typ = Some("at+jwt".into());
    assert!(sign_in(&rp).unwrap_err().to_string().contains("not an ID token"));
    op.cfg.lock().unwrap().typ = Some("Application/JWT".into());
    assert!(sign_in(&rp).is_ok());
    op.cfg.lock().unwrap().typ = Some("jwt".into());
    assert!(sign_in(&rp).is_ok());
    op.cfg.lock().unwrap().at_hash = false;
    let err = sign_in(&rp).unwrap_err();
    assert!(err.to_string().contains("no at_hash"), "{err}");
    // The refresh path holds the same rule.
    op.cfg.lock().unwrap().at_hash = true;
    let login = sign_in(&rp).unwrap();
    op.cfg.lock().unwrap().at_hash = false;
    assert!(rp.refresh(&login.refresh_token, "", Some(&login)).unwrap_err().to_string().contains("at_hash"));
}

#[test]
fn require_id_token_typ_and_at_hash_false_checks_them_only_when_present() {
    let op = start_op(OpCfg { typ: None, at_hash: false, ..OpCfg::default() });
    let rp = rp_for(op, json!({"requireIdTokenTypAndAtHash": false}));
    assert!(sign_in(&rp).is_ok());
    op.cfg.lock().unwrap().typ = Some("logout+jwt".into());
    assert!(sign_in(&rp).is_err());
    let err = RelyingParty::create(base(op, json!({"requireIdTokenTypAndAtHash": "no"}))).err().unwrap();
    assert!(err.to_string().contains("true or false"), "{err}");
}

// ---- 6. the same checks on every way of creating a client ---------------------------

#[test]
fn defaults_apply_when_created_directly() {
    let op = start_op(OpCfg::default());
    let rp = rp_for(op, json!({}));
    let config = rp.config();
    assert_eq!(config["par"], "auto");
    assert_eq!(config["dpop"], "auto");
    assert_eq!(config["clockToleranceSec"], 30);
    assert_eq!(config["maxIdTokenAgeSec"], 600);
    assert_eq!(config["idTokenSigningAlgs"], json!(["RS256"]));
    assert_eq!(config["requireIdTokenTypAndAtHash"], true);
    // resolve_config gives the same.
    let resolved = resolve_config(&base(op, json!({})), ".").unwrap();
    for key in ["par", "dpop", "clockToleranceSec", "maxIdTokenAgeSec", "idTokenSigningAlgs", "requireIdTokenTypAndAtHash"] {
        assert_eq!(resolved[key], config[key], "{key}");
    }
    let err = RelyingParty::create(base(op, json!({"clockToleranceSec": -1}))).err().unwrap();
    assert!(err.to_string().contains("clockToleranceSec"), "{err}");
    let err = RelyingParty::create(base(op, json!({"par": "maybe"}))).err().unwrap();
    assert_eq!(err.to_string(), "par must be auto, always, or never");
}

#[test]
fn the_redirect_uri_rule_holds_everywhere() {
    let op = start_op(OpCfg::default());
    for good in ["https://app.example/cb", "http://localhost:3000/cb", "http://127.0.0.1/cb", "http://[::1]:8080/cb"] {
        assert!(RelyingParty::create(base(op, json!({"redirectUri": good}))).is_ok(), "{good}");
        assert!(resolve_config(&base(op, json!({"redirectUri": good})), ".").is_ok(), "{good}");
    }
    // allowInsecure is for a development provider, not for redirect URIs.
    for bad in ["http://app.example/cb", "http://10.0.0.1/cb", "ftp://localhost/cb"] {
        let err = RelyingParty::create(base(op, json!({"redirectUri": bad}))).err().unwrap();
        assert!(err.to_string().contains("redirectUri"), "{bad}: {err}");
        assert!(resolve_config(&base(op, json!({"redirectUri": bad})), ".").is_err(), "{bad}");
    }
    let err = RelyingParty::create(base(op, json!({"redirectUri": null}))).err().unwrap();
    assert!(err.to_string().contains("redirectUri is required"), "{err}");
    let err = RelyingParty::create(base(op, json!({"postLogoutRedirectUri": "http://evil.example/"}))).err().unwrap();
    assert!(err.to_string().contains("postLogoutRedirectUri"), "{err}");
    // The per-request override.
    let rp = rp_for(op, json!({}));
    let err = rp.authorize_options(AuthorizeOptions { redirect_uri: "http://evil.example/cb".into(), ..Default::default() }).unwrap_err();
    assert!(err.to_string().contains("redirect_uri"), "{err}");
    let ok = rp.authorize_options(AuthorizeOptions { redirect_uri: "http://[::1]:9/cb".into(), ..Default::default() }).unwrap();
    assert_eq!(ok.redirect_uri, "http://[::1]:9/cb");
}

#[test]
fn an_iat_in_the_future_is_refused() {
    let op = start_op(OpCfg { iat_offset: 120, ..OpCfg::default() });
    let rp = rp_for(op, json!({}));
    let err = sign_in(&rp).unwrap_err();
    assert!(err.to_string().contains("iat is in the future"), "{err}");
    op.cfg.lock().unwrap().iat_offset = 20;
    assert!(sign_in(&rp).is_ok(), "within the 30 second tolerance");
    let strict = rp_for(op, json!({"clockToleranceSec": 5}));
    assert!(sign_in(&strict).is_err());
}

// ---- 7. the session cache -----------------------------------------------------------

#[test]
fn the_session_cache_answers_and_refreshes() {
    let op = start_op(OpCfg::default());
    let rp = rp_for(op, json!({}));
    let (txn, query) = browse(&rp, AuthorizeOptions::default());
    let login = rp.complete_session(&query, &txn, "s-1").unwrap();
    let calls = *op.token_calls.lock().unwrap();
    let access = rp.session_access_token("s-1").unwrap();
    assert_eq!(access.access_token, login.access_token);
    assert_eq!(*op.token_calls.lock().unwrap(), calls, "a cached token with time left is answered without a call");
    // Removing a session (sign-out) clears its entry.
    rp.remove_session("s-1");
    assert!(rp.session("s-1").is_none());
    assert!(rp.session_access_token("s-1").is_err());
    // Twenty seconds left (under the 30 second margin): refreshed, and the cache updated.
    let (txn, query) = browse(&rp, AuthorizeOptions::default());
    op.cfg.lock().unwrap().expires_in = 20;
    let short = rp.complete_session(&query, &txn, "s-2").unwrap();
    let refreshed = rp.session_access_token("s-2").unwrap();
    assert_ne!(refreshed.access_token, short.access_token);
    assert_eq!(last(op, "/token").body["grant_type"], "refresh_token");
    assert_eq!(rp.session("s-2").unwrap().access_token, refreshed.access_token);
    assert_eq!(rp.session("s-2").unwrap().session_id, "s-2");
    // A failed refresh removes the entry and is a refusal.
    op.cfg.lock().unwrap().fail_refresh = true;
    let err = rp.session_access_token("s-2").unwrap_err();
    assert_eq!(err.oauth_error, "invalid_grant");
    assert!(rp.session("s-2").is_none());
    // No id: a handle is made and returned.
    op.cfg.lock().unwrap().fail_refresh = false;
    op.cfg.lock().unwrap().expires_in = 300;
    let (txn, query) = browse(&rp, AuthorizeOptions::default());
    let made = rp.complete_session(&query, &txn, "").unwrap();
    assert!(made.session_id.len() >= 32);
    assert!(rp.session_access_token(&made.session_id).is_ok());
}

#[test]
fn the_session_cache_refreshes_with_a_dpop_proof() {
    let op = start_op(OpCfg { expires_in: 10, ..dpop_cfg() });
    let rp = rp_for(op, json!({}));
    let (txn, query) = browse(&rp, AuthorizeOptions::default());
    let login = rp.complete_session(&query, &txn, "d-1").unwrap();
    let access = rp.session_access_token("d-1").unwrap();
    assert_ne!(access.access_token, login.access_token);
    assert_eq!(access.token_type, "DPoP");
    let call = last(op, "/token");
    assert_eq!(call.body["grant_type"], "refresh_token");
    assert_eq!(call.proof_jkt, rp.dpop_jkt());
}

struct CountingStore {
    inner: MemorySessionStore,
    sets: Mutex<i32>,
}

impl SessionStore for CountingStore {
    fn get(&self, id: &str) -> Option<Login> {
        self.inner.get(id)
    }
    fn set(&self, id: &str, login: Login) {
        *self.sets.lock().unwrap() += 1;
        self.inner.set(id, login);
    }
    fn remove(&self, id: &str) {
        self.inner.remove(id);
    }
}

#[test]
fn the_session_store_can_be_replaced() {
    let op = start_op(OpCfg::default());
    let rp = rp_for(op, json!({}));
    let store = Arc::new(CountingStore { inner: MemorySessionStore::default(), sets: Mutex::new(0) });
    rp.set_session_store(store.clone());
    let (txn, query) = browse(&rp, AuthorizeOptions::default());
    rp.complete_session(&query, &txn, "x").unwrap();
    assert_eq!(*store.sets.lock().unwrap(), 1);
    assert!(store.inner.get("x").is_some());
    rp.remove_session("x");
    assert!(store.inner.get("x").is_none());
}
