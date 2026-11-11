// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::b64::b64url_encode;
use crate::idtoken::hash_claim;
use crate::value::JsonMap;
use crate::{resolve_config, subject_of, verify_compact_jws, AuthorizeOptions, Event, OidcError, ReceiverOptions, RelyingParty, SignalsReceiver, Transaction, DEFAULT_SCOPES};

const CLIENT: &str = "oidc-caep-risc-demo";
const SECRET: &str = "test-secret";
const SCOPES: &str = "openid profile email offline_access ssf.read ssf.manage";

pub(crate) struct Keys {
    pub(crate) provider: RsaPrivateKey,
    pub(crate) client_pem: String,
    pub(crate) client_public: RsaPublicKey,
    pub(crate) provider_jwk: Value,
}

pub(crate) fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut rng = rand::thread_rng();
        let provider = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let client = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let client_pem = client.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let n = b64url_encode(&provider.n().to_bytes_be());
        let e = b64url_encode(&provider.e().to_bytes_be());
        Keys {
            client_public: client.to_public_key(),
            provider_jwk: json!({"kty": "RSA", "n": n, "e": e, "kid": "op", "alg": "RS256", "use": "sig"}),
            provider,
            client_pem,
        }
    })
}

fn sign_id_token(payload: &Value, corrupt: bool) -> String {
    let header = json!({"alg": "RS256", "kid": "op", "typ": "JWT"});
    let h = b64url_encode(&serde_json::to_vec(&header).unwrap());
    let p = b64url_encode(&serde_json::to_vec(payload).unwrap());
    let signing = format!("{h}.{p}");
    let sig = SigningKey::<Sha256>::new(keys().provider.clone()).sign_with_rng(&mut rand::thread_rng(), signing.as_bytes()).to_vec();
    let mut encoded = URL_SAFE_NO_PAD.encode(sig);
    if corrupt && !encoded.is_empty() {
        let flip = if encoded.starts_with('A') { 'B' } else { 'A' };
        encoded.replace_range(..1, &flip.to_string());
    }
    format!("{signing}.{encoded}")
}

fn assertion_ok(assertion: &str, audience: &str) -> bool {
    let parts: Vec<&str> = assertion.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    let Ok(payload) = URL_SAFE_NO_PAD.decode(parts[1]) else {
        return false;
    };
    let Ok(doc) = serde_json::from_slice::<Value>(&payload) else {
        return false;
    };
    let aud_ok = doc.get("aud").and_then(|v| v.as_str()) == Some(audience) || doc.get("aud").and_then(|v| v.as_array()).is_some_and(|list| list.iter().any(|item| item.as_str() == Some(audience)));
    if !aud_ok {
        return false;
    }
    let Ok(sig) = URL_SAFE_NO_PAD.decode(parts[2]) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(sig.as_slice()) else {
        return false;
    };
    VerifyingKey::<Sha256>::new(keys().client_public.clone()).verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature).is_ok()
}

pub(crate) struct Req {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) query: HashMap<String, String>,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) body: String,
}

struct Stub {
    url: String,
    aud: Mutex<String>,
    corrupt: Mutex<bool>,
    bad_at_hash: Mutex<bool>,
    exp: Mutex<Option<i64>>,
    par: Mutex<bool>,
    codes: Mutex<HashMap<String, HashMap<String, String>>>,
    refresh: Mutex<HashMap<String, HashMap<String, String>>>,
    access: Mutex<HashMap<String, Value>>,
    pushed: Mutex<HashMap<String, HashMap<String, String>>>,
}

fn start_provider() -> &'static Stub {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let stub: &'static Stub = Box::leak(Box::new(Stub {
        url: format!("http://127.0.0.1:{port}"),
        aud: Mutex::new(CLIENT.into()),
        corrupt: Mutex::new(false),
        bad_at_hash: Mutex::new(false),
        exp: Mutex::new(None),
        par: Mutex::new(false),
        codes: Mutex::new(HashMap::new()),
        refresh: Mutex::new(HashMap::new()),
        access: Mutex::new(HashMap::new()),
        pushed: Mutex::new(HashMap::new()),
    }));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            if let Some(req) = read_req(&mut stream) {
                let (status, headers, body) = handle(stub, &req);
                let _ = write_res(&mut stream, status, &headers, &body);
            }
        }
    });
    stub
}

pub(crate) fn read_req(stream: &mut TcpStream) -> Option<Req> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if stream.read(&mut byte).ok()? == 0 {
            return None;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 100_000 {
            return None;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");
    let request = lines.next()?;
    let mut parts = request.split(' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len = headers.get("content-length").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
    let mut body = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut body).ok()?;
    }
    let (path, query_text) = target.split_once('?').unwrap_or((target.as_str(), ""));
    let mut query = HashMap::new();
    for pair in query_text.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        query.insert(decode_query(k), decode_query(v));
    }
    Some(Req { method, path: path.to_string(), query, headers, body: String::from_utf8_lossy(&body).into_owned() })
}

fn decode_query(value: &str) -> String {
    let plus = value.replace('+', " ");
    urlencoding_decode(&plus)
}

fn urlencoding_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00"), 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn write_res(stream: &mut TcpStream, status: u16, extra: &[(String, String)], body: &[u8]) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "OK",
    };
    let mut head = format!("HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
    for (k, v) in extra {
        head.push_str(k);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

pub(crate) fn json_res(status: u16, body: Value) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let raw = serde_json::to_vec(&body).unwrap_or_default();
    (status, vec![("Content-Type".into(), "application/json".into())], raw)
}

pub(crate) fn form(body: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in body.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(decode_query(k), decode_query(v));
    }
    out
}

fn handle(stub: &Stub, req: &Req) -> (u16, Vec<(String, String)>, Vec<u8>) {
    if req.path == "/.well-known/openid-configuration" {
        return json_res(200, metadata(stub));
    }
    if req.path == "/jwks" {
        return json_res(200, json!({"keys": [keys().provider_jwk]}));
    }
    if req.path == "/userinfo" {
        let token = req.headers.get("authorization").map(|v| v.trim_start_matches("Bearer ").trim().to_string()).unwrap_or_default();
        let claims = stub.access.lock().unwrap().get(&token).cloned();
        return match claims {
            Some(claims) => json_res(200, claims),
            None => json_res(401, json!({"error": "invalid_token"})),
        };
    }
    if req.path == "/par" && req.method == "POST" {
        if !authorized(stub, req) {
            return json_res(401, json!({"error": "invalid_client"}));
        }
        let values = form(&req.body);
        let mut buf = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
        let request_uri = format!("urn:par:{}", URL_SAFE_NO_PAD.encode(buf));
        stub.pushed.lock().unwrap().insert(request_uri.clone(), values);
        return json_res(201, json!({"request_uri": request_uri, "expires_in": 60}));
    }
    if req.path == "/authorize" {
        let mut params = req.query.clone();
        if let Some(stored) = params.get("request_uri").cloned() {
            let Some(got) = stub.pushed.lock().unwrap().get(&stored).cloned() else {
                return json_res(400, json!({"error": "invalid_request"}));
            };
            params = got;
        }
        if params.get("code_challenge_method").map(String::as_str) != Some("S256") || params.get("code_challenge").unwrap_or(&String::new()).is_empty() {
            return json_res(400, json!({"error": "invalid_request"}));
        }
        let mut buf = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
        let code = URL_SAFE_NO_PAD.encode(buf);
        let mut row = HashMap::new();
        row.insert("sub".into(), "user-1".into());
        row.insert("email".into(), "user-1@example.com".into());
        row.insert("sid".into(), "sid-1".into());
        row.insert("nonce".into(), params.get("nonce").cloned().unwrap_or_default());
        row.insert("redirect".into(), params.get("redirect_uri").cloned().unwrap_or_default());
        row.insert("challenge".into(), params.get("code_challenge").cloned().unwrap_or_default());
        stub.codes.lock().unwrap().insert(code.clone(), row);
        let location = format!("{}?code={}&state={}&iss={}", params.get("redirect_uri").cloned().unwrap_or_default(), code, params.get("state").cloned().unwrap_or_default(), stub.url);
        return (302, vec![("Location".into(), location)], Vec::new());
    }
    if req.path == "/token" && req.method == "POST" {
        if !authorized(stub, req) {
            return json_res(401, json!({"error": "invalid_client", "error_description": "client authentication failed"}));
        }
        let params = form(&req.body);
        match params.get("grant_type").map(String::as_str) {
            Some("client_credentials") => return json_res(200, json!({"access_token": "cc-token", "token_type": "Bearer", "expires_in": 120, "scope": params.get("scope").cloned().unwrap_or_default()})),
            Some("refresh_token") => {
                let Some(row) = stub.refresh.lock().unwrap().get(params.get("refresh_token").map(String::as_str).unwrap_or("")).cloned() else {
                    return json_res(400, json!({"error": "invalid_grant"}));
                };
                let mut minted = token_for(stub, &row);
                let access = minted["access_token"].as_str().unwrap_or("").to_string();
                let mut claims = stub.access.lock().unwrap().get(&access).cloned().unwrap_or(Value::Null);
                if let Some(obj) = claims.as_object_mut() {
                    obj.remove("nonce");
                }
                minted["id_token"] = Value::String(sign_id_token(&claims, false));
                return json_res(200, minted);
            }
            _ => {}
        }
        let code = params.get("code").cloned().unwrap_or_default();
        let Some(row) = stub.codes.lock().unwrap().get(&code).cloned() else {
            return json_res(400, json!({"error": "invalid_grant"}));
        };
        if params.get("redirect_uri").map(String::as_str) != Some(row.get("redirect").map(String::as_str).unwrap_or("")) {
            return json_res(400, json!({"error": "invalid_grant"}));
        }
        let verifier = params.get("code_verifier").cloned().unwrap_or_default();
        let sum = Sha256::digest(verifier.as_bytes());
        if URL_SAFE_NO_PAD.encode(sum) != row.get("challenge").cloned().unwrap_or_default() {
            return json_res(400, json!({"error": "invalid_grant", "error_description": "pkce"}));
        }
        stub.codes.lock().unwrap().remove(&code);
        return json_res(200, token_for(stub, &row));
    }
    json_res(404, json!({"error": "not_found"}))
}

fn metadata(stub: &Stub) -> Value {
    let mut doc = json!({
        "issuer": stub.url,
        "authorization_endpoint": format!("{}/authorize", stub.url),
        "token_endpoint": format!("{}/token", stub.url),
        "jwks_uri": format!("{}/jwks", stub.url),
        "userinfo_endpoint": format!("{}/userinfo", stub.url),
        "end_session_endpoint": format!("{}/end-session", stub.url),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": true,
        "scopes_supported": SCOPES.split(' ').collect::<Vec<_>>()
    });
    if *stub.par.lock().unwrap() {
        doc["pushed_authorization_request_endpoint"] = json!(format!("{}/par", stub.url));
    }
    doc
}

fn token_for(stub: &Stub, row: &HashMap<String, String>) -> Value {
    let mut a = [0u8; 16];
    let mut r = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut a);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut r);
    let access_token = URL_SAFE_NO_PAD.encode(a);
    let refresh_token = URL_SAFE_NO_PAD.encode(r);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let aud = stub.aud.lock().unwrap().clone();
    let forced = stub.exp.lock().unwrap().take();
    let (exp, iat) = if let Some(exp) = forced { (exp, exp) } else { (now + 300, now) };
    let bad = {
        let mut flag = stub.bad_at_hash.lock().unwrap();
        let value = *flag;
        *flag = false;
        value
    };
    let corrupt = {
        let mut flag = stub.corrupt.lock().unwrap();
        let value = *flag;
        *flag = false;
        value
    };
    *stub.aud.lock().unwrap() = CLIENT.into();
    let at_hash = if bad { "aaaa".to_string() } else { hash_claim(&access_token, "RS256") };
    let payload = json!({
        "iss": stub.url, "sub": row.get("sub").cloned().unwrap_or_default(), "aud": aud, "exp": exp, "iat": iat,
        "nonce": row.get("nonce").cloned().unwrap_or_default(), "email": row.get("email").cloned().unwrap_or_default(),
        "name": "Demo User", "preferred_username": row.get("sub").cloned().unwrap_or_default(), "sid": row.get("sid").cloned().unwrap_or_default(),
        "at_hash": at_hash
    });
    let token = sign_id_token(&payload, corrupt);
    stub.refresh.lock().unwrap().insert(refresh_token.clone(), row.clone());
    stub.access.lock().unwrap().insert(access_token.clone(), payload);
    json!({"access_token": access_token, "token_type": "Bearer", "expires_in": 300, "refresh_token": refresh_token, "id_token": token, "scope": SCOPES})
}

fn authorized(stub: &Stub, req: &Req) -> bool {
    if let Some(header) = req.headers.get("authorization") {
        if let Some(token) = header.strip_prefix("Basic ") {
            if let Ok(raw) = STANDARD.decode(token) {
                return String::from_utf8_lossy(&raw) == format!("{CLIENT}:{SECRET}");
            }
        }
    }
    let values = form(&req.body);
    if values.get("client_secret").is_some_and(|v| !v.is_empty()) {
        return values.get("client_id").map(String::as_str) == Some(CLIENT) && values.get("client_secret").map(String::as_str) == Some(SECRET);
    }
    let Some(assertion) = values.get("client_assertion") else {
        return false;
    };
    assertion_ok(assertion, &stub.url)
}

fn provider_config(stub: &Stub, over: Value) -> JsonMap {
    let mut doc = json!({
        "metadataUrl": format!("{}/.well-known/openid-configuration", stub.url),
        "clientId": CLIENT,
        "clientSecret": SECRET,
        "tokenEndpointAuthMethod": "client_secret_basic",
        "redirectUri": "http://127.0.0.1/callback",
        "postLogoutRedirectUri": "http://127.0.0.1/",
        "scopes": SCOPES,
        "privateKeyAlg": "RS256",
        "par": "auto",
        "clockToleranceSec": 30,
        "maxIdTokenAgeSec": 600,
        "allowInsecure": true
    });
    if let Some(extra) = over.as_object() {
        for (k, v) in extra {
            if v.is_null() {
                doc.as_object_mut().unwrap().remove(k);
            } else {
                doc[k] = v.clone();
            }
        }
    }
    doc.as_object().cloned().unwrap()
}

pub(crate) fn manual(raw_url: &str) -> (u16, String) {
    let url = url::Url::parse(raw_url).unwrap();
    let mut stream = TcpStream::connect(format!("{}:{}", url.host_str().unwrap(), url.port().unwrap())).unwrap();
    let path = format!("{}{}", url.path(), url.query().map(|q| format!("?{q}")).unwrap_or_default());
    let req = format!("GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", url.host_str().unwrap());
    stream.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf);
    let status = text.split(' ').nth(1).unwrap_or("0").parse().unwrap_or(0);
    let mut location = String::new();
    for line in text.split("\r\n") {
        if let Some(value) = line.strip_prefix("Location: ") {
            location = value.to_string();
        }
    }
    (status, location)
}

pub(crate) fn query_of(location: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(query) = location.split_once('?').map(|(_, q)| q) else {
        return out;
    };
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(decode_query(k), decode_query(v));
    }
    out
}

struct SignedIn {
    request: Transaction,
    query: HashMap<String, String>,
    login: crate::Login,
}

fn sign_in(rp: &RelyingParty) -> SignedIn {
    let request = rp.authorize().unwrap();
    let (_status, location) = manual(&request.url);
    assert!(!location.is_empty(), "the provider did not redirect");
    let query = query_of(&location);
    let login = rp.complete(&query, &request).unwrap();
    SignedIn { request, query, login }
}

#[test]
fn default_scopes_and_at_hash() {
    let sum = Sha256::digest(b"abc");
    assert_eq!(DEFAULT_SCOPES, SCOPES);
    assert_eq!(hash_claim("abc", "RS256"), b64url_encode(&sum[..sum.len() / 2]));
}

#[test]
fn signs_in_with_pkce() {
    let stub = start_provider();
    let rp = RelyingParty::create(provider_config(stub, json!({}))).unwrap();
    let signed = sign_in(&rp);
    assert_eq!(signed.login.subject, "user-1");
    assert_eq!(signed.login.email, "user-1@example.com");
    assert_eq!(signed.login.sid, "sid-1");
    assert_eq!(signed.login.issuer, stub.url);
    assert_eq!(signed.login.preferred_username, "user-1");
    assert!(!signed.login.refresh_token.is_empty());
    assert!(signed.request.url.contains("code_challenge="));
    assert!(signed.request.url.contains("code_challenge_method=S256"));
    assert!(!signed.request.url.contains("client_secret"));
    let info = rp.userinfo(&signed.login.access_token, &signed.login.token_type, &signed.login.subject).unwrap();
    assert_eq!(info.get("sub").and_then(|v| v.as_str()), Some("user-1"));
    let end = rp.end_session_url(crate::EndSessionOptions { id_token: signed.login.id_token.clone(), state: "bye".into(), ..Default::default() });
    assert!(end.contains("/end-session"));
    assert!(end.contains("id_token_hint="));
    assert!(end.contains("client_id="));
}

#[test]
fn refuses_a_callback_that_is_not_this_sign_in() {
    let stub = start_provider();
    let rp = RelyingParty::create(provider_config(stub, json!({}))).unwrap();
    let request = rp.authorize().unwrap();
    let (_status, location) = manual(&request.url);
    let mut query = query_of(&location);
    let mut bad_state = request.clone();
    bad_state.state = "nope".into();
    let err = rp.complete(&query, &bad_state).unwrap_err();
    assert!(err.to_string().contains("state"), "{err}");
    let mut bad_nonce = request.clone();
    bad_nonce.nonce = "nope".into();
    let err = rp.complete(&query, &bad_nonce).unwrap_err();
    assert!(err.to_string().contains("nonce"), "{err}");
    query.insert("iss".into(), "https://elsewhere.example".into());
    let err = rp.complete(&query, &request).unwrap_err();
    assert!(err.to_string().contains("iss mismatch"), "{err}");
    query.insert("iss".into(), stub.url.clone());
    query.insert("access_token".into(), "should-not-be-here".into());
    let err = rp.complete(&query, &request).unwrap_err();
    assert!(err.to_string().contains("access_token"), "{err}");
}

#[test]
fn accepts_a_code_once() {
    let stub = start_provider();
    let rp = RelyingParty::create(provider_config(stub, json!({}))).unwrap();
    let signed = sign_in(&rp);
    assert_eq!(signed.login.subject, "user-1");
    let err = rp.complete(&signed.query, &signed.request).unwrap_err();
    assert!(err.to_string().contains("already used"), "{err}");
}

#[test]
fn refuses_bad_tokens() {
    let stub = start_provider();
    let rp = RelyingParty::create(provider_config(stub, json!({}))).unwrap();
    let wrong = RelyingParty::create(provider_config(stub, json!({"clientSecret": "nope"}))).unwrap();
    let request = wrong.authorize().unwrap();
    let (_status, location) = manual(&request.url);
    let err = wrong.complete(&query_of(&location), &request).unwrap_err();
    assert_eq!(err.oauth_error, "invalid_client");
    *stub.corrupt.lock().unwrap() = true;
    let request = rp.authorize().unwrap();
    let (_status, location) = manual(&request.url);
    let err = rp.complete(&query_of(&location), &request).unwrap_err();
    assert!(err.to_string().contains("signature"), "{err}");
    *stub.aud.lock().unwrap() = "other-client".into();
    let request = rp.authorize().unwrap();
    let (_status, location) = manual(&request.url);
    let err = rp.complete(&query_of(&location), &request).unwrap_err();
    assert!(err.to_string().contains("audience") || err.to_string().contains("aud"), "{err}");
    let past = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 - 3600;
    *stub.exp.lock().unwrap() = Some(past);
    let request = rp.authorize().unwrap();
    let (_status, location) = manual(&request.url);
    let err = rp.complete(&query_of(&location), &request).unwrap_err();
    assert!(err.to_string().contains("exp") || err.to_string().contains("timestamp") || err.to_string().contains("old") || err.to_string().contains("iat"), "{err}");
    *stub.bad_at_hash.lock().unwrap() = true;
    let request = rp.authorize().unwrap();
    let (_status, location) = manual(&request.url);
    let err = rp.complete(&query_of(&location), &request).unwrap_err();
    assert!(err.to_string().contains("at_hash"), "{err}");
}

#[test]
fn refresh_and_client_credentials() {
    let stub = start_provider();
    let rp = RelyingParty::create(provider_config(stub, json!({}))).unwrap();
    let login = sign_in(&rp).login;
    let refreshed = rp.refresh(&login.refresh_token, "", Some(&login)).unwrap();
    assert_eq!(refreshed.subject, login.subject);
    assert_ne!(refreshed.access_token, login.access_token);
    let own = rp.client_credentials("ssf.manage").unwrap();
    assert_eq!(own.access_token, "cc-token");
    let again = rp.client_credentials("ssf.manage").unwrap();
    assert_eq!(again.access_token, "cc-token");
}

#[test]
fn par_pushes_the_request() {
    let stub = start_provider();
    *stub.par.lock().unwrap() = true;
    let rp = RelyingParty::create(provider_config(stub, json!({}))).unwrap();
    let signed = sign_in(&rp);
    assert!(signed.request.url.contains("request_uri="), "{}", signed.request.url);
    assert!(!signed.request.url.contains("code_challenge="), "{}", signed.request.url);
    assert_eq!(signed.login.subject, "user-1");
}

#[test]
fn post_and_private_key_jwt() {
    let stub = start_provider();
    let posted = RelyingParty::create(provider_config(stub, json!({"tokenEndpointAuthMethod": "client_secret_post"}))).unwrap();
    assert_eq!(sign_in(&posted).login.subject, "user-1");
    let jwt_rp = RelyingParty::create(provider_config(stub, json!({"tokenEndpointAuthMethod": "private_key_jwt", "clientSecret": null, "privateKeyPem": keys().client_pem}))).unwrap();
    assert_eq!(sign_in(&jwt_rp).login.subject, "user-1");
}

#[test]
fn reads_configuration_file_names() {
    let dir = std::env::temp_dir().join(format!("oidc-config-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("secret"), "from-file\n").unwrap();
    std::env::set_var("OIDC_TEST_SECRET", "from-env");
    let file = json!({
        "metadataUrl": "https://localhost:8081/.well-known/openid-configuration",
        "client_id": CLIENT,
        "clientSecret": "env:OIDC_TEST_SECRET",
        "redirectUri": "http://localhost:3000/callback",
        "scopes": SCOPES.split(' ').collect::<Vec<_>>()
    });
    let env = resolve_config(file.as_object().unwrap(), &dir.to_string_lossy()).unwrap();
    assert_eq!(env.get("clientId").and_then(|v| v.as_str()), Some(CLIENT));
    assert_eq!(env.get("clientSecret").and_then(|v| v.as_str()), Some("from-env"));
    assert_eq!(env.get("issuer").and_then(|v| v.as_str()), Some("https://localhost:8081"));
    assert_eq!(env.get("scopes").and_then(|v| v.as_str()), Some(SCOPES));
    assert_eq!(env.get("tokenEndpointAuthMethod").and_then(|v| v.as_str()), Some("client_secret_basic"));
    let mut from_file = file.clone();
    from_file["clientSecret"] = json!("file:secret");
    let got = resolve_config(from_file.as_object().unwrap(), &dir.to_string_lossy()).unwrap();
    assert_eq!(got.get("clientSecret").and_then(|v| v.as_str()), Some("from-file"));
    let chain = "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n";
    std::fs::write(dir.join("ca.pem"), chain).unwrap();
    let mut with_ca = file.clone();
    with_ca["tlsCa"] = json!("ca.pem");
    let got = resolve_config(with_ca.as_object().unwrap(), &dir.to_string_lossy()).unwrap();
    assert_eq!(got.get("tlsCa").and_then(|v| v.as_str()), Some(chain));
    with_ca["tlsCa"] = json!("file:ca.pem");
    let got = resolve_config(with_ca.as_object().unwrap(), &dir.to_string_lossy()).unwrap();
    assert_eq!(got.get("tlsCa").and_then(|v| v.as_str()), Some(chain));
    with_ca["tlsCa"] = json!(chain);
    let got = resolve_config(with_ca.as_object().unwrap(), &dir.to_string_lossy()).unwrap();
    assert_eq!(got.get("tlsCa").and_then(|v| v.as_str()), Some(chain.trim()));
    std::env::set_var("OIDC_TEST_CA", chain);
    with_ca["tlsCa"] = json!("env:OIDC_TEST_CA");
    let got = resolve_config(with_ca.as_object().unwrap(), &dir.to_string_lossy()).unwrap();
    assert_eq!(got.get("tlsCa").and_then(|v| v.as_str()), Some(chain));
    std::env::remove_var("OIDC_TEST_CA");
    let got = resolve_config(with_ca.as_object().unwrap(), &dir.to_string_lossy()).unwrap();
    assert!(got.get("tlsCa").is_none());
    with_ca["tlsCa"] = json!("missing.pem");
    let got = resolve_config(with_ca.as_object().unwrap(), &dir.to_string_lossy()).unwrap();
    assert!(got.get("tlsCa").is_none());
    let mut none = file.clone();
    none["tokenEndpointAuthMethod"] = json!("none");
    let err = resolve_config(none.as_object().unwrap(), &dir.to_string_lossy()).unwrap_err();
    assert!(err.to_string().contains("public client"), "{err}");
    let mut bad = file.clone();
    bad["scopes"] = json!("profile email");
    let err = resolve_config(bad.as_object().unwrap(), &dir.to_string_lossy()).unwrap_err();
    assert!(err.to_string().contains("openid"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn signals_flag() {
    let dir = std::env::temp_dir().join(format!("oidc-signals-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let file = json!({
        "metadataUrl": "https://localhost:8081/.well-known/openid-configuration",
        "client_id": CLIENT,
        "clientSecret": "secret",
        "redirectUri": "http://localhost:3000/callback",
        "ssf": {"transmitter": "https://localhost:8081/", "pollIntervalMs": 3000}
    });
    let omitted = resolve_config(file.as_object().unwrap(), &dir.to_string_lossy()).unwrap();
    assert_eq!(omitted.get("scopes").and_then(|v| v.as_str()), Some(SCOPES));
    assert!(omitted.get("signals").is_none());
    let ssf = omitted.get("ssf").and_then(|v| v.as_object()).unwrap();
    assert_eq!(ssf.get("transmitter").and_then(|v| v.as_str()), Some("https://localhost:8081"));
    assert_eq!(ssf.get("pollIntervalMs").and_then(|v| v.as_i64()).or_else(|| ssf.get("pollIntervalMs").and_then(|v| v.as_u64().map(|n| n as i64))), Some(3000));
    let mut explicit = file.clone();
    explicit["signals"] = json!(true);
    explicit["scopes"] = json!(SCOPES);
    let explicit = resolve_config(explicit.as_object().unwrap(), &dir.to_string_lossy()).unwrap();
    assert_eq!(explicit.get("scopes").and_then(|v| v.as_str()), Some(SCOPES));
    assert!(explicit.get("signals").is_none());
    let mut listed = file.clone();
    listed["signals"] = json!(false);
    listed["scopes"] = json!(SCOPES);
    listed["ssf"] = json!({"transmitter": "not-a-url"});
    let listed = resolve_config(listed.as_object().unwrap(), &dir.to_string_lossy()).unwrap();
    assert_eq!(listed.get("signals"), Some(&Value::Bool(false)));
    assert!(listed.get("ssf").is_none());
    assert_eq!(listed.get("scopes").and_then(|v| v.as_str()), Some("openid profile email offline_access"));
    let mut defaults = file.clone();
    defaults["signals"] = json!(false);
    let defaults = resolve_config(defaults.as_object().unwrap(), &dir.to_string_lossy()).unwrap();
    assert_eq!(defaults.get("signals"), Some(&Value::Bool(false)));
    assert!(defaults.get("ssf").is_none());
    assert_eq!(defaults.get("scopes").and_then(|v| v.as_str()), Some("openid profile email offline_access"));
    let mut only = file.clone();
    only["signals"] = json!(false);
    only["scopes"] = json!("ssf.read ssf.manage");
    let err = resolve_config(only.as_object().unwrap(), &dir.to_string_lossy()).unwrap_err();
    assert!(err.to_string().contains("openid"), "{err}");
    let mut bad = file.clone();
    bad["signals"] = json!("no");
    let err = resolve_config(bad.as_object().unwrap(), &dir.to_string_lossy()).unwrap_err();
    assert_eq!(err.code, "config");
    assert_eq!(err.to_string(), "signals must be true or false");
    let _ = (AuthorizeOptions::default(), OidcError::new("config", ""));
    let _ = Map::<String, Value>::new();
}

pub(crate) struct SsfKeys {
    pub(crate) private: RsaPrivateKey,
    pub(crate) other: RsaPrivateKey,
    pub(crate) jwk: JsonMap,
}

pub(crate) fn ssf_keys() -> &'static SsfKeys {
    static KEYS: OnceLock<SsfKeys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let other = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let mut jwk = JsonMap::new();
        jwk.insert("kty".into(), json!("RSA"));
        jwk.insert("n".into(), json!(b64url_encode(&private.n().to_bytes_be())));
        jwk.insert("e".into(), json!(b64url_encode(&private.e().to_bytes_be())));
        jwk.insert("kid".into(), json!("k1"));
        jwk.insert("alg".into(), json!("RS256"));
        jwk.insert("use".into(), json!("sig"));
        SsfKeys { private, other, jwk }
    })
}

pub(crate) fn sign_set(payload: &Value, key: &RsaPrivateKey, header: Value) -> String {
    let h = b64url_encode(&serde_json::to_vec(&header).unwrap());
    let p = b64url_encode(&serde_json::to_vec(payload).unwrap());
    let signing = format!("{h}.{p}");
    let sig = SigningKey::<Sha256>::new(key.clone()).sign_with_rng(&mut rand::thread_rng(), signing.as_bytes()).to_vec();
    format!("{signing}.{}", URL_SAFE_NO_PAD.encode(sig))
}

pub(crate) struct Transmitter {
    pub(crate) url: String,
    pub(crate) order: Mutex<Vec<String>>,
    pub(crate) queue: Mutex<HashMap<String, String>>,
    pub(crate) acked: Mutex<Vec<String>>,
    pub(crate) errs: Mutex<HashMap<String, String>>,
    pub(crate) created: Mutex<i32>,
    pub(crate) authorization: Mutex<String>,
    pub(crate) verify_state: Mutex<String>,
    pub(crate) verify_status: Mutex<u16>,
    /// Every DPoP proof the transmitter accepted: (method, path, claims).
    pub(crate) proofs: Mutex<Vec<(String, String, Value)>>,
    /// When set, a DPoP request without this nonce is answered 401 use_dpop_nonce.
    pub(crate) nonce: Mutex<Option<String>>,
    pub(crate) nonce_refusals: Mutex<i32>,
}

/// A DPoP proof read and verified the way a server would (RFC 9449 section 4.3).
pub(crate) struct Proof {
    pub(crate) claims: Value,
    pub(crate) jkt: String,
}

pub(crate) fn read_proof(proof: &str) -> Option<Proof> {
    use p256::ecdsa::signature::Verifier as _;
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).ok()?).ok()?;
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).ok()?).ok()?;
    if header.get("typ")?.as_str()? != "dpop+jwt" || header.get("alg")?.as_str()? != "ES256" {
        return None;
    }
    let jwk = header.get("jwk")?;
    if jwk.get("kty")?.as_str()? != "EC" || jwk.get("crv")?.as_str()? != "P-256" || jwk.get("d").is_some() {
        return None;
    }
    let x = jwk.get("x")?.as_str()?;
    let y = jwk.get("y")?.as_str()?;
    let mut point = vec![4u8];
    point.extend(URL_SAFE_NO_PAD.decode(x).ok()?);
    point.extend(URL_SAFE_NO_PAD.decode(y).ok()?);
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).ok()?;
    let sig = p256::ecdsa::Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).ok()?).ok()?;
    key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).ok()?;
    for name in ["jti", "htm", "htu", "iat"] {
        claims.get(name)?;
    }
    let canonical = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
    Some(Proof { claims, jkt: URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())) })
}

pub(crate) fn ath_of(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

pub(crate) fn start_transmitter() -> &'static Transmitter {
    // Two RSA-2048 keys. Generating them inside /jwks can outlast the
    // client's 15 s timeout on a busy machine. start_op calls alg_keys()
    // before it accepts a connection for the same reason (#41).
    ssf_keys();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let tx: &'static Transmitter = Box::leak(Box::new(Transmitter {
        url: format!("http://127.0.0.1:{port}"),
        order: Mutex::new(Vec::new()),
        queue: Mutex::new(HashMap::new()),
        acked: Mutex::new(Vec::new()),
        errs: Mutex::new(HashMap::new()),
        created: Mutex::new(0),
        authorization: Mutex::new(String::new()),
        verify_state: Mutex::new(String::new()),
        verify_status: Mutex::new(0),
        proofs: Mutex::new(Vec::new()),
        nonce: Mutex::new(None),
        nonce_refusals: Mutex::new(0),
    }));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            if let Some(req) = read_req(&mut stream) {
                let (status, headers, body) = handle_tx(tx, &req);
                let _ = write_res(&mut stream, status, &headers, &body);
            }
        }
    });
    tx
}

fn handle_tx(tx: &Transmitter, req: &Req) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let auth = req.headers.get("authorization").cloned().unwrap_or_default();
    *tx.authorization.lock().unwrap() = auth.clone();
    let mut accepted = auth == "Bearer app-token";
    if auth == "DPoP app-token" {
        let proof = req.headers.get("dpop").and_then(|raw| read_proof(raw));
        let Some(proof) = proof else {
            return (401, vec![("WWW-Authenticate".into(), "DPoP error=\"invalid_dpop_proof\"".into())], Vec::new());
        };
        let htu_ok = proof.claims["htu"].as_str() == Some(format!("{}{}", tx.url, req.path).as_str());
        let htm_ok = proof.claims["htm"].as_str() == Some(req.method.as_str());
        let ath_ok = proof.claims["ath"].as_str() == Some(ath_of("app-token").as_str());
        if !(htu_ok && htm_ok && ath_ok) {
            return (401, vec![("WWW-Authenticate".into(), "DPoP error=\"invalid_dpop_proof\"".into())], Vec::new());
        }
        let want = tx.nonce.lock().unwrap().clone();
        if let Some(want) = want {
            if proof.claims["nonce"].as_str() != Some(want.as_str()) {
                *tx.nonce_refusals.lock().unwrap() += 1;
                return (401, vec![("WWW-Authenticate".into(), "DPoP error=\"use_dpop_nonce\"".into()), ("DPoP-Nonce".into(), want)], Vec::new());
            }
        }
        tx.proofs.lock().unwrap().push((req.method.clone(), req.path.clone(), proof.claims));
        accepted = true;
    }
    if !accepted && req.path != "/.well-known/ssf-configuration" && !req.path.starts_with("/jwks") {
        return json_res(401, json!({"error": "invalid_token"}));
    }
    if req.path == "/.well-known/ssf-configuration" {
        return json_res(200, json!({
            "issuer": tx.url,
            "jwks_uri": format!("{}/jwks", tx.url),
            "configuration_endpoint": format!("{}/ssf/stream", tx.url),
            "verification_endpoint": format!("{}/ssf/verify", tx.url),
            "delivery_methods_supported": ["urn:ietf:rfc:8936"]
        }));
    }
    if req.path == "/jwks" {
        return json_res(200, json!({"keys": [ssf_keys().jwk]}));
    }
    if req.path == "/ssf/stream" && req.method == "GET" {
        return json_res(200, json!([]));
    }
    if req.path == "/ssf/stream" && req.method == "POST" {
        let doc: Value = serde_json::from_str(&req.body).unwrap_or(json!({}));
        let mut created = tx.created.lock().unwrap();
        *created += 1;
        let n = *created;
        let method = doc.get("delivery").and_then(|v| v.get("method")).and_then(|v| v.as_str()).unwrap_or("");
        return json_res(201, json!({
            "stream_id": format!("s{n}"),
            "iss": tx.url,
            "aud": "my-app",
            "delivery": {"method": method, "endpoint_url": format!("{}/ssf/poll/s{n}", tx.url)},
            "events_requested": doc.get("events_requested").cloned().unwrap_or(json!([])),
            "events_delivered": doc.get("events_requested").cloned().unwrap_or(json!([]))
        }));
    }
    if req.path == "/ssf/verify" {
        let doc: Value = serde_json::from_str(&req.body).unwrap_or(json!({}));
        *tx.verify_state.lock().unwrap() = doc.get("state").and_then(|v| v.as_str()).unwrap_or("").to_string();
        *tx.verify_status.lock().unwrap() = 204;
        return (204, vec![], Vec::new());
    }
    if req.path.starts_with("/ssf/poll/") {
        let doc: Value = serde_json::from_str(&req.body).unwrap_or(json!({}));
        if let Some(list) = doc.get("ack").and_then(|v| v.as_array()) {
            let mut acked = tx.acked.lock().unwrap();
            let mut queue = tx.queue.lock().unwrap();
            for jti in list {
                let Some(jti) = jti.as_str() else { continue };
                acked.push(jti.to_string());
                queue.remove(jti);
            }
        }
        if let Some(errs) = doc.get("setErrs").and_then(|v| v.as_object()) {
            let mut stored = tx.errs.lock().unwrap();
            let mut queue = tx.queue.lock().unwrap();
            for (jti, err) in errs {
                stored.insert(jti.clone(), err.get("err").and_then(|v| v.as_str()).unwrap_or("").to_string());
                queue.remove(jti);
            }
        }
        let queue = tx.queue.lock().unwrap();
        let order = tx.order.lock().unwrap();
        let mut body = String::from("{\"sets\":{");
        let mut first = true;
        for jti in order.iter() {
            let Some(token) = queue.get(jti) else { continue };
            if !first {
                body.push(',');
            }
            first = false;
            body.push_str(&serde_json::to_string(jti).unwrap());
            body.push(':');
            body.push_str(&serde_json::to_string(token).unwrap());
        }
        body.push_str("},\"moreAvailable\":false}");
        return (200, vec![("Content-Type".into(), "application/json".into())], body.into_bytes());
    }
    json_res(404, json!({"error": "not_found"}))
}

pub(crate) fn deliver(tx: &Transmitter, event_type: &str, sub_id: Value, extra: Value, key: Option<&RsaPrivateKey>) -> String {
    let mut buf = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    let jti = format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]);
    let mut event = json!({"event_timestamp": 1});
    if let Some(obj) = extra.as_object() {
        for (k, v) in obj {
            event[k] = v.clone();
        }
    }
    let payload = json!({
        "iss": tx.url,
        "aud": "my-app",
        "jti": jti,
        "iat": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        "sub_id": sub_id,
        "events": {event_type: event}
    });
    let token = sign_set(&payload, key.unwrap_or(&ssf_keys().private), json!({"alg": "RS256", "kid": "k1", "typ": "secevent+jwt"}));
    tx.queue.lock().unwrap().insert(jti.clone(), token);
    tx.order.lock().unwrap().push(jti.clone());
    jti
}

#[test]
fn verifies_a_set_against_the_jwks() {
    let keys = ssf_keys();
    let (_header, payload) = verify_compact_jws(&sign_set(&json!({"a": 1}), &keys.private, json!({"alg": "RS256", "kid": "k1", "typ": "secevent+jwt"})), &[keys.jwk.clone()]).unwrap();
    assert_eq!(payload.get("a").and_then(|v| v.as_i64()).or_else(|| payload.get("a").and_then(|v| v.as_u64().map(|n| n as i64))), Some(1));
    let err = verify_compact_jws(&sign_set(&json!({"a": 1}), &keys.other, json!({"alg": "RS256", "kid": "k1"})), &[keys.jwk.clone()]).unwrap_err();
    assert!(err.to_string().contains("does not verify"), "{err}");
    let err = verify_compact_jws(&sign_set(&json!({"a": 1}), &keys.private, json!({"alg": "RS256", "kid": "nope"})), &[keys.jwk.clone()]).unwrap_err();
    assert!(err.to_string().contains("kid nope"), "{err}");
    let err = verify_compact_jws(&sign_set(&json!({"a": 1}), &keys.private, json!({"alg": "none"})), &[keys.jwk.clone()]).unwrap_err();
    assert!(err.to_string().contains("does not verify"), "{err}");
}

#[test]
fn reads_subject_forms() {
    assert_eq!(Event::get("sessionRevoked"), "https://schemas.openid.net/secevent/caep/event-type/session-revoked");
    assert_eq!(Event::get("credentialCompromise"), "https://schemas.openid.net/secevent/risc/event-type/credential-compromise");
    let complex = json!({
        "format": "complex",
        "user": {"format": "iss_sub", "iss": "https://i", "sub": "urn:uuid:a"},
        "session": {"format": "opaque", "id": "S1"}
    });
    let got = subject_of(complex.as_object(), "https://i");
    assert_eq!(got.get("person").map(String::as_str), Some("urn:uuid:a"));
    assert_eq!(got.get("idpSession").map(String::as_str), Some("S1"));
    assert_eq!(got.len(), 2);
    let other = json!({"format": "iss_sub", "iss": "https://other", "sub": "urn:uuid:a"});
    assert!(subject_of(other.as_object(), "https://i").is_empty());
    let email = json!({"format": "email", "email": "A@x.com"});
    let got = subject_of(email.as_object(), "https://i");
    assert_eq!(got.get("email").map(String::as_str), Some("A@x.com"));
    assert_eq!(got.len(), 1);
}

#[test]
fn polls_and_ends_only_the_named_session() {
    let stub = start_transmitter();
    let ended = std::sync::Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
    let seen = std::sync::Arc::new(Mutex::new(Vec::<crate::SignalEvent>::new()));
    let ended_cb = std::sync::Arc::clone(&ended);
    let receiver = SignalsReceiver::new(stub.url.as_str(), std::sync::Arc::new(move |ids, _event| {
        ended_cb.lock().unwrap().push(ids);
    }), ReceiverOptions {
        headers: Some(std::sync::Arc::new(|| vec![("authorization".into(), "Bearer app-token".into())])),
        poll_interval_ms: 60_000,
        ..ReceiverOptions::default()
    }).unwrap();
    let seen_cb = std::sync::Arc::clone(&seen);
    receiver.on("*", move |event| seen_cb.lock().unwrap().push(event));
    receiver.start().unwrap();
    receiver.stop();
    assert_eq!(*stub.created.lock().unwrap(), 1);
    assert_eq!(stub.authorization.lock().unwrap().as_str(), "Bearer app-token");
    assert_eq!(receiver.stream().unwrap().get("stream_id").and_then(|v| v.as_str()), Some("s1"));
    receiver.track(json!({"local_id": "L-a1", "person": "urn:uuid:alice", "email": "alice@example.com", "idp_session": "IDP-A1"}).as_object().cloned().unwrap());
    receiver.track(json!({"local_id": "L-a2", "person": "urn:uuid:alice", "email": "alice@example.com", "idp_session": "IDP-A2"}).as_object().cloned().unwrap());
    receiver.track(json!({"local_id": "L-b1", "person": "urn:uuid:bob", "email": "bob@example.com", "idp_session": "IDP-B1"}).as_object().cloned().unwrap());
    let revoked = deliver(stub, &Event::get("sessionRevoked"), json!({"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:alice"}, "session": {"format": "opaque", "id": "IDP-A1"}}), json!({}), None);
    deliver(stub, &Event::get("credentialChange"), json!({"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:bob"}), json!({"credential_type": "password"}), None);
    receiver.poll_once().unwrap();
    let got_ended = ended.lock().unwrap().clone();
    assert_eq!(got_ended, vec![vec!["L-a1".to_string()]]);
    let got_seen = seen.lock().unwrap().clone();
    assert_eq!(got_seen.len(), 2);
    assert!(got_seen[0].ended);
    assert_eq!(got_seen[1].event_type, Event::get("credentialChange"));
    assert!(!got_seen[1].ended);
    receiver.poll_once().unwrap();
    let acked = stub.acked.lock().unwrap().clone();
    assert_eq!(acked.first().map(String::as_str), Some(revoked.as_str()));
    assert_eq!(acked.iter().filter(|item| *item == &revoked).count(), 1);
    let bad = deliver(stub, &Event::get("accountDisabled"), json!({"format": "email", "email": "alice@example.com"}), json!({}), Some(&ssf_keys().other));
    receiver.poll_once().unwrap();
    receiver.poll_once().unwrap();
    assert_eq!(stub.errs.lock().unwrap().get(&bad).map(String::as_str), Some("invalid_key"));
    receiver.verify("abc").unwrap();
    assert_eq!(stub.verify_state.lock().unwrap().as_str(), "abc");
    assert_eq!(*stub.verify_status.lock().unwrap(), 204);
    receiver.stop();
}

#[test]
fn oidc_error_is_exported() {
    let err = OidcError::new("config", "signals must be true or false");
    assert_eq!(err.code, "config");
    assert_eq!(err.to_string(), "signals must be true or false");
}
