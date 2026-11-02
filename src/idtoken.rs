// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::b64::{b64url_decode, b64url_encode};
use crate::error::OidcError;
use crate::http::send;
use crate::keys::{public_key_from_jwk, verify_hmac, verify_signature};
use crate::value::{as_f64, as_map_owned, contains_str, map_str, sprint, JsonMap};

const NOT_ID: &[&str] = &[
    "at+jwt",
    "application/at+jwt",
    "logout+jwt",
    "secevent+jwt",
    "dpop+jwt",
    "token-introspection+jwt",
    "software-statement+jwt",
    "jwt-bearer",
];

pub fn same_text(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes().zip(right.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// The left half of the digest the algorithm names, base64url, no padding.
pub fn hash_claim(value: &str, alg: &str) -> String {
    let full: Vec<u8> = if alg == "EdDSA" || alg == "Ed25519" || alg.contains("512") {
        Sha512::digest(value.as_bytes()).to_vec()
    } else if alg.contains("384") {
        Sha384::digest(value.as_bytes()).to_vec()
    } else {
        Sha256::digest(value.as_bytes()).to_vec()
    };
    b64url_encode(&full[..full.len() / 2])
}

pub struct TokenChecks {
    pub issuer: String,
    pub client_id: String,
    pub algorithms: Vec<String>,
    pub jwks: Vec<JsonMap>,
    pub clock_tolerance_sec: f64,
    pub max_id_token_age_sec: Option<f64>,
    pub client_secret: String,
    pub nonce: Option<String>,
    pub access_token: String,
    pub code: String,
    pub previous_sub: Option<String>,
    pub max_age: Option<f64>,
}

impl Default for TokenChecks {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            client_id: String::new(),
            algorithms: Vec::new(),
            jwks: Vec::new(),
            clock_tolerance_sec: 0.0,
            max_id_token_age_sec: None,
            client_secret: String::new(),
            nonce: None,
            access_token: String::new(),
            code: String::new(),
            previous_sub: None,
            max_age: None,
        }
    }
}

fn now_sec() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn decode_part(token: &str, index: usize, what: &str) -> Result<JsonMap, OidcError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(OidcError::new("signature", "the ID token is not a compact JWS: not a compact JWS"));
    }
    let raw = b64url_decode(parts[index], what).map_err(|err| OidcError::new("signature", format!("the ID token is not a compact JWS: {err}")))?;
    let parsed: Value = serde_json::from_slice(&raw).map_err(|err| OidcError::new("signature", format!("the ID token is not a compact JWS: {err}")))?;
    as_map_owned(parsed).ok_or_else(|| OidcError::new("signature", "the ID token is not a compact JWS: not a JSON object"))
}

fn candidates<'a>(jwks: &'a [JsonMap], alg: &str, kid: &str) -> Vec<&'a JsonMap> {
    let kty = if alg.starts_with("RS") || alg.starts_with("PS") {
        "RSA"
    } else if alg.starts_with("ES") {
        "EC"
    } else if alg == "EdDSA" || alg == "Ed25519" {
        "OKP"
    } else if alg.starts_with("HS") {
        "oct"
    } else {
        return Vec::new();
    };
    jwks.iter()
        .filter(|jwk| kid.is_empty() || map_str(jwk, "kid") == kid)
        .filter(|jwk| map_str(jwk, "kty") == kty)
        .filter(|jwk| {
            let use_ = jwk.get("use").map(sprint).unwrap_or_default();
            use_.is_empty() || use_ == "sig"
        })
        .filter(|jwk| {
            let named = jwk.get("alg").map(sprint).unwrap_or_default();
            named.is_empty() || named == alg
        })
        .collect()
}

fn signature_ok(token: &str, alg: &str, jwks: &[JsonMap], secret: &str) -> Result<bool, OidcError> {
    let parts: Vec<&str> = token.split('.').collect();
    let signing = format!("{}.{}", parts[0], parts[1]);
    let sig = b64url_decode(parts[2], "signature").map_err(|err| OidcError::new("signature", format!("the ID token is not a compact JWS: {err}")))?;
    if alg.starts_with("HS") {
        return Ok(verify_hmac(secret.as_bytes(), alg, signing.as_bytes(), &sig));
    }
    let header = decode_part(token, 0, "header")?;
    let kid = header.get("kid").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let keys = candidates(jwks, alg, &kid);
    if keys.is_empty() {
        return Err(OidcError::new("signature", "signature verification failed: no applicable key"));
    }
    for jwk in keys {
        let Ok(key) = public_key_from_jwk(jwk) else {
            continue;
        };
        if verify_signature(&key, alg, signing.as_bytes(), &sig) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn check_hash(claim: Option<&Value>, value: &str, alg: &str, name: &str) -> Result<(), OidcError> {
    let Some(claim) = claim else {
        return Ok(());
    };
    if claim.is_null() {
        return Ok(());
    }
    let Some(text) = claim.as_str() else {
        return Err(OidcError::new("validation", format!("the ID token's {name} does not match")));
    };
    if !same_text(text, &hash_claim(value, alg)) {
        return Err(OidcError::new("validation", format!("the ID token's {name} does not match")));
    }
    Ok(())
}

pub fn validate_id_token(token: &str, checks: &TokenChecks) -> Result<JsonMap, OidcError> {
    let header = decode_part(token, 0, "header")?;
    let alg = map_str(&header, "alg");
    if !contains_str(&checks.algorithms, &alg) {
        let shown = if alg.is_empty() { "(no alg)".to_string() } else { alg.clone() };
        return Err(OidcError::new("signature", format!("the ID token is signed with {shown}, which this client does not accept")));
    }
    if header.get("crit").is_some_and(|v| !v.is_null()) {
        return Err(OidcError::new("validation", "the ID token has a crit header this client does not understand"));
    }
    if let Some(raw_typ) = header.get("typ").filter(|v| !v.is_null()) {
        let typ = sprint(raw_typ).to_ascii_lowercase();
        if !typ.is_empty() && ((typ != "jwt" && typ != "application/jwt") || NOT_ID.contains(&typ.as_str())) {
            return Err(OidcError::new("validation", format!("the ID token typ is {raw_typ}, not an ID token")));
        }
    }
    if alg.starts_with("HS") && checks.client_secret.is_empty() {
        return Err(OidcError::new("config", format!("{alg} ID tokens need the client secret")));
    }
    let payload = decode_part(token, 1, "payload")?;
    let ok = signature_ok(token, &alg, &checks.jwks, &checks.client_secret)?;
    if !ok {
        return Err(OidcError::new("signature", "the ID token was refused: signature verification failed"));
    }
    if map_str(&payload, "iss") != checks.issuer {
        return Err(OidcError::new("validation", "the ID token was refused: issuer mismatch"));
    }
    let audiences = match payload.get("aud") {
        Some(Value::Array(list)) => list.iter().map(sprint).collect::<Vec<_>>(),
        Some(Value::Null) | None => vec![String::new()],
        Some(other) => vec![sprint(other)],
    };
    if !contains_str(&audiences, &checks.client_id) {
        return Err(OidcError::new("validation", "the ID token audience does not include this client"));
    }
    let now = now_sec();
    let tolerance = checks.clock_tolerance_sec;
    let exp = payload.get("exp").and_then(as_f64).ok_or_else(|| OidcError::new("validation", "the ID token was refused: exp is missing"))?;
    if exp + tolerance < now {
        return Err(OidcError::new("validation", "the ID token was refused: exp expired"));
    }
    if let Some(nbf) = payload.get("nbf").and_then(as_f64) {
        if nbf - tolerance > now {
            return Err(OidcError::new("validation", "the ID token was refused: nbf is in the future"));
        }
    }
    if let Some(max_age) = checks.max_id_token_age_sec {
        let iat = payload.get("iat").and_then(as_f64).ok_or_else(|| OidcError::new("validation", "the ID token was refused: iat is missing"))?;
        if (now - iat) - tolerance > max_age {
            return Err(OidcError::new("validation", "the ID token was refused: iat is too old"));
        }
    }
    let sub = payload.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    if sub.is_empty() {
        return Err(OidcError::new("validation", "the ID token has no sub"));
    }
    if audiences.len() > 1 && map_str(&payload, "azp") != checks.client_id {
        return Err(OidcError::new("validation", "an ID token with several audiences must name this client as azp"));
    }
    if let Some(azp) = payload.get("azp").filter(|v| !v.is_null()) {
        if sprint(azp) != checks.client_id {
            return Err(OidcError::new("validation", format!("the ID token azp is {azp}, not {}", checks.client_id)));
        }
    }
    if let Some(nonce) = &checks.nonce {
        let got = payload.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
        if !same_text(got, nonce) {
            return Err(OidcError::new("validation", "the ID token nonce does not match this sign-in"));
        }
    }
    if let Some(previous) = &checks.previous_sub {
        if map_str(&payload, "sub") != *previous {
            return Err(OidcError::new("validation", "the refreshed ID token is for a different subject"));
        }
    }
    if !checks.access_token.is_empty() {
        check_hash(payload.get("at_hash"), &checks.access_token, &alg, "at_hash")?;
    }
    if !checks.code.is_empty() {
        check_hash(payload.get("c_hash"), &checks.code, &alg, "c_hash")?;
    }
    if let Some(max_age) = checks.max_age {
        let auth_time = payload.get("auth_time").and_then(as_f64).ok_or_else(|| OidcError::new("validation", "max_age was requested and the ID token has no auth_time"))?;
        if auth_time < now_sec().floor() - max_age - tolerance {
            return Err(OidcError::new("validation", "the ID token auth_time is older than max_age"));
        }
    }
    Ok(payload)
}

pub fn fetch_jwks(jwks_uri: &str, ca: Option<&str>) -> Result<Vec<JsonMap>, OidcError> {
    let answer = send(jwks_uri, "GET", &[("accept".into(), "application/json".into())], None, ca, "discovery")?;
    if answer.status != 200 {
        return Err(OidcError::new("discovery", format!("the JWKS at {jwks_uri} answered {}", answer.status)));
    }
    let body: Value = serde_json::from_str(&answer.body).map_err(|_| OidcError::new("discovery", format!("the JWKS at {jwks_uri} is not JSON")))?;
    let doc = as_map_owned(body).ok_or_else(|| OidcError::new("discovery", format!("the JWKS at {jwks_uri} has no keys")))?;
    let list = doc.get("keys").and_then(|v| v.as_array()).ok_or_else(|| OidcError::new("discovery", format!("the JWKS at {jwks_uri} has no keys")))?;
    let mut out = Vec::new();
    for item in list {
        let key = as_map_owned(item.clone()).ok_or_else(|| OidcError::new("discovery", format!("the JWKS at {jwks_uri} has no keys")))?;
        out.push(key);
    }
    Ok(out)
}
