// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! DPoP (RFC 9449): the relying party's ES256 proof key, its proofs, and the
//! latest `DPoP-Nonce` each server origin gave.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::Generate;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::b64::b64url_encode;
use crate::error::OidcError;
use crate::pkce::random_token;

/// The one algorithm this crate signs DPoP proofs with.
pub const DPOP_ALG: &str = "ES256";

/// An ES256 (P-256) proof key and the nonces servers have handed out.
pub struct Dpop {
    key: SigningKey,
    jwk: Value,
    thumbprint: String,
    nonces: Mutex<HashMap<String, String>>,
}

impl Dpop {
    /// A key pair generated now and held in memory only.
    pub fn generate() -> Self {
        Self::from_key(SigningKey::generate())
    }

    /// A P-256 private key in PEM (PKCS #8 `PRIVATE KEY` or SEC 1 `EC PRIVATE KEY`).
    pub fn from_pem(pem: &str) -> Result<Self, OidcError> {
        let key = SigningKey::from_pkcs8_pem(pem)
            .or_else(|_| p256::SecretKey::from_sec1_pem(pem).map(SigningKey::from))
            .map_err(|_| OidcError::new("config", "dpopKey is not a P-256 (ES256) private key in PEM"))?;
        Ok(Self::from_key(key))
    }

    fn from_key(key: SigningKey) -> Self {
        let point = key.verifying_key().to_sec1_point(false);
        let x = b64url_encode(point.x().map(|v| v.as_slice()).unwrap_or_default());
        let y = b64url_encode(point.y().map(|v| v.as_slice()).unwrap_or_default());
        // RFC 7638: the required members only, in lexicographic order, no white space.
        let canonical = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
        let thumbprint = b64url_encode(&Sha256::digest(canonical.as_bytes()));
        Self { key, jwk: json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}), thumbprint, nonces: Mutex::new(HashMap::new()) }
    }

    /// The JWK SHA-256 thumbprint, sent as `dpop_jkt`.
    pub fn jkt(&self) -> &str {
        &self.thumbprint
    }

    /// The public key as a JWK (the proof's `jwk` header).
    pub fn public_jwk(&self) -> &Value {
        &self.jwk
    }

    /// A proof for one request. `access_token` adds `ath` (a resource request).
    /// The latest nonce this server's origin gave goes in `nonce`.
    pub fn proof(&self, method: &str, url: &str, access_token: Option<&str>) -> Result<String, OidcError> {
        let htu = htu(url)?;
        let iat = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let header = json!({"typ": "dpop+jwt", "alg": DPOP_ALG, "jwk": self.jwk});
        let mut claims = json!({"jti": random_token(), "htm": method.to_ascii_uppercase(), "htu": htu, "iat": iat});
        if let Some(nonce) = self.nonce_for(url) {
            claims["nonce"] = Value::String(nonce);
        }
        if let Some(token) = access_token {
            claims["ath"] = Value::String(b64url_encode(&Sha256::digest(token.as_bytes())));
        }
        let encode = |value: &Value| b64url_encode(&serde_json::to_vec(value).unwrap_or_default());
        let signing = format!("{}.{}", encode(&header), encode(&claims));
        let signature: Signature = self.key.sign(signing.as_bytes());
        Ok(format!("{signing}.{}", b64url_encode(&signature.to_bytes())))
    }

    /// Remembers the latest nonce a server gave, per origin.
    pub fn remember_nonce(&self, url: &str, nonce: &str) {
        let nonce = nonce.trim();
        if nonce.is_empty() {
            return;
        }
        if let Some(origin) = origin_of(url) {
            self.nonces.lock().unwrap_or_else(|e| e.into_inner()).insert(origin, nonce.to_string());
        }
    }

    pub fn nonce_for(&self, url: &str) -> Option<String> {
        let origin = origin_of(url)?;
        self.nonces.lock().unwrap_or_else(|e| e.into_inner()).get(&origin).cloned()
    }
}

/// `htu`: the request URL without its query and fragment.
pub fn htu(url: &str) -> Result<String, OidcError> {
    let mut parts = url::Url::parse(url).map_err(|_| OidcError::new("protocol", format!("{url} is not a URL")))?;
    parts.set_query(None);
    parts.set_fragment(None);
    Ok(parts.to_string())
}

/// The scheme, host and port a nonce belongs to.
pub fn origin_of(url: &str) -> Option<String> {
    let parts = url::Url::parse(url).ok()?;
    Some(parts.origin().ascii_serialization())
}

/// A resource server's 401 asking for a nonce: `WWW-Authenticate: DPoP error="use_dpop_nonce"`.
pub fn resource_wants_nonce(status: u16, www_authenticate: &str) -> bool {
    if status != 401 {
        return false;
    }
    www_authenticate.to_ascii_lowercase().contains("use_dpop_nonce")
}
