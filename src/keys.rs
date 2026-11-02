// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use hmac::{Hmac, Mac};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use sha2::{Sha256, Sha384, Sha512};

use crate::b64::b64url_decode;
use crate::error::OidcError;
use crate::value::{map_str, JsonMap};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

#[derive(Clone)]
pub enum PrivateKey {
    Rsa(RsaPrivateKey),
}

#[derive(Clone)]
pub enum PublicKey {
    Rsa(RsaPublicKey),
}

pub const ASYMMETRIC: &[&str] = &["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519"];

pub const SUPPORTED_JWS: &[&str] = &["RS256", "RS384", "RS512"];

fn hash_name(alg: &str) -> &'static str {
    if alg.contains("384") {
        "sha384"
    } else if alg.contains("512") {
        "sha512"
    } else {
        "sha256"
    }
}

pub fn load_private_key(pem_text: &str, alg: &str) -> Result<PrivateKey, OidcError> {
    if !matches!(alg, "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512") {
        return Err(OidcError::new("config", format!("the private key could not be read as {alg}: unsupported algorithm")));
    }
    let key = RsaPrivateKey::from_pkcs8_pem(pem_text)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem_text))
        .map_err(|err| OidcError::new("config", format!("the private key could not be read as {alg}: {err}")))?;
    Ok(PrivateKey::Rsa(key))
}

pub fn sign_jws(key: &PrivateKey, alg: &str, input: &[u8]) -> Result<Vec<u8>, OidcError> {
    let PrivateKey::Rsa(private) = key;
    if !alg.starts_with("RS") && !alg.starts_with("PS") {
        return Err(OidcError::new("protocol", "the client assertion could not be signed: unsupported algorithm"));
    }
    if alg.starts_with("PS") {
        return Err(OidcError::new("protocol", "the client assertion could not be signed: PSS is not implemented"));
    }
    let mut rng = rand::thread_rng();
    let bytes = match hash_name(alg) {
        "sha384" => SigningKey::<Sha384>::new(private.clone()).sign_with_rng(&mut rng, input).to_vec(),
        "sha512" => SigningKey::<Sha512>::new(private.clone()).sign_with_rng(&mut rng, input).to_vec(),
        _ => SigningKey::<Sha256>::new(private.clone()).sign_with_rng(&mut rng, input).to_vec(),
    };
    Ok(bytes)
}

pub fn verify_signature(key: &PublicKey, alg: &str, input: &[u8], signature: &[u8]) -> bool {
    if alg.starts_with("HS") {
        return false;
    }
    let PublicKey::Rsa(public) = key;
    if !alg.starts_with("RS") {
        return false;
    }
    let Ok(sig) = Signature::try_from(signature) else {
        return false;
    };
    match hash_name(alg) {
        "sha384" => VerifyingKey::<Sha384>::new(public.clone()).verify(input, &sig).is_ok(),
        "sha512" => VerifyingKey::<Sha512>::new(public.clone()).verify(input, &sig).is_ok(),
        _ => VerifyingKey::<Sha256>::new(public.clone()).verify(input, &sig).is_ok(),
    }
}

pub fn verify_hmac(secret: &[u8], alg: &str, input: &[u8], signature: &[u8]) -> bool {
    let check = |mac: Vec<u8>| mac.len() == signature.len() && mac.iter().zip(signature).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    match hash_name(alg) {
        "sha384" => HmacSha384::new_from_slice(secret).map(|mut mac| { mac.update(input); check(mac.finalize().into_bytes().to_vec()) }).unwrap_or(false),
        "sha512" => HmacSha512::new_from_slice(secret).map(|mut mac| { mac.update(input); check(mac.finalize().into_bytes().to_vec()) }).unwrap_or(false),
        _ => HmacSha256::new_from_slice(secret).map(|mut mac| { mac.update(input); check(mac.finalize().into_bytes().to_vec()) }).unwrap_or(false),
    }
}

pub fn public_key_from_jwk(jwk: &JsonMap) -> Result<PublicKey, OidcError> {
    let kty = map_str(jwk, "kty");
    match kty.as_str() {
        "RSA" => {
            let n_raw = jwk.get("n").and_then(|v| v.as_str()).ok_or_else(|| OidcError::new("signature", "missing modulus"))?;
            let e_raw = jwk.get("e").and_then(|v| v.as_str()).ok_or_else(|| OidcError::new("signature", "missing modulus"))?;
            let nb = b64url_decode(n_raw, "n")?;
            let eb = b64url_decode(e_raw, "e")?;
            let e = BigUint::from_bytes_be(&eb);
            if e.bits() > 31 || e == BigUint::from(0u32) {
                return Err(OidcError::new("signature", "bad exponent"));
            }
            let key = RsaPublicKey::new(BigUint::from_bytes_be(&nb), e).map_err(|err| {
                OidcError::new("signature", format!("the transmitter's key {} cannot be read: {err}", map_str(jwk, "kid")))
            })?;
            Ok(PublicKey::Rsa(key))
        }
        "EC" | "OKP" => Err(OidcError::new("signature", format!("the key type {kty} cannot be read"))),
        _ => Err(OidcError::new("signature", format!("the key type {kty} cannot be read"))),
    }
}
