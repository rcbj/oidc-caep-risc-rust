// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use hmac::{Hmac, Mac};
use rsa::pkcs1::DecodeRsaPrivateKey;
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

/// A verification key read from a JWK. Each variant verifies only the algorithms of its own family.
#[derive(Clone)]
pub enum PublicKey {
    Rsa(RsaPublicKey),
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    P521(p521::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

/// Every asymmetric JWS algorithm this crate verifies (ID tokens, signed UserInfo, SETs).
pub const ASYMMETRIC: &[&str] = &["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519"];

/// The HMAC algorithms an ID token may use when the application names one.
pub const SYMMETRIC: &[&str] = &["HS256", "HS384", "HS512"];

/// The algorithms a Security Event Token may be signed with.
pub const SUPPORTED_JWS: &[&str] = ASYMMETRIC;

fn hash_name(alg: &str) -> &'static str {
    if alg.contains("384") {
        "sha384"
    } else if alg.contains("512") {
        "sha512"
    } else {
        "sha256"
    }
}

/// The JWK `kty` an algorithm's key has.
pub fn kty_for(alg: &str) -> Option<&'static str> {
    if alg.starts_with("RS") || alg.starts_with("PS") {
        Some("RSA")
    } else if alg.starts_with("ES") {
        Some("EC")
    } else if alg == "EdDSA" || alg == "Ed25519" {
        Some("OKP")
    } else if alg.starts_with("HS") {
        Some("oct")
    } else {
        None
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
    let mut rng = rand::thread_rng();
    let bytes = if alg.starts_with("RS") {
        match hash_name(alg) {
            "sha384" => rsa::pkcs1v15::SigningKey::<Sha384>::new(private.clone()).sign_with_rng(&mut rng, input).to_vec(),
            "sha512" => rsa::pkcs1v15::SigningKey::<Sha512>::new(private.clone()).sign_with_rng(&mut rng, input).to_vec(),
            _ => rsa::pkcs1v15::SigningKey::<Sha256>::new(private.clone()).sign_with_rng(&mut rng, input).to_vec(),
        }
    } else if alg.starts_with("PS") {
        match hash_name(alg) {
            "sha384" => rsa::pss::SigningKey::<Sha384>::new(private.clone()).sign_with_rng(&mut rng, input).to_vec(),
            "sha512" => rsa::pss::SigningKey::<Sha512>::new(private.clone()).sign_with_rng(&mut rng, input).to_vec(),
            _ => rsa::pss::SigningKey::<Sha256>::new(private.clone()).sign_with_rng(&mut rng, input).to_vec(),
        }
    } else {
        return Err(OidcError::new("protocol", "the client assertion could not be signed: unsupported algorithm"));
    };
    Ok(bytes)
}

fn verify_rsa(public: &RsaPublicKey, alg: &str, input: &[u8], signature: &[u8]) -> bool {
    if alg.starts_with("RS") {
        let Ok(sig) = rsa::pkcs1v15::Signature::try_from(signature) else {
            return false;
        };
        return match hash_name(alg) {
            "sha384" => rsa::pkcs1v15::VerifyingKey::<Sha384>::new(public.clone()).verify(input, &sig).is_ok(),
            "sha512" => rsa::pkcs1v15::VerifyingKey::<Sha512>::new(public.clone()).verify(input, &sig).is_ok(),
            _ => rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public.clone()).verify(input, &sig).is_ok(),
        };
    }
    if alg.starts_with("PS") {
        // RFC 7518 section 3.5: MGF1 with the same hash, and a salt as long as the hash.
        let Ok(sig) = rsa::pss::Signature::try_from(signature) else {
            return false;
        };
        return match hash_name(alg) {
            "sha384" => rsa::pss::VerifyingKey::<Sha384>::new(public.clone()).verify(input, &sig).is_ok(),
            "sha512" => rsa::pss::VerifyingKey::<Sha512>::new(public.clone()).verify(input, &sig).is_ok(),
            _ => rsa::pss::VerifyingKey::<Sha256>::new(public.clone()).verify(input, &sig).is_ok(),
        };
    }
    false
}

/// Verifies a JWS signature. The key's type must be the algorithm's: an RSA key never
/// verifies an ES256 signature, and a P-256 key verifies only ES256.
pub fn verify_signature(key: &PublicKey, alg: &str, input: &[u8], signature: &[u8]) -> bool {
    match (key, alg) {
        (PublicKey::Rsa(public), _) => verify_rsa(public, alg, input, signature),
        // RFC 7518 section 3.4: R and S, each the curve's size, concatenated (not DER).
        (PublicKey::P256(public), "ES256") => p256::ecdsa::Signature::from_slice(signature).is_ok_and(|sig| public.verify(input, &sig).is_ok()),
        (PublicKey::P384(public), "ES384") => p384::ecdsa::Signature::from_slice(signature).is_ok_and(|sig| public.verify(input, &sig).is_ok()),
        (PublicKey::P521(public), "ES512") => p521::ecdsa::Signature::from_slice(signature).is_ok_and(|sig| public.verify(input, &sig).is_ok()),
        (PublicKey::Ed25519(public), "EdDSA" | "Ed25519") => ed25519_dalek::Signature::from_slice(signature).is_ok_and(|sig| public.verify_strict(input, &sig).is_ok()),
        _ => false,
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

fn coordinate(jwk: &JsonMap, name: &str, size: usize) -> Result<Vec<u8>, OidcError> {
    let raw = jwk.get(name).and_then(|v| v.as_str()).ok_or_else(|| OidcError::new("signature", format!("the key {} has no {name}", map_str(jwk, "kid"))))?;
    let bytes = b64url_decode(raw, name)?;
    if bytes.len() != size {
        return Err(OidcError::new("signature", format!("the key {} has a {name} of the wrong length", map_str(jwk, "kid"))));
    }
    Ok(bytes)
}

fn sec1_point(jwk: &JsonMap, size: usize) -> Result<Vec<u8>, OidcError> {
    let mut point = vec![0x04u8];
    point.extend(coordinate(jwk, "x", size)?);
    point.extend(coordinate(jwk, "y", size)?);
    Ok(point)
}

pub fn public_key_from_jwk(jwk: &JsonMap) -> Result<PublicKey, OidcError> {
    let kty = map_str(jwk, "kty");
    let unreadable = |err: String| OidcError::new("signature", format!("the key {} cannot be read: {err}", map_str(jwk, "kid")));
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
            let key = RsaPublicKey::new(BigUint::from_bytes_be(&nb), e).map_err(|err| unreadable(err.to_string()))?;
            Ok(PublicKey::Rsa(key))
        }
        "EC" => match map_str(jwk, "crv").as_str() {
            "P-256" => p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1_point(jwk, 32)?).map(PublicKey::P256).map_err(|err| unreadable(err.to_string())),
            "P-384" => p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1_point(jwk, 48)?).map(PublicKey::P384).map_err(|err| unreadable(err.to_string())),
            "P-521" => p521::ecdsa::VerifyingKey::from_sec1_bytes(&sec1_point(jwk, 66)?).map(PublicKey::P521).map_err(|err| unreadable(err.to_string())),
            other => Err(OidcError::new("signature", format!("the EC curve {other} cannot be read"))),
        },
        "OKP" => {
            if map_str(jwk, "crv") != "Ed25519" {
                return Err(OidcError::new("signature", format!("the OKP curve {} cannot be read", map_str(jwk, "crv"))));
            }
            let x = coordinate(jwk, "x", 32)?;
            let bytes: [u8; 32] = x.try_into().map_err(|_| unreadable("x is not 32 bytes".into()))?;
            ed25519_dalek::VerifyingKey::from_bytes(&bytes).map(PublicKey::Ed25519).map_err(|err| unreadable(err.to_string()))
        }
        _ => Err(OidcError::new("signature", format!("the key type {kty} cannot be read"))),
    }
}
