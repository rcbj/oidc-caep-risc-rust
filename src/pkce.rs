// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use sha2::{Digest, Sha256};

use crate::b64::b64url_encode;

/// 32 random bytes, base64url. A PKCE verifier and a state or nonce.
pub fn random_token() -> String {
    let mut buf = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    b64url_encode(&buf)
}

/// RFC 7636 S256: base64url(SHA-256(verifier)), with no padding.
pub fn code_challenge_s256(verifier: &str) -> String {
    let sum = Sha256::digest(verifier.as_bytes());
    b64url_encode(&sum)
}
