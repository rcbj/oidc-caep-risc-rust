// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::error::OidcError;

pub fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64url_decode(value: &str, what: &str) -> Result<Vec<u8>, OidcError> {
    if value.chars().any(|c| !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_')) {
        return Err(OidcError::new("signature", format!("{what} is not base64url")));
    }
    URL_SAFE_NO_PAD.decode(value).map_err(|_| OidcError::new("signature", format!("{what} is not base64url")))
}
