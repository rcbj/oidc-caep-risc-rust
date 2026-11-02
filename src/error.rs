// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::fmt;

/// Every failure this crate reports.
/// `code` is config, discovery, protocol, validation, signature, or ssf.
#[derive(Debug)]
pub struct OidcError {
    pub code: String,
    pub message: String,
    pub oauth_error: String,
}

impl OidcError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self { code: code.to_string(), message: message.into(), oauth_error: String::new() }
    }

    pub fn oauth(code: &str, message: impl Into<String>, oauth: &str) -> Self {
        Self { code: code.to_string(), message: message.into(), oauth_error: oauth.to_string() }
    }
}

impl fmt::Display for OidcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for OidcError {}

pub fn err(code: &str, message: impl Into<String>) -> OidcError {
    OidcError::new(code, message)
}

pub fn fmt_err(code: &str, message: String) -> OidcError {
    OidcError::new(code, message)
}
