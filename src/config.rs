// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Number, Value};

use crate::discovery::{issuer_from_metadata_url, validate_provider_metadata, DEFAULT_SCOPES};
use crate::error::OidcError;
use crate::value::{as_f64, as_map, as_string_list, is_exact_true, map_str, sprint, truthy, JsonMap};

pub type Resolved = JsonMap;

const AUTH_METHODS: &[&str] = &["client_secret_basic", "client_secret_post", "private_key_jwt"];

fn read_path(path: &str, base_dir: &str, what: &str) -> Result<String, OidcError> {
    let full = if Path::new(path).is_absolute() { PathBuf::from(path) } else { Path::new(base_dir).join(path) };
    let raw = fs::read_to_string(&full).map_err(|err| OidcError::new("config", format!("could not read {what} at {}: {err}", full.display())))?;
    Ok(raw.trim().to_string())
}

fn secret_value(raw: &str, base_dir: &str, what: &str) -> Result<String, OidcError> {
    if let Some(name) = raw.strip_prefix("env:") {
        let value = std::env::var(name).unwrap_or_default();
        if value.is_empty() {
            return Err(OidcError::new("config", format!("{what} reads {name}, and that variable is empty")));
        }
        return Ok(value);
    }
    if let Some(path) = raw.strip_prefix("file:") {
        return read_path(path, base_dir, what);
    }
    Ok(raw.to_string())
}

fn key_value(raw: &str, base_dir: &str, what: &str) -> Result<String, OidcError> {
    if raw.starts_with("env:") || raw.starts_with("file:") || raw.contains("-----BEGIN") {
        secret_value(raw, base_dir, what)
    } else {
        read_path(raw, base_dir, what)
    }
}

fn read_trust(raw: Option<&Value>, base_dir: &str) -> Option<String> {
    let value = raw.map(sprint).unwrap_or_default();
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.contains("-----BEGIN") {
        return Some(value.to_string());
    }
    if let Some(name) = value.strip_prefix("env:") {
        let got = std::env::var(name).unwrap_or_default();
        return if got.is_empty() { None } else { Some(got) };
    }
    let path = value.strip_prefix("file:").unwrap_or(value);
    if path.is_empty() {
        return None;
    }
    let full = if Path::new(path).is_absolute() { PathBuf::from(path) } else { Path::new(base_dir).join(path) };
    fs::read_to_string(full).ok()
}

fn signals_on(value: Option<&Value>) -> Result<bool, OidcError> {
    let Some(value) = value else {
        return Ok(true);
    };
    if value.is_null() || is_exact_true(value) {
        return Ok(true);
    }
    match value {
        Value::Bool(flag) => Ok(*flag),
        _ => Err(OidcError::new("config", "signals must be true or false")),
    }
}

fn is_loopback(hostname: &str) -> bool {
    matches!(hostname, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

fn check_redirect(value: &str, name: &str, allow_insecure: bool) -> Result<String, OidcError> {
    let parts = url::Url::parse(value).map_err(|_| OidcError::new("config", format!("{name} is not a URL: {value}")))?;
    if parts.scheme() != "http" && parts.scheme() != "https" || parts.host_str().is_none() {
        return Err(OidcError::new("config", format!("{name} is not a URL: {value}")));
    }
    if parts.scheme() == "https" || (parts.scheme() == "http" && (is_loopback(parts.host_str().unwrap_or("")) || allow_insecure)) {
        return Ok(value.to_string());
    }
    Err(OidcError::new("config", format!("{name} must use https, or http on loopback: {value}")))
}

fn first_string(raw: &JsonMap, keys: &[&str]) -> String {
    for key in keys {
        if let Some(value) = raw.get(*key).filter(|v| !v.is_null()) {
            return sprint(value);
        }
    }
    String::new()
}

/// Reads a configuration object and fills the defaults.
/// `signals` is omitted when CAEP and RISC are on, and present as false when they are off.
pub fn resolve_config(raw: &JsonMap, base_dir: &str) -> Result<Resolved, OidcError> {
    let client_id = first_string(raw, &["clientId", "client_id"]).trim().to_string();
    if client_id.is_empty() {
        return Err(OidcError::new("config", "client_id is required"));
    }
    let mut method = map_str(raw, "tokenEndpointAuthMethod");
    if method.is_empty() {
        method = "client_secret_basic".to_string();
    }
    if method == "none" {
        return Err(OidcError::new("config", "tokenEndpointAuthMethod \"none\" is a public client; this library authenticates a confidential client"));
    }
    if !AUTH_METHODS.contains(&method.as_str()) {
        return Err(OidcError::new("config", format!("tokenEndpointAuthMethod must be {}, not {method}", AUTH_METHODS.join(", "))));
    }
    let redirect_uri = first_string(raw, &["redirectUri", "redirect_uri"]).trim().to_string();
    if redirect_uri.is_empty() {
        return Err(OidcError::new("config", "redirectUri is required"));
    }
    let allow_insecure = raw.get("allowInsecure").is_some_and(is_exact_true);
    let signals = signals_on(raw.get("signals"))?;
    let scopes = if raw.get("scopes").is_none() || raw.get("scopes").is_some_and(|v| v.is_null()) {
        DEFAULT_SCOPES.trim().to_string()
    } else if let Some(list) = raw.get("scopes").and_then(as_string_list) {
        list.into_iter().map(|item| item.trim().to_string()).filter(|item| !item.is_empty()).collect::<Vec<_>>().join(" ")
    } else {
        sprint(raw.get("scopes").unwrap()).trim().to_string()
    };
    let scopes = if signals {
        scopes
    } else {
        scopes.split_whitespace().filter(|part| *part != "ssf.read" && *part != "ssf.manage").collect::<Vec<_>>().join(" ")
    };
    if !scopes.split_whitespace().any(|part| part == "openid") {
        return Err(OidcError::new("config", "scopes must include openid"));
    }
    let mut par = raw.get("par").filter(|v| !v.is_null()).map(sprint).unwrap_or_else(|| "auto".to_string());
    if par.is_empty() {
        par = "auto".to_string();
    }
    if par != "auto" && par != "always" && par != "never" {
        return Err(OidcError::new("config", "par must be auto, always, or never"));
    }
    let mut issuer = raw.get("issuer").filter(|v| !v.is_null()).map(|v| sprint(v).trim().to_string()).unwrap_or_default();
    if issuer.is_empty() {
        issuer.clear();
    }
    let metadata_url = raw.get("metadataUrl").filter(|v| !v.is_null()).map(|v| sprint(v).trim().to_string()).filter(|v| !v.is_empty());
    if let Some(metadata_url) = &metadata_url {
        let from_url = issuer_from_metadata_url(metadata_url)?;
        if !issuer.is_empty() && issuer != from_url {
            return Err(OidcError::new("config", format!("issuer {issuer} is not the issuer of {metadata_url} ({from_url})")));
        }
        issuer = from_url;
    }
    let mut metadata = None;
    if let Some(file) = raw.get("metadataFile").filter(|v| !v.is_null()).map(sprint).filter(|v| !v.is_empty()) {
        let full = if Path::new(&file).is_absolute() { PathBuf::from(&file) } else { Path::new(base_dir).join(&file) };
        let body = fs::read_to_string(&full).map_err(|err| OidcError::new("config", format!("could not read metadata at {}: {err}", full.display())))?;
        let parsed: Value = serde_json::from_str(&body).map_err(|err| OidcError::new("config", format!("could not read metadata at {}: {err}", full.display())))?;
        let doc = as_map(&parsed).ok_or_else(|| OidcError::new("config", format!("could not read metadata at {}: not an object", full.display())))?;
        let checked = validate_provider_metadata(doc, &issuer)?;
        issuer = map_str(&checked, "issuer");
        metadata = Some(checked);
    }
    if metadata_url.is_none() && metadata.is_none() {
        return Err(OidcError::new("config", "metadataUrl or metadataFile is required"));
    }
    let needs_secret = method != "private_key_jwt";
    let client_secret = if let Some(value) = raw.get("clientSecret").filter(|v| !v.is_null()).map(sprint).filter(|v| !v.is_empty()) {
        secret_value(&value, base_dir, "the client secret")?
    } else {
        String::new()
    };
    if needs_secret && client_secret.is_empty() {
        return Err(OidcError::new("config", format!("{method} needs clientSecret")));
    }
    let private_key = if let Some(value) = raw.get("privateKey").filter(|v| !v.is_null()).map(sprint).filter(|v| !v.is_empty()) {
        key_value(&value, base_dir, "the private key")?
    } else {
        String::new()
    };
    if method == "private_key_jwt" && private_key.is_empty() {
        return Err(OidcError::new("config", "private_key_jwt needs privateKey"));
    }
    let tls_ca = read_trust(raw.get("tlsCa"), base_dir);
    let post = first_string(raw, &["postLogoutRedirectUri", "post_logout_redirect_uri"]).trim().to_string();
    let mut ssf = None;
    if signals {
        if let Some(doc) = raw.get("ssf").and_then(as_map) {
            let transmitter = map_str(doc, "transmitter").trim().trim_end_matches('/').to_string();
            if !transmitter.is_empty() {
                if !transmitter.starts_with("http://") && !transmitter.starts_with("https://") {
                    return Err(OidcError::new("config", "ssf.transmitter must be an http(s) URL"));
                }
                let mut block = JsonMap::new();
                block.insert("transmitter".into(), Value::String(transmitter));
                if doc.get("pollIntervalMs").is_some_and(truthy) {
                    block.insert("pollIntervalMs".into(), doc.get("pollIntervalMs").cloned().unwrap_or(Value::Null));
                }
                ssf = Some(block);
            }
        }
    }
    let checked_redirect = check_redirect(&redirect_uri, "redirectUri", allow_insecure)?;
    let mut out = JsonMap::new();
    if !issuer.is_empty() {
        out.insert("issuer".into(), Value::String(issuer));
    }
    if let Some(metadata_url) = metadata_url {
        out.insert("metadataUrl".into(), Value::String(metadata_url));
    }
    if let Some(metadata) = metadata {
        out.insert("metadata".into(), Value::Object(metadata));
    }
    out.insert("clientId".into(), Value::String(client_id));
    if !client_secret.is_empty() {
        out.insert("clientSecret".into(), Value::String(client_secret));
    }
    if !private_key.is_empty() {
        out.insert("privateKeyPem".into(), Value::String(private_key));
    }
    if let Some(alg) = raw.get("privateKeyAlg").filter(|v| !v.is_null()).map(sprint).filter(|v| !v.is_empty()) {
        out.insert("privateKeyAlg".into(), Value::String(alg));
    } else {
        out.insert("privateKeyAlg".into(), Value::String("RS256".into()));
    }
    out.insert("tokenEndpointAuthMethod".into(), Value::String(method));
    out.insert("redirectUri".into(), Value::String(checked_redirect));
    if !post.is_empty() {
        out.insert("postLogoutRedirectUri".into(), Value::String(check_redirect(&post, "postLogoutRedirectUri", allow_insecure)?));
    }
    out.insert("scopes".into(), Value::String(scopes));
    if let Some(alg) = raw.get("idTokenSignedResponseAlg").filter(|v| !v.is_null()).map(sprint).filter(|v| !v.is_empty()) {
        out.insert("idTokenSignedResponseAlg".into(), Value::String(alg));
    }
    out.insert("par".into(), Value::String(par));
    let clock = raw.get("clockToleranceSec").filter(|v| !v.is_null()).cloned().unwrap_or(Value::Number(Number::from(30)));
    let max_age = raw.get("maxIdTokenAgeSec").filter(|v| !v.is_null()).cloned().unwrap_or(Value::Number(Number::from(600)));
    out.insert("clockToleranceSec".into(), clock);
    out.insert("maxIdTokenAgeSec".into(), max_age);
    out.insert("allowInsecure".into(), Value::Bool(allow_insecure));
    if let Some(tls_ca) = tls_ca {
        out.insert("tlsCa".into(), Value::String(tls_ca));
    }
    if !signals {
        out.insert("signals".into(), Value::Bool(false));
    }
    if let Some(ssf) = ssf {
        out.insert("ssf".into(), Value::Object(ssf));
    }
    let _ = as_f64;
    Ok(out)
}

pub fn read_config_file(path: &str) -> Result<Resolved, OidcError> {
    let body = fs::read_to_string(path).map_err(|err| OidcError::new("config", format!("could not read {path}: {err}")))?;
    let parsed: Value = serde_json::from_str(&body).map_err(|err| OidcError::new("config", format!("could not read {path}: {err}")))?;
    let doc = as_map(&parsed).ok_or_else(|| OidcError::new("config", "the configuration must be a JSON object"))?;
    let abs = fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
    let base = abs.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
    resolve_config(doc, &base.to_string_lossy())
}
