// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use serde_json::Value;

use crate::error::OidcError;
use crate::http::send;
use crate::keys::ASYMMETRIC;
use crate::value::{as_map_owned, as_string_list, contains_str, is_exact_true, JsonMap};

pub const DEFAULT_SCOPES: &str = "openid profile email offline_access ssf.read ssf.manage";

const REQUIRED: &[&str] = &[
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "response_types_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
];

pub fn issuer_from_metadata_url(metadata_url: &str) -> Result<String, OidcError> {
    let parts = url::Url::parse(metadata_url).map_err(|_| OidcError::new("config", format!("metadataUrl is not a URL: {metadata_url}")))?;
    if parts.scheme() != "http" && parts.scheme() != "https" || parts.host_str().is_none() {
        return Err(OidcError::new("config", format!("metadataUrl is not a URL: {metadata_url}")));
    }
    const MARKER: &str = "/.well-known/openid-configuration";
    let path = parts.path();
    let Some(at) = path.find(MARKER) else {
        return Err(OidcError::new("config", format!("metadataUrl must be the openid-configuration URL, not {metadata_url}")));
    };
    let prefix = path[..at].trim_end_matches('/');
    let host = parts.host_str().unwrap_or("");
    let port = parts.port().map(|p| format!(":{p}")).unwrap_or_default();
    Ok(format!("{}://{host}{port}{prefix}", parts.scheme()))
}

fn must_be_url(value: &Value, name: &str) -> Result<String, OidcError> {
    let Some(text) = value.as_str().filter(|text| !text.is_empty()) else {
        return Err(OidcError::new("discovery", format!("OpenID Provider metadata {name} is missing")));
    };
    let parts = url::Url::parse(text).map_err(|_| OidcError::new("discovery", format!("OpenID Provider metadata {name} is not a valid URL")))?;
    if parts.scheme() != "http" && parts.scheme() != "https" || parts.host_str().is_none() {
        return Err(OidcError::new("discovery", format!("OpenID Provider metadata {name} is not a valid URL")));
    }
    if name == "issuer" && (parts.query().is_some() || parts.fragment().is_some()) {
        return Err(OidcError::new("discovery", "issuer must not contain a query or fragment"));
    }
    Ok(text.to_string())
}

pub fn validate_provider_metadata(raw: &JsonMap, expected_issuer: &str) -> Result<JsonMap, OidcError> {
    let missing: Vec<&str> = REQUIRED.iter().copied().filter(|key| !raw.contains_key(*key)).collect();
    if !missing.is_empty() {
        return Err(OidcError::new("discovery", format!("OpenID Provider metadata is missing {}", missing.join(", "))));
    }
    let mut metadata = JsonMap::new();
    for key in ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"] {
        let value = must_be_url(&raw[key], key)?;
        metadata.insert(key.to_string(), Value::String(value));
    }
    for key in ["userinfo_endpoint", "end_session_endpoint", "pushed_authorization_request_endpoint", "revocation_endpoint"] {
        if let Some(value) = raw.get(key).filter(|v| !v.is_null()) {
            metadata.insert(key.to_string(), Value::String(must_be_url(value, key)?));
        }
    }
    for key in ["token_endpoint_auth_methods_supported", "code_challenge_methods_supported", "scopes_supported", "grant_types_supported"] {
        if let Some(value) = raw.get(key).filter(|v| !v.is_null()) {
            let list = as_string_list(value).ok_or_else(|| OidcError::new("discovery", format!("{key} must be an array")))?;
            metadata.insert(key.to_string(), Value::Array(list.into_iter().map(Value::String).collect()));
        }
    }
    if let Some(value) = raw.get("authorization_response_iss_parameter_supported").filter(|v| !v.is_null()) {
        metadata.insert("authorization_response_iss_parameter_supported".to_string(), Value::Bool(is_exact_true(value)));
    }
    let response_types = as_string_list(raw.get("response_types_supported").unwrap_or(&Value::Null)).unwrap_or_default();
    if !contains_str(&response_types, "code") {
        return Err(OidcError::new("discovery", "OpenID Provider does not support response_type=code"));
    }
    metadata.insert("response_types_supported".to_string(), Value::Array(response_types.into_iter().map(Value::String).collect()));
    let subjects = as_string_list(raw.get("subject_types_supported").unwrap_or(&Value::Null)).ok_or_else(|| OidcError::new("discovery", "subject_types_supported must be an array"))?;
    metadata.insert("subject_types_supported".to_string(), Value::Array(subjects.into_iter().map(Value::String).collect()));
    let algs = as_string_list(raw.get("id_token_signing_alg_values_supported").unwrap_or(&Value::Null))
        .ok_or_else(|| OidcError::new("discovery", "id_token_signing_alg_values_supported must be an array"))?;
    metadata.insert("id_token_signing_alg_values_supported".to_string(), Value::Array(algs.into_iter().map(Value::String).collect()));
    if !expected_issuer.is_empty() && metadata.get("issuer").and_then(|v| v.as_str()) != Some(expected_issuer) {
        let got = metadata.get("issuer").and_then(|v| v.as_str()).unwrap_or("");
        return Err(OidcError::new("discovery", format!("issuer mismatch: expected \"{expected_issuer}\", got \"{got}\"")));
    }
    Ok(metadata)
}

pub fn discover_provider(metadata_url: &str, ca: Option<&str>) -> Result<JsonMap, OidcError> {
    let expected = issuer_from_metadata_url(metadata_url)?;
    let answer = send(metadata_url, "GET", &[("accept".into(), "application/json".into())], None, ca, "discovery")?;
    if answer.status != 200 {
        return Err(OidcError::new("discovery", format!("{metadata_url} answered {}", answer.status)));
    }
    let body: Value = serde_json::from_str(&answer.body).map_err(|err| OidcError::new("discovery", format!("{metadata_url} did not answer JSON: {err}")))?;
    let doc = as_map_owned(body).ok_or_else(|| OidcError::new("discovery", "OpenID Provider metadata must be a JSON object"))?;
    validate_provider_metadata(&doc, &expected)
}

pub fn well_known_urls(issuer: &str, suffix: &str) -> Vec<String> {
    let Ok(parts) = url::Url::parse(issuer) else {
        return Vec::new();
    };
    let path = parts.path().trim_end_matches('/');
    let host = parts.host_str().unwrap_or("");
    let port = parts.port().map(|p| format!(":{p}")).unwrap_or_default();
    let origin = format!("{}://{host}{port}", parts.scheme());
    let inserted = format!("{origin}/.well-known/{suffix}{path}");
    let appended = format!("{origin}{path}/.well-known/{suffix}");
    if inserted == appended {
        vec![inserted]
    } else {
        vec![inserted, appended]
    }
}

pub fn id_token_algorithms(advertised: &[String], pinned: &str) -> Result<Vec<String>, OidcError> {
    if !pinned.is_empty() {
        if !contains_str(advertised, pinned) {
            return Err(OidcError::new("discovery", format!("the provider does not advertise id_token alg {pinned}")));
        }
        return Ok(vec![pinned.to_string()]);
    }
    let allowed: Vec<String> = advertised.iter().filter(|alg| ASYMMETRIC.contains(&alg.as_str())).cloned().collect();
    if allowed.is_empty() {
        return Err(OidcError::new("discovery", format!("none of the provider's ID token algorithms can be verified ({})", advertised.join(", "))));
    }
    Ok(allowed)
}

pub fn scheme_of(value: &str) -> String {
    url::Url::parse(value).map(|u| u.scheme().to_string()).unwrap_or_default()
}
