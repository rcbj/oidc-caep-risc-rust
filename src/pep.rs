// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The embedded iya-sts PEP (the `pep` feature; rcbj/iya-sts#1206, this
//! repository's #46). The PEP itself is the shared `iya-pep` crate. This
//! library only wires it in:
//!
//! - **Configuration.** A `pep` section in `oidc.json`, off unless present.
//!   `pdpUrl` defaults to the provider's issuer (the realm prefix
//!   included) and `application` to `clientId`; `tlsCa` and `signals`
//!   follow the library's own unless the section says otherwise.
//! - **Keys (D1).** The PEP's assertion key must differ from the
//!   `private_key_jwt` key and the DPoP key: `RelyingParty::create` refuses
//!   a configuration where any two have the same JWK thumbprint.
//! - **The subject.** A `Login` becomes the PEP's subject: the
//!   username (iya-sts's `username` claim, else `preferred_username`, else
//!   `sub`) as the id, which the service's PIP
//!   resolves, and the ID token's claims (and userinfo, when the
//!   application fetched it) as properties. The PEP sends only the claims
//!   the realm's AuthZEN catalogue declares. No request header is read.
//! - **Signals (D4).** `SignalsReceiver` built with this relying party asks
//!   for `pep-policies-changed` too (in `local` mode, or `central` with a
//!   Permit cache), verifies its SET like any other, and hands the event
//!   to the PEP.

use std::sync::Arc;

use serde_json::Value;

use crate::dpop::Dpop;
use crate::error::OidcError;
use crate::keys::PrivateKey;
use crate::rp::Login;
use crate::value::{map_str, JsonMap};

pub use iya_pep::{Access, Decision, EventStream, Mode, Obligation, Pep, PepConfig, Status, Subject, POLICIES_CHANGED_EVENT};

/// Builds the PEP from the configuration's `pep` section, or `None` when
/// there is none. Checks that its key is not one of the relying party's.
pub(crate) fn build(config: &JsonMap, metadata: &JsonMap, key: Option<&PrivateKey>, dpop: Option<&Dpop>) -> Result<Option<Arc<Pep>>, OidcError> {
    let Some(section) = config.get("pep").filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let Some(map) = section.as_object() else {
        return Err(OidcError::new("config", "pep must be an object"));
    };
    let mut map = map.clone();
    // The library's own values, unless the section names its own.
    if !map.contains_key("signals") {
        map.insert("signals".into(), Value::Bool(!matches!(config.get("signals"), Some(Value::Bool(false)))));
    }
    if !map.contains_key("tlsCa") {
        if let Some(ca) = config.get("tlsCa").and_then(Value::as_str).filter(|s| s.contains("-----BEGIN")) {
            map.insert("tlsCa".into(), Value::String(ca.to_string()));
        }
    }
    let issuer = {
        let from_metadata = map_str(metadata, "issuer");
        if from_metadata.is_empty() { map_str(config, "issuer") } else { from_metadata }
    };
    let pep_config = PepConfig::from_json(&Value::Object(map), &issuer, &map_str(config, "clientId")).map_err(|e| OidcError::new("config", e.message))?;
    let pep = Pep::new(pep_config).map_err(|e| OidcError::new("config", e.message))?;
    let pep_key = pep.key_thumbprint();
    if let Some(PrivateKey::Rsa(private)) = key {
        use rsa::traits::PublicKeyParts;
        let jwk = serde_json::json!({
            "kty": "RSA",
            "n": crate::b64::b64url_encode(&private.n().to_bytes_be()),
            "e": crate::b64::b64url_encode(&private.e().to_bytes_be()),
        });
        if iya_pep::jwk_thumbprint(&jwk).as_deref() == Some(pep_key.as_str()) {
            return Err(OidcError::new("config", "pep.assertionKey is the private_key_jwt key; the PEP needs a key of its own"));
        }
    }
    if let Some(dpop) = dpop {
        if dpop.jkt() == pep_key {
            return Err(OidcError::new("config", "pep.assertionKey is the DPoP key; the PEP needs a key of its own"));
        }
    }
    Ok(Some(Arc::new(pep)))
}

/// The PEP's subject for a sign-in: the username (the `username` claim,
/// else `preferred_username`, else `sub`) as the id, and every ID token claim as a property. The PEP sends only the
/// ones the realm's catalogue declares.
pub fn subject_of(login: &Login) -> Subject {
    subject_with_userinfo(login, &JsonMap::new())
}

/// `subject_of`, with the userinfo claims the application fetched laid
/// over the ID token's.
pub fn subject_with_userinfo(login: &Login, userinfo: &JsonMap) -> Subject {
    let mut properties = login.claims.clone();
    for (name, value) in userinfo {
        properties.insert(name.clone(), value.clone());
    }
    // iya-sts's own `username` claim is on every ID token it issues;
    // `preferred_username` is a `profile` claim, there only when granted.
    let username = login.claims.get("username").and_then(|v| v.as_str()).filter(|v| !v.is_empty()).map(str::to_string);
    let id = username.unwrap_or_else(|| if login.preferred_username.is_empty() { login.subject.clone() } else { login.preferred_username.clone() });
    Subject::user(id, properties)
}

/// Whether a receiver built with this PEP asks for `pep-policies-changed`.
pub(crate) fn wants_events(pep: &Pep) -> bool {
    pep.config().mode == Mode::Local || pep.config().permit_cache_ms > 0
}
