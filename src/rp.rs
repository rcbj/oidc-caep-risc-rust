// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::b64::b64url_encode;
use crate::config::{apply_defaults, check_redirect, read_config_file};
use crate::discovery::{discover_provider, id_token_algorithms, scheme_of};
use crate::dpop::{resource_wants_nonce, Dpop, DPOP_ALG};
use crate::error::OidcError;
use crate::http::{send, Answer};
use crate::value::{string_list, JsonMap};
use crate::idtoken::{validate_id_token, TokenChecks};
use crate::keys::{load_private_key, sign_jws, PrivateKey};
use crate::pkce::{code_challenge_s256, random_token};
use crate::value::{as_f64, as_map, as_string_list, contains_str, is_exact_true, map_str};

const FRONT: &[&str] = &["access_token", "id_token", "refresh_token", "token_type"];

fn now_sec() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn form_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
            out.push(byte as char);
        } else if byte == b' ' {
            out.push('+');
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn query_escape(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            out.push(byte as char);
        } else if byte == b' ' {
            out.push('+');
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn form_body(fields: &HashMap<String, String>, order: &[String]) -> String {
    let mut parts = Vec::new();
    let mut seen = Vec::new();
    for key in order {
        if let Some(value) = fields.get(key) {
            parts.push(format!("{}={}", query_escape(key), query_escape(value)));
            seen.push(key.clone());
        }
    }
    for (key, value) in fields {
        if !seen.iter().any(|item| item == key) {
            parts.push(format!("{}={}", query_escape(key), query_escape(value)));
        }
    }
    parts.join("&")
}

fn uuid4() -> String {
    let mut buf = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    buf[6] = (buf[6] & 0x0f) | 0x40;
    buf[8] = (buf[8] & 0x3f) | 0x80;
    format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15])
}

fn apply_client_auth(config: &JsonMap, key: Option<&PrivateKey>, body: &mut HashMap<String, String>, headers: &mut Vec<(String, String)>, audience: &str) -> Result<(), OidcError> {
    let method = map_str(config, "tokenEndpointAuthMethod");
    let client_id = map_str(config, "clientId");
    match method.as_str() {
        "client_secret_basic" => {
            let raw = format!("{}:{}", form_encode(&client_id), form_encode(&map_str(config, "clientSecret")));
            headers.push(("authorization".into(), format!("Basic {}", STANDARD.encode(raw.as_bytes()))));
            Ok(())
        }
        "client_secret_post" => {
            body.insert("client_id".into(), client_id);
            body.insert("client_secret".into(), map_str(config, "clientSecret"));
            Ok(())
        }
        _ => {
            let key = key.ok_or_else(|| OidcError::new("config", "private_key_jwt has no signing key"))?;
            let mut alg = map_str(config, "privateKeyAlg");
            if alg.is_empty() {
                alg = "RS256".into();
            }
            let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
            let header = serde_json::json!({"alg": alg, "typ": "JWT"});
            let claims = serde_json::json!({"iss": client_id, "sub": client_id, "aud": audience, "jti": uuid4(), "iat": now, "exp": now + 60});
            let signing = format!("{}.{}", b64url_encode(&serde_json::to_vec(&header).unwrap_or_default()), b64url_encode(&serde_json::to_vec(&claims).unwrap_or_default()));
            let sig = sign_jws(key, &alg, signing.as_bytes())?;
            body.insert("client_id".into(), client_id);
            body.insert("client_assertion_type".into(), "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into());
            body.insert("client_assertion".into(), format!("{signing}.{}", b64url_encode(&sig)));
            Ok(())
        }
    }
}

fn with_query(base: &str, params: &HashMap<String, String>, order: &[String]) -> String {
    let mut parts = url::Url::parse(base).unwrap_or_else(|_| url::Url::parse("http://invalid/").unwrap());
    if parts.path().is_empty() {
        parts.set_path("/");
    }
    parts.set_query(Some(&form_body(params, order)));
    parts.set_fragment(None);
    parts.to_string()
}

/// The sign-in kept until the browser returns.
#[derive(Clone, Debug, Default)]
pub struct Transaction {
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub url: String,
    pub max_age: Option<f64>,
    pub expected_sub: String,
    /// The `acr_values` the request named (space-separated). The ID token's `acr` must be one of them.
    pub acr_values: String,
}

/// A completed sign-in. Tokens stay in this process.
#[derive(Clone, Debug, Default)]
pub struct Login {
    pub subject: String,
    pub issuer: String,
    pub claims: JsonMap,
    pub access_token: String,
    pub id_token: String,
    pub token_type: String,
    pub email: String,
    pub name: String,
    pub preferred_username: String,
    pub sid: String,
    pub refresh_token: String,
    pub expires_at: Option<f64>,
    pub scope: String,
    /// The session cache key (`complete_session`), or empty.
    pub session_id: String,
}

impl Login {
    /// The access token and its type, as a resource request needs them.
    pub fn access(&self) -> Access {
        Access { access_token: self.access_token.clone(), token_type: self.token_type.clone(), expires_at: self.expires_at, scope: self.scope.clone() }
    }
}

/// Where completed sign-ins are kept, by a session identifier the application chooses.
/// The default is `MemorySessionStore`; a store shared by several processes implements this.
pub trait SessionStore: Send + Sync {
    fn get(&self, session_id: &str) -> Option<Login>;
    fn set(&self, session_id: &str, login: Login);
    fn remove(&self, session_id: &str);
}

/// The default session store: this process's memory.
#[derive(Default)]
pub struct MemorySessionStore {
    entries: Mutex<HashMap<String, Login>>,
}

impl SessionStore for MemorySessionStore {
    fn get(&self, session_id: &str) -> Option<Login> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).get(session_id).cloned()
    }

    fn set(&self, session_id: &str, login: Login) {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).insert(session_id.to_string(), login);
    }

    fn remove(&self, session_id: &str) {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).remove(session_id);
    }
}

/// A cached access token is used while it has more than this many seconds left.
pub const SESSION_REFRESH_MARGIN_SEC: f64 = 30.0;

#[derive(Clone, Debug, Default)]
pub struct AuthorizeOptions {
    pub redirect_uri: String,
    pub scope: String,
    pub prompt: String,
    pub login_hint: String,
    pub max_age: Option<f64>,
    pub acr_values: String,
    pub expected_sub: String,
}

#[derive(Clone, Debug, Default)]
pub struct EndSessionOptions {
    pub id_token: String,
    pub post_logout: Option<String>,
    pub state: String,
    pub logout_hint: String,
}

#[derive(Clone, Debug, Default)]
pub struct Access {
    pub access_token: String,
    pub token_type: String,
    pub expires_at: Option<f64>,
    pub scope: String,
}

struct TokenResponse {
    access_token: String,
    token_type: String,
    id_token: String,
    refresh_token: String,
    expires_in: Option<f64>,
    scope: String,
}

/// A confidential OpenID Connect client.
pub struct RelyingParty {
    config: JsonMap,
    metadata: JsonMap,
    key: Option<PrivateKey>,
    algs: Vec<String>,
    dpop: Option<Dpop>,
    require_typ_at_hash: bool,
    jwks: Mutex<Option<Vec<JsonMap>>>,
    used_codes: Mutex<HashMap<String, f64>>,
    cc: Mutex<Option<(String, Access, f64)>>,
    sessions: RwLock<Arc<dyn SessionStore>>,
    refreshing: Mutex<()>,
}

impl RelyingParty {
    pub fn config(&self) -> &JsonMap {
        &self.config
    }

    pub fn metadata(&self) -> &JsonMap {
        &self.metadata
    }

    pub fn tls_ca(&self) -> Option<&str> {
        self.config.get("tlsCa").and_then(|v| v.as_str()).filter(|v| !v.is_empty())
    }

    pub fn from_file(path: &str) -> Result<Self, OidcError> {
        Self::create(read_config_file(path)?)
    }

    /// Builds a relying party from a configuration object. The defaults and the redirect
    /// URI rule apply here exactly as they do to `from_file` (`apply_defaults`).
    pub fn create(config: JsonMap) -> Result<Self, OidcError> {
        let mut config = config;
        apply_defaults(&mut config)?;
        let method = map_str(&config, "tokenEndpointAuthMethod");
        if method == "private_key_jwt" && map_str(&config, "privateKeyPem").is_empty() {
            return Err(OidcError::new("config", "private_key_jwt needs a private key"));
        }
        if method != "private_key_jwt" && map_str(&config, "clientSecret").is_empty() {
            return Err(OidcError::new("config", format!("{method} needs a client secret")));
        }
        let allow = config.get("allowInsecure").is_some_and(is_exact_true);
        if !allow {
            let issuer = map_str(&config, "issuer");
            if !issuer.is_empty() && scheme_of(&issuer) == "http" {
                return Err(OidcError::new("config", "issuer must use https (set allowInsecure for a development provider)"));
            }
        }
        let metadata = if let Some(metadata) = config.get("metadata").and_then(as_map) {
            metadata.clone()
        } else {
            let metadata_url = map_str(&config, "metadataUrl");
            if metadata_url.is_empty() {
                return Err(OidcError::new("config", "metadataUrl or metadata is required"));
            }
            if !allow && scheme_of(&metadata_url) != "https" {
                return Err(OidcError::new("config", "metadataUrl must use https (set allowInsecure for a development provider)"));
            }
            discover_provider(&metadata_url, config.get("tlsCa").and_then(|v| v.as_str()))?
        };
        if !allow {
            for (name, value) in &metadata {
                if let Some(text) = value.as_str() {
                    if text.starts_with("http:") && (name.ends_with("endpoint") || name == "jwks_uri" || name == "issuer") {
                        return Err(OidcError::new("discovery", format!("{name} must use https: {text}")));
                    }
                }
            }
        }
        if let Some(methods) = metadata.get("token_endpoint_auth_methods_supported").and_then(as_string_list) {
            if !methods.is_empty() && !contains_str(&methods, &method) {
                return Err(OidcError::new("discovery", format!("the provider does not advertise {method}")));
            }
        }
        if let Some(challenges) = metadata.get("code_challenge_methods_supported").and_then(as_string_list) {
            if !challenges.is_empty() && !contains_str(&challenges, "S256") {
                return Err(OidcError::new("discovery", "the provider does not advertise PKCE S256"));
            }
        }
        let key = if map_str(&config, "privateKeyPem").is_empty() {
            None
        } else {
            let mut alg = map_str(&config, "privateKeyAlg");
            if alg.is_empty() {
                alg = "RS256".into();
            }
            Some(load_private_key(&map_str(&config, "privateKeyPem"), &alg)?)
        };
        let pinned = map_str(&config, "idTokenSignedResponseAlg");
        let allowed = string_list(config.get("idTokenSigningAlgs").unwrap_or(&Value::Null));
        let advertised = as_string_list(metadata.get("id_token_signing_alg_values_supported").unwrap_or(&Value::Null)).unwrap_or_default();
        let algs = id_token_algorithms(&advertised, &pinned, &allowed)?;
        let par_mode = map_str(&config, "par");
        let par_endpoint = map_str(&metadata, "pushed_authorization_request_endpoint");
        let par_required = metadata.get("require_pushed_authorization_requests").is_some_and(is_exact_true);
        if par_required && par_mode == "never" {
            return Err(OidcError::new("config", "par is never, and the provider requires pushed authorization requests"));
        }
        if par_endpoint.is_empty() && par_mode == "always" {
            return Err(OidcError::new("discovery", "par is always, and the provider has no pushed authorization endpoint"));
        }
        if par_endpoint.is_empty() && par_required {
            return Err(OidcError::new("discovery", "the provider requires pushed authorization requests and has no pushed authorization endpoint"));
        }
        let dpop = Self::dpop_key(&config, &metadata)?;
        let require_typ_at_hash = !matches!(config.get("requireIdTokenTypAndAtHash"), Some(Value::Bool(false)));
        Ok(Self {
            config,
            metadata,
            key,
            algs,
            dpop,
            require_typ_at_hash,
            jwks: Mutex::new(None),
            used_codes: Mutex::new(HashMap::new()),
            cc: Mutex::new(None),
            sessions: RwLock::new(Arc::new(MemorySessionStore::default())),
            refreshing: Mutex::new(()),
        })
    }

    /// `dpop`: `auto` uses DPoP when the provider advertises ES256 in
    /// `dpop_signing_alg_values_supported`, `always` requires that, `never` sends no proofs.
    fn dpop_key(config: &JsonMap, metadata: &JsonMap) -> Result<Option<Dpop>, OidcError> {
        let mode = map_str(config, "dpop");
        let pem = map_str(config, "dpopKey");
        let named = if pem.is_empty() { None } else { Some(Dpop::from_pem(&pem)?) };
        if mode == "never" {
            return Ok(None);
        }
        let advertised = metadata.get("dpop_signing_alg_values_supported").and_then(as_string_list);
        let es256 = advertised.as_ref().is_some_and(|list| contains_str(list, DPOP_ALG));
        if mode == "always" && advertised.is_none() {
            return Err(OidcError::new("discovery", "dpop is always, and the provider does not advertise dpop_signing_alg_values_supported"));
        }
        if mode == "always" && !es256 {
            return Err(OidcError::new("discovery", "dpop is always, and the provider does not advertise ES256 for DPoP"));
        }
        if !es256 {
            return Ok(None);
        }
        Ok(Some(named.unwrap_or_else(Dpop::generate)))
    }

    /// True when this relying party sends DPoP proofs.
    pub fn uses_dpop(&self) -> bool {
        self.dpop.is_some()
    }

    /// The DPoP key's JWK thumbprint (`dpop_jkt`), when DPoP is in use.
    pub fn dpop_jkt(&self) -> Option<String> {
        self.dpop.as_ref().map(|d| d.jkt().to_string())
    }

    /// The ID token algorithms this relying party accepts.
    pub fn id_token_algs(&self) -> &[String] {
        &self.algs
    }

    /// Replaces the session store (`MemorySessionStore` by default).
    pub fn set_session_store(&self, store: Arc<dyn SessionStore>) {
        *self.sessions.write().unwrap_or_else(|e| e.into_inner()) = store;
    }

    fn store(&self) -> Arc<dyn SessionStore> {
        Arc::clone(&self.sessions.read().unwrap_or_else(|e| e.into_inner()))
    }

    pub fn authorize(&self) -> Result<Transaction, OidcError> {
        self.authorize_options(AuthorizeOptions::default())
    }

    pub fn authorize_options(&self, opts: AuthorizeOptions) -> Result<Transaction, OidcError> {
        let redirect_uri = if opts.redirect_uri.is_empty() {
            map_str(&self.config, "redirectUri")
        } else {
            check_redirect(&opts.redirect_uri, "redirect_uri")?
        };
        let acr_values = if opts.acr_values.is_empty() { map_str(&self.config, "acrValues") } else { opts.acr_values.split_whitespace().collect::<Vec<_>>().join(" ") };
        let scope = if opts.scope.is_empty() { map_str(&self.config, "scopes") } else { opts.scope };
        let state = random_token();
        let nonce = random_token();
        let verifier = random_token();
        let mut params = HashMap::new();
        params.insert("response_type".into(), "code".into());
        params.insert("client_id".into(), map_str(&self.config, "clientId"));
        params.insert("redirect_uri".into(), redirect_uri.clone());
        params.insert("scope".into(), scope);
        params.insert("state".into(), state.clone());
        params.insert("nonce".into(), nonce.clone());
        params.insert("code_challenge".into(), code_challenge_s256(&verifier));
        params.insert("code_challenge_method".into(), "S256".into());
        let mut order = vec!["response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method"].into_iter().map(str::to_string).collect::<Vec<_>>();
        if !opts.prompt.is_empty() {
            params.insert("prompt".into(), opts.prompt);
            order.push("prompt".into());
        }
        if !opts.login_hint.is_empty() {
            params.insert("login_hint".into(), opts.login_hint);
            order.push("login_hint".into());
        }
        if let Some(max_age) = opts.max_age {
            params.insert("max_age".into(), trim_float(max_age));
            order.push("max_age".into());
        }
        if !acr_values.is_empty() {
            params.insert("acr_values".into(), acr_values.clone());
            order.push("acr_values".into());
        }
        if let Some(dpop) = &self.dpop {
            params.insert("dpop_jkt".into(), dpop.jkt().to_string());
            order.push("dpop_jkt".into());
        }
        let mut txn = Transaction { state, nonce, code_verifier: verifier, redirect_uri, url: String::new(), max_age: opts.max_age, expected_sub: opts.expected_sub, acr_values };
        let par_endpoint = map_str(&self.metadata, "pushed_authorization_request_endpoint");
        let mode = map_str(&self.config, "par");
        let required = self.metadata.get("require_pushed_authorization_requests").is_some_and(is_exact_true);
        let use_par = mode == "always" || (mode == "auto" && (required || !par_endpoint.is_empty()));
        if required && mode == "never" {
            return Err(OidcError::new("config", "par is never, and the provider requires pushed authorization requests"));
        }
        if mode == "always" && par_endpoint.is_empty() {
            return Err(OidcError::new("discovery", "par is always, and the provider has no pushed authorization endpoint"));
        }
        if use_par && !par_endpoint.is_empty() {
            let (pushed, _) = self.post_form(&par_endpoint, params, order)?;
            let request_uri = pushed.get("request_uri").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if request_uri.is_empty() {
                return Err(OidcError::new("protocol", "the pushed authorization response has no request_uri"));
            }
            let mut q = HashMap::new();
            q.insert("client_id".into(), map_str(&self.config, "clientId"));
            q.insert("request_uri".into(), request_uri);
            txn.url = with_query(&map_str(&self.metadata, "authorization_endpoint"), &q, &["client_id".into(), "request_uri".into()]);
            return Ok(txn);
        }
        txn.url = with_query(&map_str(&self.metadata, "authorization_endpoint"), &params, &order);
        Ok(txn)
    }

    pub fn complete(&self, query: &HashMap<String, String>, txn: &Transaction) -> Result<Login, OidcError> {
        for name in FRONT {
            if query.contains_key(*name) {
                return Err(OidcError::new("validation", format!("{name} was returned on the redirect, and a code-flow client refuses it")));
            }
        }
        if let Some(error) = query.get("error").filter(|v| !v.is_empty()) {
            let mut message = error.clone();
            if let Some(desc) = query.get("error_description").filter(|v| !v.is_empty()) {
                message = format!("{error}: {desc}");
            }
            return Err(OidcError::oauth("protocol", message, error));
        }
        let state = query.get("state").map(String::as_str).unwrap_or("");
        if txn.state.is_empty() || !crate::idtoken::same_text(state, &txn.state) {
            return Err(OidcError::new("validation", "the callback state does not match this sign-in"));
        }
        if let Some(iss) = query.get("iss") {
            if iss != &map_str(&self.metadata, "issuer") {
                return Err(OidcError::new("validation", format!("iss mismatch in the callback: {iss}")));
            }
        } else if self.metadata.get("authorization_response_iss_parameter_supported").is_some_and(is_exact_true) {
            return Err(OidcError::new("validation", "iss is missing from the callback, and the provider requires it"));
        }
        let code = query.get("code").cloned().unwrap_or_default();
        if code.is_empty() {
            return Err(OidcError::new("validation", "the callback has no code"));
        }
        self.remember_code(&code)?;
        let mut body = HashMap::new();
        body.insert("grant_type".into(), "authorization_code".into());
        body.insert("code".into(), code.clone());
        body.insert("redirect_uri".into(), txn.redirect_uri.clone());
        body.insert("code_verifier".into(), txn.code_verifier.clone());
        let tokens = self.token(body, vec!["grant_type".into(), "code".into(), "redirect_uri".into(), "code_verifier".into()])?;
        if tokens.id_token.is_empty() {
            return Err(OidcError::new("protocol", "the token response has no id_token"));
        }
        let mut extra = TokenChecks::default();
        extra.nonce = Some(txn.nonce.clone());
        extra.access_token = tokens.access_token.clone();
        extra.code = code;
        extra.max_age = txn.max_age;
        extra.require_typ = self.require_typ_at_hash;
        extra.require_at_hash = self.require_typ_at_hash;
        extra.acr_values = txn.acr_values.split_whitespace().map(str::to_string).collect();
        let claims = self.id_token(&tokens.id_token, extra)?;
        if !txn.expected_sub.is_empty() && map_str(&claims, "sub") != txn.expected_sub {
            return Err(OidcError::new("validation", "the provider signed in a different account from the one requested"));
        }
        Ok(login_from(tokens, claims))
    }

    pub fn refresh(&self, refresh_token: &str, scope: &str, previous: Option<&Login>) -> Result<Login, OidcError> {
        if refresh_token.is_empty() {
            return Err(OidcError::new("protocol", "there is no refresh token"));
        }
        let mut body = HashMap::new();
        body.insert("grant_type".into(), "refresh_token".into());
        body.insert("refresh_token".into(), refresh_token.to_string());
        let mut order = vec!["grant_type".into(), "refresh_token".into()];
        if !scope.is_empty() {
            body.insert("scope".into(), scope.to_string());
            order.push("scope".into());
        }
        let mut tokens = self.token(body, order)?;
        let mut claims = previous.map(|login| login.claims.clone());
        let mut id_token = tokens.id_token.clone();
        if previous.is_some() && id_token.is_empty() {
            id_token = previous.unwrap().id_token.clone();
        }
        if !tokens.id_token.is_empty() {
            let previous = previous.ok_or_else(|| OidcError::new("validation", "the refresh returned an ID token and there is no previous sign-in to check it against"))?;
            let mut extra = TokenChecks::default();
            extra.access_token = tokens.access_token.clone();
            extra.previous_sub = Some(previous.subject.clone());
            extra.require_typ = self.require_typ_at_hash;
            extra.require_at_hash = self.require_typ_at_hash;
            claims = Some(self.id_token(&tokens.id_token, extra)?);
            id_token = tokens.id_token.clone();
        }
        if claims.is_none() || id_token.is_empty() {
            return Err(OidcError::new("protocol", "the refresh returned no ID token and no previous sign-in was given"));
        }
        if tokens.refresh_token.is_empty() {
            tokens.refresh_token = refresh_token.to_string();
        }
        tokens.id_token = id_token;
        Ok(login_from(tokens, claims.unwrap()))
    }

    pub fn client_credentials(&self, scope: &str) -> Result<Access, OidcError> {
        let scope = if scope.is_empty() { "ssf.manage" } else { scope };
        let now = now_sec();
        if let Some((saved, token, until)) = self.cc.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            if saved == scope && *until > now {
                return Ok(token.clone());
            }
        }
        let mut body = HashMap::new();
        body.insert("grant_type".into(), "client_credentials".into());
        body.insert("scope".into(), scope.to_string());
        let tokens = self.token(body, vec!["grant_type".into(), "scope".into()])?;
        let token = access_from(&tokens);
        let until = token.expires_at.map(|at| at - 30.0).unwrap_or(now + 60.0);
        *self.cc.lock().unwrap_or_else(|e| e.into_inner()) = Some((scope.to_string(), token.clone(), until));
        Ok(token)
    }

    /// UserInfo with an access token of `token_type` (`Bearer`, or `DPoP` with a proof).
    pub fn userinfo(&self, access_token: &str, token_type: &str, expected_sub: &str) -> Result<JsonMap, OidcError> {
        if expected_sub.is_empty() {
            return Err(OidcError::new("validation", "userinfo needs the subject to check the response against"));
        }
        let endpoint = map_str(&self.metadata, "userinfo_endpoint");
        if endpoint.is_empty() {
            return Err(OidcError::new("discovery", "the provider has no userinfo_endpoint"));
        }
        let accept = [("accept".to_string(), "application/json, application/jwt".to_string())];
        let answer = self.send_resource("GET", &endpoint, access_token, token_type, &accept, None, self.tls_ca(), "protocol")?;
        if answer.status == 401 {
            return Err(OidcError::oauth("protocol", "userinfo refused the access token", "invalid_token"));
        }
        if answer.status != 200 {
            return Err(OidcError::new("protocol", format!("userinfo answered {}", answer.status)));
        }
        if answer.content_type.contains("application/jwt") {
            return self.id_token(answer.body.trim(), TokenChecks { algorithms: self.algs.clone(), ..TokenChecks::default() });
        }
        let body: Value = serde_json::from_str(&answer.body).map_err(|err| OidcError::new("protocol", format!("userinfo did not answer JSON: {err}")))?;
        let claims = as_map(&body).cloned().ok_or_else(|| OidcError::new("validation", "userinfo did not answer a JSON object"))?;
        if map_str(&claims, "sub") != expected_sub {
            return Err(OidcError::new("validation", "userinfo sub does not match the ID token sub"));
        }
        Ok(claims)
    }

    pub fn end_session_url(&self, opts: EndSessionOptions) -> String {
        let endpoint = map_str(&self.metadata, "end_session_endpoint");
        if endpoint.is_empty() {
            return String::new();
        }
        let redirect = opts.post_logout.unwrap_or_else(|| map_str(&self.config, "postLogoutRedirectUri"));
        let mut query = HashMap::new();
        let mut order = Vec::new();
        if !opts.id_token.is_empty() {
            query.insert("id_token_hint".into(), opts.id_token);
            order.push("id_token_hint".into());
        }
        if !redirect.is_empty() {
            query.insert("post_logout_redirect_uri".into(), redirect);
            order.push("post_logout_redirect_uri".into());
        }
        query.insert("client_id".into(), map_str(&self.config, "clientId"));
        order.push("client_id".into());
        if !opts.logout_hint.is_empty() {
            query.insert("logout_hint".into(), opts.logout_hint);
            order.push("logout_hint".into());
        }
        if !opts.state.is_empty() {
            query.insert("state".into(), opts.state);
            order.push("state".into());
        }
        with_query(&endpoint, &query, &order)
    }

    fn id_token(&self, token: &str, mut extra: TokenChecks) -> Result<JsonMap, OidcError> {
        extra.issuer = map_str(&self.metadata, "issuer");
        extra.client_id = map_str(&self.config, "clientId");
        if extra.algorithms.is_empty() {
            extra.algorithms = self.algs.clone();
        }
        if let Some(tol) = self.config.get("clockToleranceSec").and_then(as_f64) {
            extra.clock_tolerance_sec = tol;
        }
        if let Some(age) = self.config.get("maxIdTokenAgeSec").and_then(as_f64) {
            extra.max_id_token_age_sec = Some(age);
        }
        if extra.client_secret.is_empty() {
            extra.client_secret = map_str(&self.config, "clientSecret");
        }
        if let Ok(keys) = self.keys(false) {
            extra.jwks = keys;
        }
        match validate_id_token(token, &extra) {
            Ok(claims) => Ok(claims),
            Err(err) if err.code == "signature" => {
                *self.jwks.lock().unwrap_or_else(|e| e.into_inner()) = None;
                match self.keys(true) {
                    Ok(keys) => {
                        extra.jwks = keys;
                        validate_id_token(token, &extra)
                    }
                    Err(_) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }

    fn keys(&self, force: bool) -> Result<Vec<JsonMap>, OidcError> {
        if !force {
            if let Some(keys) = self.jwks.lock().unwrap_or_else(|e| e.into_inner()).clone() {
                return Ok(keys);
            }
        }
        let fetched = crate::idtoken::fetch_jwks(&map_str(&self.metadata, "jwks_uri"), self.tls_ca())?;
        *self.jwks.lock().unwrap_or_else(|e| e.into_inner()) = Some(fetched.clone());
        Ok(fetched)
    }

    fn token(&self, body: HashMap<String, String>, order: Vec<String>) -> Result<TokenResponse, OidcError> {
        let (parsed, proof_sent) = self.post_form(&map_str(&self.metadata, "token_endpoint"), body, order)?;
        let access = parsed.get("access_token").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let token_type = parsed.get("token_type").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if access.is_empty() {
            return Err(OidcError::new("protocol", "the token response has no access_token"));
        }
        if token_type.is_empty() {
            return Err(OidcError::new("protocol", "the token response has no token_type"));
        }
        // RFC 9449 section 5: a proof was sent, so the token must be DPoP-bound; none was
        // sent, so it must be a Bearer token.
        if proof_sent && !token_type.eq_ignore_ascii_case("dpop") {
            return Err(OidcError::new("protocol", format!("this client sent a DPoP proof and the provider returned token_type {token_type}, not DPoP")));
        }
        if !proof_sent && token_type.eq_ignore_ascii_case("dpop") {
            return Err(OidcError::new("protocol", "the provider returned a DPoP token; this client sent no DPoP proof and asked for a Bearer token"));
        }
        if !proof_sent && !token_type.eq_ignore_ascii_case("bearer") {
            return Err(OidcError::new("protocol", format!("the token response token_type is {token_type}")));
        }
        Ok(TokenResponse {
            access_token: access,
            token_type,
            id_token: parsed.get("id_token").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            refresh_token: parsed.get("refresh_token").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            expires_in: parsed.get("expires_in").and_then(as_f64),
            scope: parsed.get("scope").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        })
    }

    /// A form POST to the authorization server (PAR or token endpoint), with a DPoP proof
    /// when DPoP is in use. A 400 `use_dpop_nonce` is retried once with the nonce it gave.
    /// Returns the JSON answer and whether a proof was sent.
    fn post_form(&self, endpoint: &str, body: HashMap<String, String>, mut order: Vec<String>) -> Result<(JsonMap, bool), OidcError> {
        for key in body.keys() {
            if !order.iter().any(|item| item == key) {
                order.push(key.clone());
            }
        }
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut fields = body.clone();
            let mut headers = vec![("accept".into(), "application/json".into()), ("content-type".into(), "application/x-www-form-urlencoded".into())];
            // A fresh client assertion (and jti) on every attempt.
            apply_client_auth(&self.config, self.key.as_ref(), &mut fields, &mut headers, &map_str(&self.metadata, "issuer"))?;
            if let Some(dpop) = &self.dpop {
                headers.push(("dpop".into(), dpop.proof("POST", endpoint, None)?));
            }
            let mut field_order = order.clone();
            for key in fields.keys() {
                if !field_order.iter().any(|item| item == key) {
                    field_order.push(key.clone());
                }
            }
            let encoded = form_body(&fields, &field_order);
            let answer = send(endpoint, "POST", &headers, Some(&encoded), self.tls_ca(), "protocol")?;
            if let Some(dpop) = &self.dpop {
                dpop.remember_nonce(endpoint, &answer.dpop_nonce);
            }
            let parsed: Value = if answer.body.is_empty() {
                Value::Object(JsonMap::new())
            } else {
                serde_json::from_str(&answer.body).map_err(|err| OidcError::new("protocol", format!("{endpoint} answered {} with no JSON: {err}", answer.status)))?
            };
            let doc = as_map(&parsed).cloned().unwrap_or_default();
            if answer.status != 200 && answer.status != 201 {
                let oauth = doc.get("error").and_then(|v| v.as_str()).unwrap_or("");
                if self.dpop.is_some() && answer.status == 400 && oauth == "use_dpop_nonce" && attempt == 1 && !answer.dpop_nonce.is_empty() {
                    continue;
                }
                let description = doc.get("error_description").and_then(|v| v.as_str()).unwrap_or("");
                let mut message = format!("{endpoint} answered {}", answer.status);
                if !oauth.is_empty() {
                    message.push_str(": ");
                    message.push_str(oauth);
                }
                if !description.is_empty() {
                    message.push_str(": ");
                    message.push_str(description);
                }
                return Err(OidcError::oauth("protocol", message, oauth));
            }
            return Ok((doc, self.dpop.is_some()));
        }
    }

    /// The `Authorization` header (and `DPoP` proof, with `ath`) for a resource request
    /// made with an access token of `token_type`.
    pub fn resource_headers(&self, method: &str, url: &str, access_token: &str, token_type: &str) -> Result<Vec<(String, String)>, OidcError> {
        if token_type.eq_ignore_ascii_case("dpop") {
            let dpop = self.dpop.as_ref().ok_or_else(|| OidcError::new("protocol", "this access token is DPoP-bound and this client holds no DPoP key"))?;
            return Ok(vec![("authorization".into(), format!("DPoP {access_token}")), ("dpop".into(), dpop.proof(method, url, Some(access_token))?)]);
        }
        Ok(vec![("authorization".into(), format!("Bearer {access_token}"))])
    }

    /// A resource request. With a DPoP-bound token, a 401 carrying
    /// `WWW-Authenticate: DPoP error="use_dpop_nonce"` is retried once with the nonce it gave.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn send_resource(&self, method: &str, url: &str, access_token: &str, token_type: &str, extra: &[(String, String)], body: Option<&str>, ca: Option<&str>, code: &str) -> Result<Answer, OidcError> {
        let bound = token_type.eq_ignore_ascii_case("dpop");
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut headers = extra.to_vec();
            headers.extend(self.resource_headers(method, url, access_token, token_type)?);
            let answer = send(url, method, &headers, body, ca, code)?;
            if bound {
                if let Some(dpop) = &self.dpop {
                    dpop.remember_nonce(url, &answer.dpop_nonce);
                }
                if attempt == 1 && resource_wants_nonce(answer.status, &answer.www_authenticate) && !answer.dpop_nonce.is_empty() {
                    continue;
                }
            }
            return Ok(answer);
        }
    }

    /// `complete`, and the tokens kept in the session cache under `session_id`
    /// (a new random handle when it is empty, returned as `Login::session_id`).
    pub fn complete_session(&self, query: &HashMap<String, String>, txn: &Transaction, session_id: &str) -> Result<Login, OidcError> {
        let mut login = self.complete(query, txn)?;
        login.session_id = if session_id.is_empty() { random_token() } else { session_id.to_string() };
        self.store().set(&login.session_id, login.clone());
        Ok(login)
    }

    /// The cached sign-in of a session, if any.
    pub fn session(&self, session_id: &str) -> Option<Login> {
        self.store().get(session_id)
    }

    /// A valid access token for a session: the cached one while it has more than 30
    /// seconds left, otherwise one obtained with the refresh token (with a DPoP proof when
    /// DPoP is in use), and the cache is updated. A failed refresh removes the entry.
    pub fn session_access_token(&self, session_id: &str) -> Result<Access, OidcError> {
        let store = self.store();
        let fresh = |login: &Login| login.expires_at.map_or(true, |at| at - now_sec() > SESSION_REFRESH_MARGIN_SEC);
        let login = store.get(session_id).ok_or_else(|| OidcError::new("protocol", "there is no cached sign-in for this session"))?;
        if fresh(&login) {
            return Ok(login.access());
        }
        let _one = self.refreshing.lock().unwrap_or_else(|e| e.into_inner());
        // Another caller may have refreshed while this one waited.
        let login = store.get(session_id).ok_or_else(|| OidcError::new("protocol", "there is no cached sign-in for this session"))?;
        if fresh(&login) {
            return Ok(login.access());
        }
        if login.refresh_token.is_empty() {
            store.remove(session_id);
            return Err(OidcError::new("protocol", "the session's access token has expired and there is no refresh token"));
        }
        match self.refresh(&login.refresh_token, "", Some(&login)) {
            Ok(mut refreshed) => {
                refreshed.session_id = session_id.to_string();
                store.set(session_id, refreshed.clone());
                Ok(refreshed.access())
            }
            Err(err) => {
                store.remove(session_id);
                Err(OidcError::oauth(&err.code, format!("the session's refresh was refused: {}", err.message), &err.oauth_error))
            }
        }
    }

    /// Clears a session's cached tokens (sign-out, a CAEP session-revoked).
    pub fn remove_session(&self, session_id: &str) {
        self.store().remove(session_id);
    }

    fn remember_code(&self, code: &str) -> Result<(), OidcError> {
        let now = now_sec();
        let key = hex_encode(&Sha256::digest(code.as_bytes()));
        let mut used = self.used_codes.lock().unwrap_or_else(|e| e.into_inner());
        used.retain(|_, at| *at >= now - 600.0);
        if used.contains_key(&key) {
            return Err(OidcError::new("validation", "this authorization code was already used"));
        }
        used.insert(key, now);
        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn trim_float(value: f64) -> String {
    let text = serde_json::to_string(&value).unwrap_or_else(|_| "0".into());
    text
}

fn claim_string(claims: &JsonMap, name: &str) -> String {
    claims.get(name).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn login_from(tokens: TokenResponse, claims: JsonMap) -> Login {
    let expires_at = tokens.expires_in.map(|secs| now_sec() + secs);
    Login {
        subject: map_str(&claims, "sub"),
        issuer: map_str(&claims, "iss"),
        email: claim_string(&claims, "email"),
        name: claim_string(&claims, "name"),
        preferred_username: claim_string(&claims, "preferred_username"),
        sid: claim_string(&claims, "sid"),
        claims,
        access_token: tokens.access_token,
        id_token: tokens.id_token,
        token_type: tokens.token_type,
        refresh_token: tokens.refresh_token,
        expires_at,
        scope: tokens.scope,
        session_id: String::new(),
    }
}

fn access_from(tokens: &TokenResponse) -> Access {
    Access {
        access_token: tokens.access_token.clone(),
        token_type: tokens.token_type.clone(),
        expires_at: tokens.expires_in.map(|secs| now_sec() + secs),
        scope: tokens.scope.clone(),
    }
}
