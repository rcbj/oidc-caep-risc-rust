// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

use crate::b64::b64url_decode;
use crate::discovery::well_known_urls;
use crate::error::OidcError;
use crate::http::send;
use crate::keys::{public_key_from_jwk, verify_signature, SUPPORTED_JWS};
use crate::value::{as_f64, as_map, as_map_owned, as_string_list, clip, contains_str, is_exact_true, json_compact, map_str, sprint, JsonMap};

const POLL_METHOD: &str = "urn:ietf:rfc:8936";
const CAEP: &str = "https://schemas.openid.net/secevent/caep/event-type/";
const RISC: &str = "https://schemas.openid.net/secevent/risc/event-type/";
const SSF: &str = "https://schemas.openid.net/secevent/ssf/event-type/";

fn now_sec() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Short names for CAEP, RISC, and SSF event types.
pub fn event_map() -> HashMap<&'static str, String> {
    let mut out = HashMap::new();
    let pairs = [
        ("sessionRevoked", format!("{CAEP}session-revoked")),
        ("tokenClaimsChange", format!("{CAEP}token-claims-change")),
        ("credentialChange", format!("{CAEP}credential-change")),
        ("assuranceLevelChange", format!("{CAEP}assurance-level-change")),
        ("deviceComplianceChange", format!("{CAEP}device-compliance-change")),
        ("sessionEstablished", format!("{CAEP}session-established")),
        ("sessionPresented", format!("{CAEP}session-presented")),
        ("riskLevelChange", format!("{CAEP}risk-level-change")),
        ("accountCredentialChangeRequired", format!("{RISC}account-credential-change-required")),
        ("accountPurged", format!("{RISC}account-purged")),
        ("accountDisabled", format!("{RISC}account-disabled")),
        ("accountEnabled", format!("{RISC}account-enabled")),
        ("identifierChanged", format!("{RISC}identifier-changed")),
        ("identifierRecycled", format!("{RISC}identifier-recycled")),
        ("credentialCompromise", format!("{RISC}credential-compromise")),
        ("optIn", format!("{RISC}opt-in")),
        ("optOutInitiated", format!("{RISC}opt-out-initiated")),
        ("optOutCancelled", format!("{RISC}opt-out-cancelled")),
        ("optOutEffective", format!("{RISC}opt-out-effective")),
        ("recoveryActivated", format!("{RISC}recovery-activated")),
        ("recoveryInformationChanged", format!("{RISC}recovery-information-changed")),
        ("sessionsRevoked", format!("{RISC}sessions-revoked")),
        ("verification", format!("{SSF}verification")),
        ("streamUpdated", format!("{SSF}stream-updated")),
    ];
    for (name, uri) in pairs {
        out.insert(name, uri);
    }
    out
}

/// The event-type map. Built once per call; tests compare a few keys.
pub struct Event;

impl Event {
    pub fn get(name: &str) -> String {
        event_map().get(name).cloned().unwrap_or_default()
    }
}

pub fn default_events_requested() -> Vec<String> {
    ["sessionRevoked", "credentialChange", "assuranceLevelChange", "tokenClaimsChange", "accountDisabled", "accountEnabled", "accountPurged", "credentialCompromise", "sessionsRevoked", "accountCredentialChangeRequired"]
        .into_iter()
        .map(Event::get)
        .collect()
}

pub fn default_ending_events() -> Vec<String> {
    ["sessionRevoked", "accountDisabled", "accountPurged", "credentialCompromise", "sessionsRevoked"].into_iter().map(Event::get).collect()
}

fn present<'a>(document: &'a JsonMap, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|name| document.get(*name).filter(|v| !v.is_null()))
}

fn simple_subject(identifier: &JsonMap, issuer: &str) -> HashMap<String, String> {
    let fmt = present(identifier, &["format", "subject_type"]).map(sprint).unwrap_or_default();
    let mut out = HashMap::new();
    match fmt.as_str() {
        "iss_sub" => {
            if let Some(sub) = identifier.get("sub").and_then(|v| v.as_str()) {
                let iss = identifier.get("iss");
                if iss.is_none() || iss.is_some_and(|v| v.is_null()) || sprint(iss.unwrap()) == issuer {
                    out.insert("sub".into(), sub.to_string());
                }
            }
        }
        "email" => {
            if let Some(email) = identifier.get("email").and_then(|v| v.as_str()) {
                out.insert("email".into(), email.to_string());
            }
        }
        "opaque" => {
            if let Some(id) = identifier.get("id").and_then(|v| v.as_str()) {
                out.insert("opaque".into(), id.to_string());
            }
        }
        "aliases" => {
            if let Some(list) = identifier.get("identifiers").and_then(|v| v.as_array()) {
                for one in list {
                    if let Some(doc) = one.as_object() {
                        for (k, v) in simple_subject(doc, issuer) {
                            out.insert(k, v);
                        }
                    }
                }
            }
        }
        _ => {}
    }
    out
}

/// Reads an event's subject. A complex subject's user is the person and its session the provider session.
pub fn subject_of(sub_id: Option<&JsonMap>, issuer: &str) -> HashMap<String, String> {
    let Some(sub_id) = sub_id else {
        return HashMap::new();
    };
    let fmt = present(sub_id, &["format", "subject_type"]).map(sprint).unwrap_or_default();
    let has_user = sub_id.get("user").is_some_and(|v| !v.is_null());
    let has_session = sub_id.get("session").is_some_and(|v| !v.is_null());
    if fmt == "complex" || (fmt.is_empty() && (has_user || has_session)) {
        let user = sub_id.get("user").and_then(as_map).map(|doc| simple_subject(doc, issuer)).unwrap_or_default();
        let session = sub_id.get("session").and_then(as_map).map(|doc| simple_subject(doc, issuer)).unwrap_or_default();
        let mut out = HashMap::new();
        if let Some(person) = user.get("sub").filter(|v| !v.is_empty()) {
            out.insert("person".into(), person.clone());
        }
        if let Some(email) = user.get("email").filter(|v| !v.is_empty()) {
            out.insert("email".into(), email.clone());
        }
        let session_id = session.get("opaque").filter(|v| !v.is_empty()).or_else(|| session.get("sub").filter(|v| !v.is_empty()));
        if let Some(id) = session_id {
            out.insert("idpSession".into(), id.clone());
        }
        return out;
    }
    let one = simple_subject(sub_id, issuer);
    let mut out = HashMap::new();
    if let Some(person) = one.get("sub").filter(|v| !v.is_empty()) {
        out.insert("person".into(), person.clone());
    }
    if let Some(email) = one.get("email").filter(|v| !v.is_empty()) {
        out.insert("email".into(), email.clone());
    }
    out
}

/// Verifies a compact JWS against the keys of a JWKS. The key comes from the JWKS, never from the token.
pub fn verify_compact_jws(token: &str, keys: &[JsonMap]) -> Result<(JsonMap, JsonMap), OidcError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(OidcError::new("signature", "the SET is not a compact JWS"));
    }
    let header_raw = b64url_decode(parts[0], "header").map_err(|err| OidcError::new("signature", format!("the SET's header is not base64url: {err}")))?;
    let payload_raw = b64url_decode(parts[1], "payload").map_err(|err| OidcError::new("signature", format!("the SET's payload is not base64url: {err}")))?;
    let header_val: Value = serde_json::from_slice(&header_raw).map_err(|err| OidcError::new("signature", format!("the SET's header or payload is not JSON: {err}")))?;
    let payload_val: Value = serde_json::from_slice(&payload_raw).map_err(|err| OidcError::new("signature", format!("the SET's header or payload is not JSON: {err}")))?;
    let header = as_map_owned(header_val).ok_or_else(|| OidcError::new("signature", "the SET's header or payload is not a JSON object"))?;
    let payload = as_map_owned(payload_val).ok_or_else(|| OidcError::new("signature", "the SET's header or payload is not a JSON object"))?;
    let alg = map_str(&header, "alg");
    let known = matches!(alg.as_str(), "RS256" | "RS384" | "RS512");
    if !known {
        let shown = if alg.is_empty() { "(no alg)" } else { alg.as_str() };
        return Err(OidcError::new("signature", format!("the SET is signed with {shown}, which this receiver does not verify ({})", SUPPORTED_JWS.join(", "))));
    }
    if header.get("crit").is_some_and(|v| !v.is_null()) {
        return Err(OidcError::new("signature", "the SET's header has a crit member this receiver does not understand"));
    }
    let kid = header.get("kid").and_then(|v| v.as_str()).unwrap_or("");
    let matched: Vec<&JsonMap> = keys
        .iter()
        .filter(|jwk| kid.is_empty() || map_str(jwk, "kid") == kid)
        .filter(|jwk| map_str(jwk, "kty") == "RSA")
        .filter(|jwk| {
            let use_ = jwk.get("use").map(sprint).unwrap_or_default();
            use_.is_empty() || use_ == "sig"
        })
        .filter(|jwk| {
            let named = jwk.get("alg").map(sprint).unwrap_or_default();
            named.is_empty() || named == alg
        })
        .collect();
    if matched.is_empty() {
        let suffix = if kid.is_empty() { String::new() } else { format!(" with kid {kid}") };
        return Err(OidcError::new("signature", format!("the transmitter publishes no RSA signing key{suffix}")));
    }
    let signature = b64url_decode(parts[2], "signature").map_err(|err| OidcError::new("signature", format!("the SET's signature is not base64url: {err}")))?;
    let data = format!("{}.{}", parts[0], parts[1]);
    for jwk in matched {
        let key = public_key_from_jwk(jwk)?;
        if verify_signature(&key, &alg, data.as_bytes(), &signature) {
            return Ok((header, payload));
        }
    }
    Err(OidcError::new("signature", "the SET's signature does not verify against the transmitter's keys"))
}

struct SessionIndex {
    max: usize,
    order: Vec<String>,
    sessions: HashMap<String, JsonMap>,
}

impl SessionIndex {
    fn new(max: usize) -> Self {
        Self { max: if max == 0 { 100_000 } else { max }, order: Vec::new(), sessions: HashMap::new() }
    }

    fn add(&mut self, session: JsonMap) {
        let local_id = map_str(&session, "local_id");
        if self.sessions.len() >= self.max && !self.sessions.contains_key(&local_id) {
            let now = now_sec();
            self.order.retain(|key| {
                let Some(value) = self.sessions.get(key) else {
                    return false;
                };
                if let Some(exp) = value.get("expires_at").and_then(as_f64) {
                    if exp <= now {
                        return false;
                    }
                }
                true
            });
            self.sessions.retain(|key, value| {
                if let Some(exp) = value.get("expires_at").and_then(as_f64) {
                    if exp <= now {
                        return false;
                    }
                }
                self.order.iter().any(|item| item == key)
            });
            while self.sessions.len() >= self.max && !self.order.is_empty() {
                let oldest = self.order.remove(0);
                self.sessions.remove(&oldest);
            }
        }
        let mut stored = session;
        if let Some(email) = stored.get("email").and_then(|v| v.as_str()) {
            if !email.is_empty() {
                stored.insert("email".into(), Value::String(email.to_ascii_lowercase()));
            }
        }
        if !self.sessions.contains_key(&local_id) {
            self.order.push(local_id.clone());
        }
        self.sessions.insert(local_id, stored);
    }

    fn remove(&mut self, local_id: &str) {
        if self.sessions.remove(local_id).is_some() {
            self.order.retain(|key| key != local_id);
        }
    }

    fn find<F: Fn(&JsonMap) -> bool>(&mut self, match_fn: F) -> Vec<String> {
        let now = now_sec();
        let mut out = Vec::new();
        let mut kept = Vec::new();
        for key in self.order.drain(..) {
            let Some(value) = self.sessions.get(&key) else {
                continue;
            };
            if let Some(exp) = value.get("expires_at").and_then(as_f64) {
                if exp <= now {
                    self.sessions.remove(&key);
                    continue;
                }
            }
            if match_fn(value) {
                out.push(key.clone());
            }
            kept.push(key);
        }
        self.order = kept;
        out
    }
}

#[derive(Clone, Debug)]
pub struct SignalEvent {
    pub event_type: String,
    pub payload: JsonMap,
    pub subject: HashMap<String, String>,
    pub jti: String,
    pub sessions: Vec<String>,
    pub ended: bool,
    pub iat: Option<f64>,
    pub txn: String,
}

pub struct ReceiverOptions {
    pub tls_ca: Option<String>,
    pub headers: Option<Arc<dyn Fn() -> Vec<(String, String)> + Send + Sync>>,
    pub events_requested: Vec<String>,
    pub end_on: Vec<String>,
    pub description: String,
    pub poll_interval_ms: i64,
    pub max_events: i64,
}

impl Default for ReceiverOptions {
    fn default() -> Self {
        Self { tls_ca: None, headers: None, events_requested: Vec::new(), end_on: Vec::new(), description: String::new(), poll_interval_ms: 0, max_events: 0 }
    }
}

struct Shared {
    config: Option<JsonMap>,
    stream: Option<JsonMap>,
    keys: Vec<JsonMap>,
    keys_at: f64,
    running: bool,
    ack: Vec<String>,
    errs: Map<String, Value>,
    handlers: HashMap<String, Vec<Arc<dyn Fn(SignalEvent) + Send + Sync>>>,
    inflight_done: bool,
    inflight: Option<Arc<(Mutex<Option<Result<bool, String>>>, std::sync::Condvar)>>,
}

/// Finds or creates this application's poll stream and turns events into local sessions.
pub struct SignalsReceiver {
    transmitter: String,
    on_end: Arc<dyn Fn(Vec<String>, SignalEvent) + Send + Sync>,
    tls_ca: Option<String>,
    headers: Option<Arc<dyn Fn() -> Vec<(String, String)> + Send + Sync>>,
    events_requested: Vec<String>,
    end_on: Vec<String>,
    description: String,
    poll_ms: i64,
    max_events: i64,
    index: Arc<Mutex<SessionIndex>>,
    shared: Arc<Mutex<Shared>>,
    stop: Arc<Mutex<bool>>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl SignalsReceiver {
    pub fn new(transmitter: &str, on_end: Arc<dyn Fn(Vec<String>, SignalEvent) + Send + Sync>, opts: ReceiverOptions) -> Result<Self, OidcError> {
        if transmitter.is_empty() || !(transmitter.starts_with("http://") || transmitter.starts_with("https://")) {
            return Err(OidcError::new("config", "transmitter must be an http(s) URL"));
        }
        let events = if opts.events_requested.is_empty() { default_events_requested() } else { opts.events_requested };
        let end_on = if opts.end_on.is_empty() { default_ending_events() } else { opts.end_on };
        let poll = if opts.poll_interval_ms <= 0 { 5000 } else { opts.poll_interval_ms };
        let max_events = if opts.max_events <= 0 { 50 } else { opts.max_events };
        Ok(Self {
            transmitter: transmitter.trim_end_matches('/').to_string(),
            on_end,
            tls_ca: opts.tls_ca,
            headers: opts.headers,
            events_requested: events,
            end_on,
            description: opts.description,
            poll_ms: poll,
            max_events,
            index: Arc::new(Mutex::new(SessionIndex::new(0))),
            shared: Arc::new(Mutex::new(Shared {
                config: None,
                stream: None,
                keys: Vec::new(),
                keys_at: 0.0,
                running: false,
                ack: Vec::new(),
                errs: Map::new(),
                handlers: HashMap::new(),
                inflight_done: true,
                inflight: None,
            })),
            stop: Arc::new(Mutex::new(false)),
            thread: Mutex::new(None),
        })
    }

    pub fn stream(&self) -> Option<JsonMap> {
        self.shared.lock().unwrap_or_else(|e| e.into_inner()).stream.clone()
    }

    pub fn track(&self, session: JsonMap) {
        self.index.lock().unwrap_or_else(|e| e.into_inner()).add(session);
    }

    pub fn untrack(&self, local_id: &str) {
        self.index.lock().unwrap_or_else(|e| e.into_inner()).remove(local_id);
    }

    pub fn on<F>(&self, event_type: &str, handler: F)
    where
        F: Fn(SignalEvent) + Send + Sync + 'static,
    {
        self.shared.lock().unwrap_or_else(|e| e.into_inner()).handlers.entry(event_type.to_string()).or_default().push(Arc::new(handler));
    }

    pub fn start(&self) -> Result<(), OidcError> {
        if self.shared.lock().unwrap_or_else(|e| e.into_inner()).running {
            return Ok(());
        }
        let cfg = self.discover()?;
        {
            self.shared.lock().unwrap_or_else(|e| e.into_inner()).config = Some(cfg);
        }
        self.jwks(true)?;
        let stream = self.ensure_stream()?;
        let endpoint = stream.get("delivery").and_then(as_map).map(|d| map_str(d, "endpoint_url")).unwrap_or_default();
        if endpoint.is_empty() {
            return Err(OidcError::new("ssf", "the stream has no poll endpoint_url"));
        }
        {
            let mut shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            if shared.running {
                shared.stream = Some(stream);
                return Ok(());
            }
            shared.stream = Some(stream);
            shared.running = true;
        }
        *self.stop.lock().unwrap_or_else(|e| e.into_inner()) = false;
        let worker = self.worker();
        let handle = thread::spawn(move || worker.loop_poll());
        *self.thread.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
        Ok(())
    }

    /// Stops polling and waits until the background poll has finished.
    pub fn stop(&self) {
        {
            let mut shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            shared.running = false;
        }
        *self.stop.lock().unwrap_or_else(|e| e.into_inner()) = true;
        let handle = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(handle) = handle {
            let started = Instant::now();
            while !handle.is_finished() && started.elapsed() < Duration::from_secs(20) {
                thread::sleep(Duration::from_millis(20));
            }
            if handle.is_finished() {
                let _ = handle.join();
            }
        }
    }

    pub fn poll_once(&self) -> Result<bool, OidcError> {
        self.worker().poll_once()
    }

    pub fn verify(&self, state: &str) -> Result<(), OidcError> {
        self.worker().verify(state)
    }

    fn worker(&self) -> Worker {
        Worker {
            on_end: Arc::clone(&self.on_end),
            tls_ca: self.tls_ca.clone(),
            headers: self.headers.clone(),
            end_on: self.end_on.clone(),
            poll_ms: self.poll_ms,
            max_events: self.max_events,
            index: Arc::clone(&self.index),
            shared: Arc::clone(&self.shared),
            stop: Arc::clone(&self.stop),
        }
    }
}

struct Worker {
    on_end: Arc<dyn Fn(Vec<String>, SignalEvent) + Send + Sync>,
    tls_ca: Option<String>,
    headers: Option<Arc<dyn Fn() -> Vec<(String, String)> + Send + Sync>>,
    end_on: Vec<String>,
    poll_ms: i64,
    max_events: i64,
    index: Arc<Mutex<SessionIndex>>,
    shared: Arc<Mutex<Shared>>,
    stop: Arc<Mutex<bool>>,
}

impl Worker {
    fn loop_poll(&self) {
        loop {
            let running = self.shared.lock().unwrap_or_else(|e| e.into_inner()).running;
            if !running {
                return;
            }
            let polled = self.poll_once();
            let mut delay = self.poll_ms;
            match &polled {
                Ok(true) => delay = 0,
                Ok(false) => {}
                Err(err) => {
                    eprintln!("ssf: poll failed: {err}");
                    delay = (self.poll_ms * 4).min(60_000);
                }
            }
            if !self.shared.lock().unwrap_or_else(|e| e.into_inner()).running {
                return;
            }
            let started = Instant::now();
            while started.elapsed() < Duration::from_millis(delay as u64) {
                if *self.stop.lock().unwrap_or_else(|e| e.into_inner()) {
                    return;
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
    }

    fn poll_once(&self) -> Result<bool, OidcError> {
        let flight = {
            let mut shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            let finished = match &shared.inflight {
                None => true,
                Some(existing) => existing.0.lock().unwrap_or_else(|e| e.into_inner()).is_some(),
            };
            if finished {
                let flight = Arc::new((Mutex::new(None), std::sync::Condvar::new()));
                shared.inflight = Some(Arc::clone(&flight));
                let worker = self.clone_worker();
                let background = Arc::clone(&flight);
                thread::spawn(move || {
                    let result = worker.poll_now().map_err(|err| err.message);
                    let mut slot = background.0.lock().unwrap_or_else(|e| e.into_inner());
                    *slot = Some(result);
                    background.1.notify_all();
                });
                flight
            } else {
                Arc::clone(shared.inflight.as_ref().unwrap())
            }
        };
        let mut slot = flight.0.lock().unwrap_or_else(|e| e.into_inner());
        while slot.is_none() {
            slot = flight.1.wait(slot).unwrap_or_else(|e| e.into_inner());
        }
        match slot.clone().unwrap() {
            Ok(more) => Ok(more),
            Err(message) => Err(OidcError::new("ssf", message)),
        }
    }

    fn clone_worker(&self) -> Worker {
        Worker {
            on_end: Arc::clone(&self.on_end),
            tls_ca: self.tls_ca.clone(),
            headers: self.headers.clone(),
            end_on: self.end_on.clone(),
            poll_ms: self.poll_ms,
            max_events: self.max_events,
            index: Arc::clone(&self.index),
            shared: Arc::clone(&self.shared),
            stop: Arc::clone(&self.stop),
        }
    }

    fn poll_now(&self) -> Result<bool, OidcError> {
        let (stream, ack, set_errs) = {
            let mut shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            let stream = shared.stream.clone().unwrap_or_default();
            let ack = std::mem::take(&mut shared.ack);
            let set_errs = std::mem::take(&mut shared.errs);
            (stream, ack, set_errs)
        };
        let endpoint = stream.get("delivery").and_then(as_map).map(|d| map_str(d, "endpoint_url")).unwrap_or_default();
        let mut body = serde_json::json!({"maxEvents": self.max_events, "returnImmediately": true});
        if !ack.is_empty() {
            body["ack"] = Value::Array(ack.iter().cloned().map(Value::String).collect());
        }
        if !set_errs.is_empty() {
            body["setErrs"] = Value::Object(set_errs.clone());
        }
        let answer = self.call("POST", &endpoint, Some(&body));
        let (status, parsed, raw) = match answer {
            Ok(value) => value,
            Err(err) => {
                self.restore(ack, set_errs);
                return Err(err);
            }
        };
        if status != 200 {
            self.restore(ack, set_errs);
            return Err(OidcError::new("ssf", format!("the poll answered {status}: {}", clip(&json_compact(&parsed), 300))));
        }
        let sets = parsed.get("sets").and_then(as_map).cloned().unwrap_or_default();
        for (jti, token) in &sets {
            let Some(token) = token.as_str() else {
                continue;
            };
            if let Err(err) = self.handle(jti, token) {
                eprintln!("ssf: SET {jti} refused: {err}");
                let code = if err.code == "signature" { "invalid_key" } else { "invalid_request" };
                let mut shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
                let mut doc = Map::new();
                doc.insert("err".into(), Value::String(code.into()));
                doc.insert("description".into(), Value::String(err.message.clone()));
                shared.errs.insert(jti.clone(), Value::Object(doc));
            } else {
                self.shared.lock().unwrap_or_else(|e| e.into_inner()).ack.push(jti.clone());
            }
        }
        let _ = raw;
        Ok(parsed.get("moreAvailable").is_some_and(is_exact_true))
    }

    fn restore(&self, ack: Vec<String>, set_errs: Map<String, Value>) {
        let mut shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        let mut merged = ack;
        merged.append(&mut shared.ack);
        shared.ack = merged;
        for (key, value) in set_errs {
            shared.errs.entry(key).or_insert(value);
        }
    }

    fn handle(&self, jti: &str, token: &str) -> Result<(), OidcError> {
        let keys = self.jwks(false)?;
        let verified = match verify_compact_jws(token, &keys) {
            Ok(value) => value,
            Err(err) if err.code == "signature" && (err.message.contains("publishes no") || err.message.contains("does not verify")) => {
                let keys = self.jwks(true).map_err(|_| err.clone_message())?;
                verify_compact_jws(token, &keys)?
            }
            Err(err) => return Err(err),
        };
        let (header, payload) = verified;
        if let Some(typ) = header.get("typ").filter(|v| !v.is_null()) {
            if sprint(typ).to_ascii_lowercase() != "secevent+jwt" {
                return Err(OidcError::new("validation", format!("the SET's typ is {typ}")));
            }
        }
        let (issuer, stream) = {
            let shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            (shared.config.as_ref().map(|c| map_str(c, "issuer")).unwrap_or_default(), shared.stream.clone().unwrap_or_default())
        };
        if map_str(&payload, "iss") != issuer {
            return Err(OidcError::new("validation", format!("the SET was issued by {}, not {issuer}", payload.get("iss").map(sprint).unwrap_or_default())));
        }
        let want = match stream.get("aud") {
            Some(Value::Array(list)) => list.iter().map(sprint).collect::<Vec<_>>(),
            Some(other) if !other.is_null() && !sprint(other).is_empty() => vec![sprint(other)],
            _ => Vec::new(),
        };
        let aud = match payload.get("aud") {
            Some(Value::Array(list)) => list.iter().map(sprint).collect::<Vec<_>>(),
            Some(other) if !other.is_null() => vec![sprint(other)],
            _ => Vec::new(),
        };
        if !want.is_empty() && !aud.iter().any(|one| contains_str(&want, one)) {
            return Err(OidcError::new("validation", format!("the SET is for {}, not this stream", aud.join(", "))));
        }
        if let Some(named) = payload.get("jti").filter(|v| !v.is_null()) {
            if sprint(named) != jti {
                return Err(OidcError::new("validation", "the SET's jti is not the one it was delivered under"));
            }
        }
        let events = payload.get("events").and_then(as_map).cloned().unwrap_or_default();
        if events.is_empty() {
            return Err(OidcError::new("validation", "the SET carries no events"));
        }
        for (event_type, body) in events {
            let body_map = body.as_object().cloned().unwrap_or_default();
            let subject_src = if payload.get("sub_id").is_some_and(|v| !v.is_null()) {
                payload.get("sub_id").and_then(as_map).cloned()
            } else {
                body_map.get("subject").and_then(as_map).cloned()
            };
            let subject = subject_of(subject_src.as_ref(), &issuer);
            let sessions = self.sessions_for(&event_type, &subject);
            let mut ended = self.end_on.iter().any(|item| item == &event_type) && !sessions.is_empty();
            let mut event = SignalEvent {
                event_type: event_type.clone(),
                payload: if body.is_object() { body_map.clone() } else { JsonMap::new() },
                subject,
                jti: jti.to_string(),
                sessions: sessions.clone(),
                ended,
                iat: payload.get("iat").and_then(as_f64),
                txn: payload.get("txn").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            };
            if ended {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.on_end)(sessions.clone(), event.clone())));
                if result.is_err() {
                    eprintln!("ssf: onEndSessions threw for {event_type} (SET {jti} is still acknowledged)");
                    ended = false;
                    event.ended = false;
                } else {
                    for local_id in &sessions {
                        self.index.lock().unwrap_or_else(|e| e.into_inner()).remove(local_id);
                    }
                }
            }
            let handlers = {
                let shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
                let mut list = shared.handlers.get(&event_type).cloned().unwrap_or_default();
                if let Some(star) = shared.handlers.get("*") {
                    list.extend(star.clone());
                }
                list
            };
            for handler in handlers {
                let event = event.clone();
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(event)));
            }
        }
        Ok(())
    }

    fn sessions_for(&self, event_type: &str, subject: &HashMap<String, String>) -> Vec<String> {
        if event_type == Event::get("verification") || event_type == Event::get("streamUpdated") {
            return Vec::new();
        }
        if let Some(idp) = subject.get("idpSession").filter(|v| !v.is_empty()) {
            let found = self.index.lock().unwrap_or_else(|e| e.into_inner()).find(|session| map_str(session, "idp_session") == *idp);
            if !found.is_empty() || event_type == Event::get("sessionRevoked") {
                return found;
            }
        }
        if let Some(person) = subject.get("person").filter(|v| !v.is_empty()) {
            return self.index.lock().unwrap_or_else(|e| e.into_inner()).find(|session| map_str(session, "person") == *person);
        }
        if let Some(email) = subject.get("email").filter(|v| !v.is_empty()) {
            let wanted = email.to_ascii_lowercase();
            return self.index.lock().unwrap_or_else(|e| e.into_inner()).find(|session| map_str(session, "email") == wanted);
        }
        Vec::new()
    }

    fn verify(&self, state: &str) -> Result<(), OidcError> {
        let (endpoint, stream_id) = {
            let shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            let endpoint = shared.config.as_ref().map(|c| map_str(c, "verification_endpoint")).unwrap_or_default();
            let stream_id = shared.stream.as_ref().map(|s| map_str(s, "stream_id")).unwrap_or_default();
            (endpoint, stream_id)
        };
        if endpoint.is_empty() {
            return Err(OidcError::new("ssf", "the transmitter publishes no verification_endpoint"));
        }
        let mut body = serde_json::json!({"stream_id": stream_id});
        if !state.is_empty() {
            body["state"] = Value::String(state.to_string());
        }
        let (status, _, _) = self.call("POST", &endpoint, Some(&body))?;
        if status != 200 && status != 204 {
            return Err(OidcError::new("ssf", format!("verification answered {status}")));
        }
        Ok(())
    }

    fn jwks(&self, force: bool) -> Result<Vec<JsonMap>, OidcError> {
        {
            let shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            if !force && !shared.keys.is_empty() && now_sec() - shared.keys_at < 3600.0 {
                return Ok(shared.keys.clone());
            }
        }
        let uri = self.shared.lock().unwrap_or_else(|e| e.into_inner()).config.as_ref().map(|c| map_str(c, "jwks_uri")).unwrap_or_default();
        let (status, parsed, _) = self.call("GET", &uri, None)?;
        let doc = parsed.as_object().cloned().unwrap_or_default();
        let Some(list) = doc.get("keys").and_then(|v| v.as_array()).cloned().filter(|_| status == 200) else {
            return Err(OidcError::new("ssf", format!("the transmitter's JWKS answered {status}")));
        };
        let mut keys = Vec::new();
        for item in list {
            keys.push(as_map_owned(item).ok_or_else(|| OidcError::new("ssf", format!("the transmitter's JWKS answered {status}")))?);
        }
        let mut shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        shared.keys = keys.clone();
        shared.keys_at = now_sec();
        Ok(keys)
    }

    fn call(&self, method: &str, raw_url: &str, body: Option<&Value>) -> Result<(u16, Value, String), OidcError> {
        let mut headers = vec![("accept".into(), "application/json".into())];
        if let Some(extra) = &self.headers {
            headers.extend(extra());
        }
        let payload = if let Some(body) = body {
            let text = serde_json::to_string(body).map_err(|err| OidcError::new("ssf", err.to_string()))?;
            headers.push(("content-type".into(), "application/json".into()));
            Some(text)
        } else {
            None
        };
        let answer = send(raw_url, method, &headers, payload.as_deref(), self.tls_ca.as_deref(), "ssf")?;
        let parsed = if answer.body.is_empty() { Value::Null } else { serde_json::from_str(&answer.body).unwrap_or(Value::String(answer.body.clone())) };
        Ok((answer.status, parsed, answer.body))
    }
}

impl OidcError {
    fn clone_message(&self) -> OidcError {
        OidcError { code: self.code.clone(), message: self.message.clone(), oauth_error: self.oauth_error.clone() }
    }
}

impl SignalsReceiver {
    fn call(&self, method: &str, raw_url: &str, body: Option<&Value>) -> Result<(u16, Value, String), OidcError> {
        let mut headers = vec![("accept".into(), "application/json".into())];
        if let Some(extra) = &self.headers {
            headers.extend(extra());
        }
        let payload = if let Some(body) = body {
            let text = serde_json::to_string(body).map_err(|err| OidcError::new("ssf", err.to_string()))?;
            headers.push(("content-type".into(), "application/json".into()));
            Some(text)
        } else {
            None
        };
        let answer = send(raw_url, method, &headers, payload.as_deref(), self.tls_ca.as_deref(), "ssf")?;
        let parsed = if answer.body.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&answer.body).unwrap_or(Value::String(answer.body.clone()))
        };
        Ok((answer.status, parsed, answer.body))
    }

    fn discover(&self) -> Result<JsonMap, OidcError> {
        let urls = well_known_urls(&self.transmitter, "ssf-configuration");
        let mut last = OidcError::new("ssf", format!("no transmitter configuration at {}", urls.join(" or ")));
        for (i, one) in urls.iter().enumerate() {
            let (status, parsed, _) = self.call("GET", one, None)?;
            let doc = parsed.as_object().cloned().unwrap_or_default();
            if status == 404 && i + 1 != urls.len() {
                continue;
            }
            if status != 200 || map_str(&doc, "configuration_endpoint").is_empty() || map_str(&doc, "jwks_uri").is_empty() {
                last = OidcError::new("ssf", format!("{one} answered {status} without a usable transmitter configuration"));
                continue;
            }
            if let Some(methods) = as_string_list(doc.get("delivery_methods_supported").unwrap_or(&Value::Null)) {
                if !methods.is_empty() && !contains_str(&methods, POLL_METHOD) {
                    return Err(OidcError::new("ssf", "the transmitter does not offer poll delivery (RFC 8936)"));
                }
            }
            return Ok(doc);
        }
        Err(last)
    }

    fn jwks(&self, force: bool) -> Result<Vec<JsonMap>, OidcError> {
        {
            let shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            if !force && !shared.keys.is_empty() && now_sec() - shared.keys_at < 3600.0 {
                return Ok(shared.keys.clone());
            }
        }
        let uri = self.shared.lock().unwrap_or_else(|e| e.into_inner()).config.as_ref().map(|c| map_str(c, "jwks_uri")).unwrap_or_default();
        let (status, parsed, _) = self.call("GET", &uri, None)?;
        let doc = parsed.as_object().cloned().unwrap_or_default();
        let list = doc.get("keys").and_then(|v| v.as_array()).cloned();
        let Some(list) = list.filter(|_| status == 200) else {
            return Err(OidcError::new("ssf", format!("the transmitter's JWKS answered {status}")));
        };
        let mut keys = Vec::new();
        for item in list {
            let Some(key) = as_map_owned(item) else {
                return Err(OidcError::new("ssf", format!("the transmitter's JWKS answered {status}")));
            };
            keys.push(key);
        }
        let mut shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        shared.keys = keys.clone();
        shared.keys_at = now_sec();
        Ok(keys)
    }

    fn ensure_stream(&self) -> Result<JsonMap, OidcError> {
        let endpoint = self.shared.lock().unwrap_or_else(|e| e.into_inner()).config.as_ref().map(|c| map_str(c, "configuration_endpoint")).unwrap_or_default();
        let (status, parsed, _) = self.call("GET", &endpoint, None)?;
        if status == 200 {
            let all = match &parsed {
                Value::Array(list) => list.clone(),
                Value::Null => Vec::new(),
                other => vec![other.clone()],
            };
            for item in all {
                if let Some(stream) = item.as_object() {
                    let method = stream.get("delivery").and_then(as_map).map(|d| map_str(d, "method")).unwrap_or_default();
                    if method == POLL_METHOD && !map_str(stream, "stream_id").is_empty() {
                        return Ok(stream.clone());
                    }
                }
            }
        } else if status != 404 {
            return Err(OidcError::new("ssf", format!("listing the streams at {endpoint} answered {status}: {}", clip(&json_compact(&parsed), 300))));
        }
        let mut body = serde_json::json!({"delivery": {"method": POLL_METHOD}, "events_requested": self.events_requested});
        if !self.description.is_empty() {
            body["description"] = Value::String(self.description.clone());
        }
        let (created_status, created, _) = self.call("POST", &endpoint, Some(&body))?;
        let stream = created.as_object().cloned().unwrap_or_default();
        if (created_status != 200 && created_status != 201) || map_str(&stream, "stream_id").is_empty() {
            return Err(OidcError::new("ssf", format!("creating a stream at {endpoint} answered {created_status}: {}", clip(&json_compact(&created), 300))));
        }
        Ok(stream)
    }
}
