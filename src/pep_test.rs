// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The embedded PEP wired into the relying party (#46): the configuration
//! and its defaults, the three-key refusal, the `Login` adapter, `decide`
//! and `decide_session` against a stub PDP, and the `pep-policies-changed`
//! event handed over by `SignalsReceiver`. The PEP's own behaviour (the
//! credential, both modes, the engine) is iya-pep's suite.

use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

use crate::pep::{subject_of, subject_with_userinfo, Access, Decision, POLICIES_CHANGED_EVENT};
use crate::suite::{deliver, json_res, keys, provider_config, read_req, start_provider, start_transmitter, write_res, Req};
use crate::value::JsonMap;
use crate::{ReceiverOptions, RelyingParty, SignalsReceiver};

/// A stub PDP: the token endpoint, register, heartbeat, the catalogue and
/// the AuthZEN evaluation. `decisions` are answered in order, then Permit.
struct Pdp {
    url: String,
    seen: Mutex<Vec<(String, String, String)>>,
    decisions: Mutex<Vec<bool>>,
    /// `local`: whether the policy pull answers.
    policies_up: std::sync::atomic::AtomicBool,
}

impl Pdp {
    fn count(&self, path: &str) -> usize {
        self.seen.lock().unwrap().iter().filter(|(_, p, _)| p == path).count()
    }

    fn bodies(&self, path: &str) -> Vec<Value> {
        self.seen.lock().unwrap().iter().filter(|(_, p, _)| p == path).map(|(_, _, b)| serde_json::from_str(b).unwrap_or(Value::Null)).collect()
    }
}

fn start_pdp() -> &'static Pdp {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let pdp: &'static Pdp = Box::leak(Box::new(Pdp { url: format!("http://127.0.0.1:{port}/realm/r1"), seen: Mutex::new(Vec::new()), decisions: Mutex::new(Vec::new()), policies_up: std::sync::atomic::AtomicBool::new(true) }));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            if let Some(req) = read_req(&mut stream) {
                let (status, headers, body) = answer(pdp, &req);
                let _ = write_res(&mut stream, status, &headers, &body);
            }
        }
    });
    pdp
}

fn answer(pdp: &Pdp, req: &Req) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let path = req.path.trim_start_matches("/realm/r1").to_string();
    pdp.seen.lock().unwrap().push((req.method.clone(), path.clone(), req.body.clone()));
    if path != "/oauth2/token" && !req.headers.get("authorization").is_some_and(|a| a.starts_with("DPoP ")) {
        return json_res(401, json!({"error": "invalid_token"}));
    }
    match path.as_str() {
        "/oauth2/token" => json_res(200, json!({"access_token": "pep-token", "token_type": "DPoP", "expires_in": 300})),
        "/xacml/pep/register" => json_res(201, json!({"registered": true})),
        "/xacml/pep/heartbeat" => json_res(200, json!({"acknowledged": true, "current": true})),
        "/xacml/pep/authzen-catalogue" => json_res(
            200,
            json!({"syncToken": "c1", "realm": "r1", "rows": [
                {"object": "subject", "property": "acr", "attributeId": "urn:example:acr"},
                {"object": "subject", "property": "email", "attributeId": "urn:example:email"}
            ], "settings": {"obligationsProfile": false}}),
        ),
        "/xacml/pep/policies" if pdp.policies_up.load(std::sync::atomic::Ordering::SeqCst) => json_res(200, json!({"syncToken": "p1", "root": "orders", "policies": [{
            "name": "orders", "policyId": "orders", "kind": "Policy", "version": "1.0", "isRoot": true, "description": "",
            "combiningAlgId": "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit", "document": READ_ONLY}], "withheld": [], "note": ""})),
        "/xacml/pep/policies" => json_res(503, json!({"error": "server_error", "error_description": "not now"})),
        "/admin-api/pep-audit" => json_res(200, json!({"acknowledged": 0})),
        "/access/v1/evaluation" => {
            let mut queue = pdp.decisions.lock().unwrap();
            let decision = if queue.is_empty() { true } else { queue.remove(0) };
            json_res(200, json!({"decision": decision}))
        }
        _ => json_res(404, json!({"error": "not_found"})),
    }
}

/// Permits `read`, and nothing else.
const READ_ONLY: &str = r#"<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="orders" Version="1.0" RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit"><Target/><Rule RuleId="read" Effect="Permit"><Target><AnyOf><AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">read</AttributeValue><AttributeDesignator Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action" AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" DataType="http://www.w3.org/2001/XMLSchema#string" MustBePresent="false"/></Match></AllOf></AnyOf></Target></Rule></Policy>"#;

fn key_file(tag: &str, pem: &str) -> String {
    let path = std::env::temp_dir().join(format!("oidc-pep-{tag}-{}.pem", std::process::id()));
    std::fs::write(&path, pem).unwrap();
    path.to_string_lossy().into_owned()
}

fn ec_pem(seed: u8) -> String {
    use p256::pkcs8::EncodePrivateKey;
    p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap().to_pkcs8_pem(Default::default()).unwrap().to_string()
}

fn pep_section(pdp: &Pdp, tag: &str, extra: Value) -> Value {
    let mut section = json!({"name": "pep-demo", "assertionKey": key_file(tag, &ec_pem(5)), "pdpUrl": pdp.url, "heartbeatIntervalMs": 60000});
    for (k, v) in extra.as_object().unwrap() {
        section[k] = v.clone();
    }
    section
}

fn login() -> crate::Login {
    let mut claims = JsonMap::new();
    claims.insert("sub".into(), json!("0b6e-uuid"));
    claims.insert("acr".into(), json!("urn:example:mfa"));
    claims.insert("auth_time".into(), json!(1_700_000_000));
    crate::Login { subject: "0b6e-uuid".into(), preferred_username: "alice".into(), claims, ..Default::default() }
}

#[test]
fn a_pep_section_builds_a_started_pep_with_the_librarys_defaults() {
    let op = start_provider();
    let pdp = start_pdp();
    let mut section = pep_section(pdp, "defaults", json!({}));
    section.as_object_mut().unwrap().remove("pdpUrl");
    let rp = RelyingParty::create(provider_config(op, json!({"pep": section}))).unwrap();
    let pep = rp.pep().expect("a PEP");
    assert_eq!(pep.config().pdp_url, crate::value::map_str(rp.metadata(), "issuer"), "pdpUrl defaults to the issuer");
    assert_eq!(pep.config().application, "oidc-caep-risc-demo", "application defaults to clientId");
    assert!(pep.config().signals, "signals follow the library's, on by default");
    assert!(pep.status().running);

    let rp = RelyingParty::create(provider_config(op, json!({"pep": pep_section(pdp, "started", json!({}))}))).unwrap();
    assert_eq!(rp.pep().unwrap().config().application, "oidc-caep-risc-demo");
    let register = pdp.bodies("/xacml/pep/register");
    assert!(!register.is_empty(), "registered at create");
    assert_eq!(register[0]["kind"], "embedded");
    assert_eq!(register[0]["application"], "oidc-caep-risc-demo");
    assert!(rp.pep().unwrap().status().registered);

    let off = RelyingParty::create(provider_config(op, json!({"signals": false, "pep": pep_section(pdp, "nosignals", json!({}))}))).unwrap();
    assert!(!off.pep().unwrap().config().signals);
    assert!(RelyingParty::create(provider_config(op, json!({}))).unwrap().pep().is_none(), "no section, no PEP");
}

#[test]
fn a_bad_section_is_refused_at_create() {
    let op = start_provider();
    let pdp = start_pdp();
    for (section, says) in [
        (json!("on"), "pep must be an object"),
        (pep_section(pdp, "bad-mode", json!({"mode": "remote"})), "pep.mode"),
        (pep_section(pdp, "bad-member", json!({"polIntervalMs": 1})), "polIntervalMs"),
        (json!({"name": "pep-demo", "assertionKey": "/nowhere.pem", "pdpUrl": pdp.url}), "could not be read"),
    ] {
        let err = RelyingParty::create(provider_config(op, json!({"pep": section}))).err().expect("refused");
        assert_eq!(err.code, "config");
        assert!(err.message.contains(says), "{} / {says}", err.message);
    }
}

#[test]
fn the_pep_key_must_differ_from_the_private_key_jwt_key_and_the_dpop_key() {
    let op = start_provider();
    let pdp = start_pdp();
    let same_as_client = json!({"name": "pep-demo", "assertionKey": key_file("jwt", &keys().client_pem), "pdpUrl": pdp.url});
    let err = RelyingParty::create(provider_config(
        op,
        json!({"tokenEndpointAuthMethod": "private_key_jwt", "clientSecret": null, "privateKeyPem": keys().client_pem, "pep": same_as_client}),
    ))
    .err()
    .expect("refused");
    assert!(err.message.contains("private_key_jwt key"), "{}", err.message);

    // DPoP is on when the provider advertises ES256; the named key is the PEP's.
    let mut metadata: JsonMap = RelyingParty::create(provider_config(op, json!({}))).unwrap().metadata().clone();
    metadata.insert("dpop_signing_alg_values_supported".into(), json!(["ES256"]));
    let dpop_pem = ec_pem(5);
    let section = json!({"name": "pep-demo", "assertionKey": key_file("dpop", &dpop_pem), "pdpUrl": pdp.url});
    let err = RelyingParty::create(provider_config(op, json!({"metadataUrl": null, "metadata": metadata, "dpop": "always", "dpopKey": dpop_pem, "pep": section})))
        .err()
        .expect("refused");
    assert!(err.message.contains("DPoP key"), "{}", err.message);

    // Three different keys are fine.
    let section = json!({"name": "pep-demo", "assertionKey": key_file("own", &ec_pem(6)), "pdpUrl": pdp.url});
    let rp = RelyingParty::create(provider_config(
        op,
        json!({"metadataUrl": null, "metadata": metadata, "dpop": "always", "dpopKey": ec_pem(7), "tokenEndpointAuthMethod": "private_key_jwt", "clientSecret": null, "privateKeyPem": keys().client_pem, "pep": section}),
    ))
    .unwrap();
    assert_ne!(rp.pep().unwrap().key_thumbprint(), rp.dpop_jkt().unwrap());
}

#[test]
fn a_login_becomes_the_peps_subject() {
    let s = subject_of(&login());
    assert_eq!((s.kind.as_str(), s.id.as_str()), ("user", "alice"), "the username the service's PIP resolves");
    assert_eq!(s.properties["acr"], "urn:example:mfa");
    assert_eq!(s.properties["auth_time"], 1_700_000_000);
    let mut nameless = login();
    nameless.preferred_username.clear();
    assert_eq!(subject_of(&nameless).id, "0b6e-uuid", "sub when there is no username");
    let mut info = JsonMap::new();
    info.insert("email".into(), json!("alice@example.com"));
    info.insert("acr".into(), json!("from-userinfo"));
    let s = subject_with_userinfo(&login(), &info);
    assert_eq!(s.properties["email"], "alice@example.com");
    assert_eq!(s.properties["acr"], "from-userinfo", "userinfo is laid over the ID token's claims");
}

#[test]
fn decide_asks_the_service_with_the_declared_claims_only() {
    let op = start_provider();
    let pdp = start_pdp();
    let rp = RelyingParty::create(provider_config(op, json!({"pep": pep_section(pdp, "decide", json!({}))}))).unwrap();
    pdp.decisions.lock().unwrap().extend([true, false]);
    assert!(rp.decide(&login(), &Access::new("read", "order", "42")).is_permit());
    assert!(matches!(rp.decide(&login(), &Access::new("delete", "order", "42")), Decision::Deny { .. }));
    let body = &pdp.bodies("/access/v1/evaluation")[0];
    assert_eq!(body["subject"]["id"], "alice");
    assert_eq!(body["subject"]["properties"], json!({"acr": "urn:example:mfa"}), "auth_time and sub are not in the catalogue");
    assert_eq!(body["context"]["application"], "oidc-caep-risc-demo");

    // A session that does not exist (or was ended by session-revoked) has no
    // subject, and nothing is asked.
    let before = pdp.count("/access/v1/evaluation");
    assert!(matches!(rp.decide_session("no-such-session", &Access::new("read", "order", "42")), Decision::Deny { .. }));
    assert_eq!(pdp.count("/access/v1/evaluation"), before);
    let store = Arc::new(crate::MemorySessionStore::new(10, 3600));
    crate::SessionStore::set(store.as_ref(), "s1", login());
    rp.set_session_store(store);
    assert!(rp.decide_session("s1", &Access::new("read", "order", "42")).is_permit());
    rp.remove_session("s1");
    assert!(!rp.decide_session("s1", &Access::new("read", "order", "42")).is_permit());

    let none = RelyingParty::create(provider_config(op, json!({}))).unwrap();
    assert!(matches!(none.decide(&login(), &Access::new("read", "order", "42")), Decision::Unavailable { .. }), "no section never permits");
}

#[test]
fn the_receiver_asks_for_the_policy_event_and_hands_it_to_the_pep() {
    let pdp = start_pdp();
    let tx = start_transmitter();
    let op = crate::profile_test::start_op(crate::profile_test::dpop_cfg());
    // central with a Permit cache: the event clears it.
    let rp = Arc::new(crate::profile_test::rp_for(op, json!({"pep": pep_section(pdp, "event", json!({"permitCacheMs": 30000}))})));
    let plain = Arc::new(crate::profile_test::rp_for(op, json!({})));
    let without = SignalsReceiver::new(&tx.url, Arc::new(|_, _| {}), ReceiverOptions { relying_party: Some(plain), poll_interval_ms: 60_000, ..ReceiverOptions::default() }).unwrap();
    assert!(!without.events_requested().iter().any(|e| e == POLICIES_CHANGED_EVENT), "no PEP, no event asked for");
    let receiver = SignalsReceiver::new(&tx.url, Arc::new(|_, _| {}), ReceiverOptions { relying_party: Some(Arc::clone(&rp)), poll_interval_ms: 60_000, ..ReceiverOptions::default() }).unwrap();
    assert!(receiver.events_requested().iter().any(|e| e == POLICIES_CHANGED_EVENT), "asked for on the application's own stream");

    let access = Access::new("read", "order", "42");
    assert!(rp.decide(&login(), &access).is_permit());
    assert!(rp.decide(&login(), &access).is_permit());
    assert_eq!(pdp.count("/access/v1/evaluation"), 1, "the second came from the Permit cache");

    receiver.start().unwrap();
    // A SET signed by another key is refused and never reaches the PEP.
    deliver(tx, POLICIES_CHANGED_EVENT, json!({"format": "opaque", "id": "oidc-caep-risc-demo"}), json!({"pep": "pep-demo", "changed": ["policies"]}), Some(&crate::suite::ssf_keys().other));
    receiver.poll_once().unwrap();
    assert!(rp.decide(&login(), &access).is_permit());
    assert_eq!(pdp.count("/access/v1/evaluation"), 1, "an unverified event changes nothing");

    // A verified one is handed to the PEP, which clears its cache.
    deliver(tx, POLICIES_CHANGED_EVENT, json!({"format": "opaque", "id": "oidc-caep-risc-demo"}), json!({"pep": "pep-demo", "changed": ["policies"], "sync_token": "p2"}), None);
    receiver.poll_once().unwrap();
    receiver.stop();
    assert!(rp.decide(&login(), &access).is_permit());
    assert_eq!(pdp.count("/access/v1/evaluation"), 2, "the event cleared the cache");
}

#[cfg(feature = "local")]
#[test]
fn local_mode_fails_closed_then_decides_in_process() {
    let op = start_provider();
    let pdp = start_pdp();
    pdp.policies_up.store(false, std::sync::atomic::Ordering::SeqCst);
    let rp = RelyingParty::create(provider_config(op, json!({"signals": false, "pep": pep_section(pdp, "local", json!({"mode": "local", "pollIntervalMs": 1000}))}))).unwrap();
    assert!(matches!(rp.decide(&login(), &Access::new("read", "order", "42")), Decision::Unavailable { .. }), "no policy held yet");

    pdp.policies_up.store(true, std::sync::atomic::Ordering::SeqCst);
    let pep = rp.pep().unwrap();
    let held = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(100));
        pep.status().holds_policy
    });
    assert!(held, "the poll (signals: false, pollIntervalMs) pulled once the service answered");
    assert!(rp.decide(&login(), &Access::new("read", "order", "42")).is_permit());
    assert!(matches!(rp.decide(&login(), &Access::new("write", "order", "42")), Decision::Deny { .. }));
    assert_eq!(pdp.count("/access/v1/evaluation"), 0, "decided in process");
    assert!(pdp.seen.lock().unwrap().iter().any(|(_, p, _)| p == "/xacml/pep/policies"));
}
