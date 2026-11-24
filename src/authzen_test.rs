// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! AuthZEN through the embedded PEP (#46): one case table,
//! `src/tests/authzen_cases.json`, and two runners over it, both through
//! this library's own API (`RelyingParty::decide`, `decide_session`, a
//! `Login`, the `pep` section).
//!
//! - **Offline** (`the_table_decides_as_expected_in_local_mode`, in the normal
//!   `cargo test`): a `local` PEP per application against a stub PDP that
//!   serves the table's catalogue and its policies' XACML, and answers the
//!   PIP from the table's directory users. Every case must get `expect`,
//!   except one marked `knownLocalDefect`, which must still be wrong.
//! - **Live** (`live_central_equals_local`, ignored; run by
//!   `scripts/live_iya_sts.py --authzen`, which provisions a fresh iya-sts and
//!   names its plan in `AUTHZEN_LIVE_PLAN`): a `central` and a `local` PEP per
//!   application. Every case must get the same answer from both, and that
//!   answer must be `expect`. All mismatches are collected and reported once.
//!
//! An answer is what the host sees: `Permit` with the obligations handed to
//! it, `Deny`, or `Unavailable`. The reasons are reported, not compared.

use std::collections::BTreeMap;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::pep::{Access, Decision};
use crate::suite::{json_res, provider_config, read_req, start_provider, write_res, Req};
use crate::value::JsonMap;
use crate::{Login, MemorySessionStore, RelyingParty, SessionStore};

const TABLE: &str = include_str!("tests/authzen_cases.json");

fn table() -> Value {
    serde_json::from_str(TABLE).expect("src/tests/authzen_cases.json is JSON")
}

fn object(value: &Value) -> JsonMap {
    value.as_object().cloned().unwrap_or_default()
}

/// The sign-in a case describes: the username the PIP resolves, and the ID
/// token's claims (`sub` among them, which no catalogue row declares).
fn login_of(case: &Value) -> Login {
    let username = case["login"]["username"].as_str().unwrap_or("").to_string();
    let mut claims = object(&case["login"]["claims"]);
    let subject = format!("sub-{username}");
    claims.insert("sub".into(), json!(subject));
    claims.insert("preferred_username".into(), json!(username));
    Login { subject, preferred_username: username, claims, ..Default::default() }
}

fn access_of(case: &Value) -> Access {
    let a = &case["access"];
    let mut access = Access::new(a["action"].as_str().unwrap_or(""), a["type"].as_str().unwrap_or(""), a["id"].as_str().unwrap_or(""));
    access.action_properties = object(&a["actionProperties"]);
    access.resource_properties = object(&a["resource"]);
    access.context = object(&a["context"]);
    access
}

/// One case through one relying party: `decide`, or `decide_session` for a
/// live or an ended session.
fn decide(rp: &RelyingParty, store: &Arc<MemorySessionStore>, case: &Value, index: usize) -> Decision {
    let login = login_of(case);
    let access = access_of(case);
    match case["session"].as_str() {
        None => rp.decide(&login, &access),
        Some(state) => {
            let id = format!("authzen-case-{index}");
            store.set(&id, login);
            if state == "ended" {
                rp.remove_session(&id);
            }
            rp.decide_session(&id, &access)
        }
    }
}

fn normal_obligations(list: Vec<Value>) -> Vec<Value> {
    let mut list = list;
    list.sort_by_key(|o| o.to_string());
    list
}

/// What the host sees, in the table's terms.
fn answer_of(decision: &Decision) -> Value {
    match decision {
        Decision::Permit { obligations, .. } => {
            let handed = normal_obligations(obligations.iter().map(|o| json!({"type": o.kind, "properties": o.properties})).collect());
            if handed.is_empty() { json!({"decision": "Permit"}) } else { json!({"decision": "Permit", "obligations": handed}) }
        }
        Decision::Deny { .. } => json!({"decision": "Deny"}),
        Decision::Unavailable { .. } => json!({"decision": "Unavailable"}),
    }
}

fn why_of(decision: &Decision) -> String {
    match decision {
        Decision::Permit { .. } => String::new(),
        Decision::Deny { why } | Decision::Unavailable { why } => why.clone(),
    }
}

fn expected_of(case: &Value) -> Value {
    let e = &case["expect"];
    let handed = normal_obligations(e["obligations"].as_array().cloned().unwrap_or_default());
    if handed.is_empty() { json!({"decision": e["decision"]}) } else { json!({"decision": e["decision"], "obligations": handed}) }
}

fn pep_section(name: &str, mode: &str, key: &str, application: &str, supported: &Value, pdp_url: Option<&str>) -> Value {
    let mut section = json!({
        "name": name, "mode": mode, "assertionKey": key, "application": application,
        "supportedObligations": supported, "pollIntervalMs": 1000, "heartbeatIntervalMs": 10000,
    });
    if let Some(url) = pdp_url {
        section["pdpUrl"] = json!(url);
    }
    section
}

/// Waits until a PEP can decide: registered, and in `local` holding a set.
fn wait_ready(rp: &RelyingParty, local: bool) -> bool {
    let pep = rp.pep().expect("a PEP");
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        let s = pep.status();
        if s.registered && (!local || s.holds_policy) {
            return true;
        }
        thread::sleep(Duration::from_millis(200));
    }
    false
}

// ---------------------------------------------------------------------------
// The offline stub PDP: what a `local` PEP pulls, from the table.
// ---------------------------------------------------------------------------

fn attribute_in(tag: &str, name: &str) -> Option<String> {
    let start = tag.find(&format!("{name}=\""))? + name.len() + 2;
    let end = tag[start..].find('"')? + start;
    Some(tag[start..end].replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&amp;", "&"))
}

/// Answers a `<PIPRequest>` from the table's directory users, as iya-sts's
/// PIP would: a bare designator name is the user's directory attribute.
fn pip_answer(table: &Value, query: &str) -> String {
    let subject = query
        .find("subject:subject-id")
        .and_then(|at| query[at..].find("<AttributeValue").map(|v| at + v))
        .and_then(|at| query[at..].find('>').map(|g| at + g + 1))
        .and_then(|at| query[at..].find("</AttributeValue>").map(|end| query[at..at + end].to_string()))
        .unwrap_or_default();
    let user = table["users"].as_array().unwrap().iter().find(|u| u["username"] == subject.as_str());
    let mut by_category: BTreeMap<String, String> = BTreeMap::new();
    for piece in query.split("<AttributeDesignator").skip(1) {
        let tag = &piece[..piece.find("/>").unwrap_or(piece.len())];
        let (Some(category), Some(id), Some(data_type)) = (attribute_in(tag, "Category"), attribute_in(tag, "AttributeId"), attribute_in(tag, "DataType")) else { continue };
        if let Some(value) = user.and_then(|u| u["attributes"][&id].as_str()) {
            by_category.entry(category).or_default().push_str(&format!(
                "<Attribute AttributeId=\"{id}\" IncludeInResult=\"false\"><AttributeValue DataType=\"{data_type}\">{value}</AttributeValue></Attribute>"
            ));
        }
    }
    let xacml = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17";
    let mut out = String::from("<PIPResponse xmlns=\"urn:sts:xacml:pip:1.0\">");
    for (category, attributes) in by_category {
        out.push_str(&format!("<Attributes xmlns=\"{xacml}\" Category=\"{category}\">{attributes}</Attributes>"));
    }
    out.push_str("</PIPResponse>");
    out
}

/// A policy's stored XACML, kept in the table as lines.
fn xacml_of(policy: &Value) -> String {
    policy["xacml"].as_array().map(|lines| lines.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n")).unwrap_or_default()
}

/// The table's policies for one application, as `GET /xacml/pep/policies`
/// sends them: the root and its reference closure.
fn policy_rows(table: &Value, app: &str) -> Vec<Value> {
    table["policies"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["app"] == app)
        .map(|p| {
            let document = xacml_of(p);
            let document = document.as_str();
            // The root element, past the XML declaration.
            let root = &document[document.find("<Policy").unwrap_or(0)..];
            let set = root.starts_with("<PolicySet");
            let id_attr = if set { "PolicySetId" } else { "PolicyId" };
            let head = &root[..root.find('>').unwrap_or(root.len())];
            json!({
                "name": p["name"], "policyId": attribute_in(head, id_attr).unwrap_or_default(),
                "kind": if set { "PolicySet" } else { "Policy" }, "version": attribute_in(head, "Version").unwrap_or_else(|| "1.0".into()),
                "isRoot": p["root"].as_bool().unwrap_or(false), "description": "", "document": document,
            })
        })
        .collect()
}

struct Pdp {
    url: String,
    pip_queries: Mutex<usize>,
}

fn start_pdp(table: &'static Value) -> &'static Pdp {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let pdp: &'static Pdp = Box::leak(Box::new(Pdp { url: format!("http://127.0.0.1:{port}"), pip_queries: Mutex::new(0) }));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            if let Some(req) = read_req(&mut stream) {
                let (status, headers, body) = answer(pdp, table, &req);
                let _ = write_res(&mut stream, status, &headers, &body);
            }
        }
    });
    pdp
}

fn answer(pdp: &Pdp, table: &Value, req: &Req) -> (u16, Vec<(String, String)>, Vec<u8>) {
    match req.path.as_str() {
        "/oauth2/token" => json_res(200, json!({"access_token": "pep-token", "token_type": "DPoP", "expires_in": 300})),
        "/xacml/pep/register" => json_res(201, json!({"registered": true})),
        "/xacml/pep/heartbeat" => json_res(200, json!({"acknowledged": true, "current": true})),
        "/admin-api/pep-audit" => json_res(200, json!({"acknowledged": 0})),
        "/xacml/pep/authzen-catalogue" => json_res(200, json!({"syncToken": "c1", "rows": table["catalogue"], "settings": {"obligationsProfile": true}})),
        "/xacml/pep/policies" => {
            // pep-az-<app>-local
            let name = req.query.get("pep").cloned().unwrap_or_default();
            let app = name.trim_start_matches("pep-az-").trim_end_matches("-local").to_string();
            json_res(200, json!({"syncToken": format!("p-{app}"), "policies": policy_rows(table, &app), "withheld": [], "note": ""}))
        }
        "/xacml/pip" => {
            *pdp.pip_queries.lock().unwrap() += 1;
            (200, vec![("content-type".into(), "application/xml".into())], pip_answer(table, &req.body).into_bytes())
        }
        _ => json_res(404, json!({"error": "not_found"})),
    }
}

fn key_file(tag: &str, seed: u8) -> String {
    use p256::pkcs8::EncodePrivateKey;
    let pem = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap().to_pkcs8_pem(Default::default()).unwrap().to_string();
    let path = std::env::temp_dir().join(format!("oidc-authzen-{tag}-{}.pem", std::process::id()));
    std::fs::write(&path, pem).unwrap();
    path.to_string_lossy().into_owned()
}

#[test]
fn the_table_is_well_formed() {
    let t = table();
    let apps = t["applications"].as_object().unwrap();
    let cases = t["cases"].as_array().unwrap();
    assert!(cases.len() >= 40, "{} cases", cases.len());
    let mut names = std::collections::HashSet::new();
    for case in cases {
        assert!(names.insert(case["name"].as_str().unwrap()), "a case name is used twice: {}", case["name"]);
        assert!(apps.contains_key(case["app"].as_str().unwrap()), "{}", case["name"]);
        assert!(["Permit", "Deny", "Unavailable"].contains(&case["expect"]["decision"].as_str().unwrap()), "{}", case["name"]);
    }
    for app in apps.keys() {
        let roots = t["policies"].as_array().unwrap().iter().filter(|p| p["app"] == app.as_str() && p["root"] == true).count();
        assert_eq!(roots, 1, "{app} has one root");
    }
    // Every row reads at iya-pep's grammar, so none is silently left out.
    let pulled = iya_pep::authzen::Catalogue::from_pull(&json!({"rows": t["catalogue"]})).unwrap();
    assert_eq!(pulled.rows.len(), t["catalogue"].as_array().unwrap().len());
}

/// Every case through a `local` PEP of its application, against the stub.
#[test]
fn the_table_decides_as_expected_in_local_mode() {
    let t: &'static Value = Box::leak(Box::new(table()));
    let missing: Vec<&Value> = t["policies"].as_array().unwrap().iter().filter(|p| xacml_of(p).is_empty()).map(|p| &p["name"]).collect();
    assert!(missing.is_empty(), "policies without xacml {missing:?}: run scripts/live_iya_sts.py --authzen with AUTHZEN_XACML_OUT");
    let op = start_provider();
    let pdp = start_pdp(t);
    let mut rps: BTreeMap<String, (RelyingParty, Arc<MemorySessionStore>)> = BTreeMap::new();
    for (seed, (key, app)) in t["applications"].as_object().unwrap().iter().enumerate() {
        let name = format!("pep-az-{key}-local");
        let section = pep_section(&name, "local", &key_file(key, 20 + seed as u8), app["identifier"].as_str().unwrap(), &t["supportedObligations"], Some(&pdp.url));
        let rp = RelyingParty::create(provider_config(op, json!({"signals": false, "pep": section}))).unwrap();
        assert!(wait_ready(&rp, true), "{name} never held its policy: {}", rp.pep().unwrap().status().last_error);
        let store = Arc::new(MemorySessionStore::new(100, 3600));
        rp.set_session_store(store.clone());
        rps.insert(key.clone(), (rp, store));
    }
    let mut wrong = Vec::new();
    for (i, case) in t["cases"].as_array().unwrap().iter().enumerate() {
        let (rp, store) = &rps[case["app"].as_str().unwrap()];
        let decision = decide(rp, store, case, i);
        let right = answer_of(&decision) == expected_of(case);
        if case["knownLocalDefect"].is_string() {
            // Still wrong, as recorded. Once the local PEP gets it right the
            // mark must go, so the live run's verdict is the only one left.
            if right {
                wrong.push(format!("{}: local now answers as expected; remove knownLocalDefect", case["name"]));
            } else {
                eprintln!("known local defect, still present: {}: got {}, expected {}", case["name"], answer_of(&decision), expected_of(case));
            }
        } else if !right {
            wrong.push(format!("{}: got {} ({}), expected {}", case["name"], answer_of(&decision), why_of(&decision), expected_of(case)));
        }
    }
    assert!(*pdp.pip_queries.lock().unwrap() > 0, "the PIP was asked");
    assert!(wrong.is_empty(), "{} of {} cases:\n{}", wrong.len(), t["cases"].as_array().unwrap().len(), wrong.join("\n"));
}

/// The differential against a real iya-sts. `scripts/live_iya_sts.py
/// --authzen` provisions it and writes the plan this reads.
#[test]
#[ignore = "needs a provisioned iya-sts: scripts/live_iya_sts.py --authzen"]
fn live_central_equals_local() {
    let path = std::env::var("AUTHZEN_LIVE_PLAN").expect("AUTHZEN_LIVE_PLAN names the plan scripts/live_iya_sts.py --authzen wrote");
    let plan: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let t = table();
    let ca = std::fs::read_to_string(plan["tlsCa"].as_str().unwrap()).unwrap();
    let mut rps: BTreeMap<(String, String), (RelyingParty, Arc<MemorySessionStore>)> = BTreeMap::new();
    let mut not_ready = Vec::new();
    for (key, app) in plan["apps"].as_object().unwrap() {
        let identifier = app["application"].as_str().unwrap();
        for mode in ["central", "local"] {
            let pep = &app[mode];
            let config = json!({
                "metadataUrl": plan["metadataUrl"], "clientId": identifier, "clientSecret": "unused-by-this-test",
                "tokenEndpointAuthMethod": "client_secret_basic", "redirectUri": "http://127.0.0.1/callback",
                "tlsCa": ca, "signals": false,
                "pep": pep_section(pep["name"].as_str().unwrap(), mode, pep["key"].as_str().unwrap(), identifier, &plan["supportedObligations"], None),
            });
            let rp = RelyingParty::create(config.as_object().unwrap().clone()).unwrap_or_else(|e| panic!("{key} {mode}: {}", e.message));
            if !wait_ready(&rp, mode == "local") {
                not_ready.push(format!("{key} {mode}: {}", rp.pep().unwrap().status().last_error));
            }
            let store = Arc::new(MemorySessionStore::new(100, 3600));
            rp.set_session_store(store.clone());
            rps.insert((key.clone(), mode.to_string()), (rp, store));
        }
    }
    assert!(not_ready.is_empty(), "PEPs not ready: {not_ready:?}");

    let cases = t["cases"].as_array().unwrap();
    let (mut equal, mut as_expected) = (0, 0);
    let mut mismatches = Vec::new();
    for (i, case) in cases.iter().enumerate() {
        let app = case["app"].as_str().unwrap().to_string();
        let (c_rp, c_store) = &rps[&(app.clone(), "central".to_string())];
        let (l_rp, l_store) = &rps[&(app.clone(), "local".to_string())];
        let central = decide(c_rp, c_store, case, i);
        let local = decide(l_rp, l_store, case, i);
        let (c, l, e) = (answer_of(&central), answer_of(&local), expected_of(case));
        if c == l {
            equal += 1;
        }
        if c == e && l == e {
            as_expected += 1;
        }
        if c != l || c != e || l != e {
            mismatches.push(json!({
                "case": case["name"], "app": app, "central": c, "local": l, "expected": e,
                "centralWhy": why_of(&central), "localWhy": why_of(&local),
            }));
        }
    }
    let statuses: Vec<Value> = rps
        .iter()
        .map(|((app, mode), (rp, _))| {
            let s = rp.pep().unwrap().status();
            json!({"app": app, "mode": mode, "decisions": s.decisions, "allowed": s.allowed, "refused": s.refused, "unavailable": s.unavailable, "policyCount": s.policy_count, "lastError": s.last_error})
        })
        .collect();
    let result = json!({
        "cases": cases.len(), "centralEqualsLocal": equal, "asExpected": as_expected,
        "mismatches": mismatches, "peps": statuses,
    });
    println!("AUTHZEN-RESULT {result}");
    let listing: Vec<String> = mismatches
        .iter()
        .map(|m| format!("{} [{}]: central {} / local {} / expected {} (central: {}; local: {})", m["case"], m["app"], m["central"], m["local"], m["expected"], m["centralWhy"], m["localWhy"]))
        .collect();
    assert!(listing.is_empty(), "{} of {} cases differ:\n{}", listing.len(), cases.len(), listing.join("\n"));
}
