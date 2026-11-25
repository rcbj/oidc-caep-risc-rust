// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The demo's two PEP-protected pages (#46): `GET /attribute-protected` and
//! `/orders/<id>`, through the demo's own route handlers (`demo/main.rs`,
//! included here as a module and served by its own `serve` on a loopback
//! port), signed in the way a browser signs in (`/login`, the provider's
//! authorization endpoint, `/callback`), with no iya-sts:
//!
//! - the provider is `profile_test.rs`'s stub, which signs in whoever
//!   `Op::sign_in_as` names, with or without an `acr`;
//! - the PDP is `authzen_test.rs`'s stub, serving `src/tests/demo_pep_policy.json`:
//!   the catalogue row `subject.acr`, the XACML iya-sts stores for the
//!   install script's `orders_policy()`, and the PIP's `attr1` per user;
//! - the demo's PEP is `local`, so the policy is decided in this process.
//!
//! Each page's status is compared with `Decision::http_status()` of the same
//! decision asked of a second relying party made from the same file.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::authzen_test::{key_file, start_pdp, Pdp};
use crate::pep::{Access, Decision};
use crate::profile_test::{base, start_op, Op, OpCfg};
use crate::suite::manual;
use crate::value::JsonMap;
use crate::{Login, RelyingParty};

#[allow(dead_code, unused_imports, unused_variables, unused_mut, clippy::all)]
#[path = "../demo/main.rs"]
mod demo;

const TABLE: &str = include_str!("tests/demo_pep_policy.json");
/// attr1 = abc123: the attribute-protected page is permitted.
const ALLOWED: &str = "oidc-demo-user";
/// attr1 = not-abc123.
const DENIED: &str = "oidc-demo-denied";
/// No attr1 at all.
const NO_ATTR1: &str = "oidc-demo-no-attr1";
const ACR: &str = "urn:example:mfa";

struct Demo {
    url: String,
    op: &'static Op,
    pdp: &'static Pdp,
    config: String,
}

/// The demo, with a `local` `pep` section, on its own stub provider and PDP.
fn start_demo(tag: &str) -> Demo {
    start_demo_with(tag, json!({"signals": false}))
}

/// The same, with `extra` laid over the configuration (`ssf`, `signals`).
fn start_demo_with(tag: &str, extra: Value) -> Demo {
    let table: &'static Value = Box::leak(Box::new(serde_json::from_str(TABLE).expect("src/tests/demo_pep_policy.json is JSON")));
    let op = start_op(OpCfg::default());
    let pdp = start_pdp(table);
    // authzen_test's stub serves the policies of `pep-az-<app>-local`.
    let section = json!({
        "name": "pep-az-demo-local", "mode": "local", "assertionKey": key_file(&format!("demo-{tag}"), 41),
        "pdpUrl": pdp.url, "pollIntervalMs": 1000, "heartbeatIntervalMs": 10000,
    });
    let mut over = extra;
    over["pep"] = section;
    let config = base(op, over);
    let path = std::env::temp_dir().join(format!("oidc-demo-pep-{tag}-{}.json", std::process::id()));
    std::fs::write(&path, Value::Object(config).to_string()).unwrap();
    let config = path.to_string_lossy().into_owned();
    let app = demo::new_app(config.clone(), String::new(), false, vec![7u8; 32], false);
    let server: &'static tiny_http::Server = Box::leak(Box::new(tiny_http::Server::http("127.0.0.1:0").unwrap()));
    let port = server.server_addr().to_ip().unwrap().port();
    thread::spawn(move || demo::serve(app, server));
    Demo { url: format!("http://127.0.0.1:{port}"), op, pdp, config }
}

struct Page {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Page {
    fn header(&self, name: &str) -> String {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone()).unwrap_or_default()
    }

    fn cookie(&self, name: &str) -> String {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
            .filter_map(|(_, v)| v.split(';').next()?.trim().strip_prefix(&format!("{name}=")).map(str::to_string))
            .next()
            .unwrap_or_default()
    }

    fn heading(&self) -> String {
        let start = self.body.find("<h1>").map(|i| i + 4).unwrap_or(0);
        let end = self.body[start..].find("</h1>").map(|i| i + start).unwrap_or(start);
        self.body[start..end].to_string()
    }
}

/// One request to the demo, as a browser sends it: the cookie, no redirect followed.
fn call(demo: &Demo, method: &str, path: &str, cookie: &str) -> Page {
    let port = demo.url.rsplit(':').next().unwrap();
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let cookie = if cookie.is_empty() { String::new() } else { format!("Cookie: {cookie}\r\n") };
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: text/html\r\n{cookie}Content-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.split("\r\n");
    let status = lines.next().and_then(|l| l.split(' ').nth(1)).and_then(|s| s.parse().ok()).unwrap_or(0);
    let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
    Page { status, headers, body: body.to_string() }
}

/// Signs `user` in through the demo's `/login` and `/callback`, the
/// provider's ID token carrying `acr` when given; answers the session cookie.
fn sign_in(demo: &Demo, user: &str, acr: Option<&str>) -> String {
    demo.op.sign_in_as(user, acr);
    let login = call(demo, "GET", "/login", "");
    assert_eq!(login.status, 302, "{}", login.body);
    let txn = login.cookie("oidc_txn");
    assert!(!txn.is_empty(), "/login set the transaction cookie");
    let (status, back) = manual(&login.header("location"));
    assert_eq!(status, 302, "the provider sent the browser back");
    let query = back.split_once('?').map(|(_, q)| q).unwrap_or("");
    let done = call(demo, "GET", &format!("/callback?{query}"), &format!("oidc_txn={txn}"));
    assert_eq!(done.status, 303, "the sign-in completed: {}", done.body);
    let session = done.cookie("oidc_session");
    assert!(!session.is_empty(), "the session cookie is set");
    let cookie = format!("oidc_session={session}");
    let home = call(demo, "GET", "/", &cookie);
    assert!(home.heading().contains(user), "signed in as {user}: {}", home.heading());
    cookie
}

/// Waits until the demo's PEP holds the policy (`GET /pep-status`).
fn wait_for_policy(demo: &Demo, cookie: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last = Value::Null;
    while Instant::now() < deadline {
        let page = call(demo, "GET", "/pep-status", cookie);
        last = serde_json::from_str(&page.body).unwrap_or(Value::Null);
        if last["policy"]["held"] == json!(true) {
            return;
        }
        thread::sleep(Duration::from_millis(200));
    }
    panic!("the demo's PEP never held its policy: {last}");
}

/// A second relying party from the same configuration file, with its own
/// `local` PEP against the same stub, for the decision each page reports.
fn reference(demo: &Demo) -> RelyingParty {
    let rp = RelyingParty::from_file(&demo.config).unwrap();
    let pep = rp.pep().expect("a PEP");
    let deadline = Instant::now() + Duration::from_secs(60);
    while !pep.status().holds_policy && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(200));
    }
    assert!(pep.status().holds_policy, "the reference PEP holds the policy: {}", pep.status().last_error);
    rp
}

fn login_of(user: &str, acr: Option<&str>) -> Login {
    let mut claims = JsonMap::new();
    claims.insert("sub".into(), json!(user));
    if let Some(acr) = acr {
        claims.insert("acr".into(), json!(acr));
    }
    Login { subject: user.into(), claims, ..Default::default() }
}

/// The page's status is `http_status()` of the same decision, and its
/// heading says which decision it was.
fn assert_status_from_decision(page: &Page, decision: &Decision, what: &str) {
    assert_eq!(page.status, decision.http_status(), "{what}: the page's status is the decision's http_status() ({decision:?})");
    let heading = page.heading();
    match decision {
        Decision::Permit { .. } => assert!(heading == "Allowed" || heading.starts_with("Order "), "{what}: {heading}"),
        Decision::Deny { .. } => assert_eq!(heading, "Not allowed", "{what}"),
        Decision::Unavailable { .. } => assert_eq!(heading, "No decision", "{what}"),
    }
}

#[test]
fn the_allowed_user_gets_both_pages_and_writing_an_order_is_refused() {
    let demo = start_demo("allowed");
    let cookie = sign_in(&demo, ALLOWED, Some(ACR));
    wait_for_policy(&demo, &cookie);

    let page = call(&demo, "GET", "/attribute-protected", &cookie);
    assert_eq!(page.status, 200, "{}", page.body);
    assert_eq!(page.heading(), "Allowed");
    assert!(page.body.contains("The PEP permitted it"), "{}", page.body);
    assert!(page.body.contains("href=\"/attribute-protected\"") && page.body.contains("href=\"/orders/42\""), "the top bar links both pages");

    let order = call(&demo, "GET", "/orders/42", &cookie);
    assert_eq!(order.status, 200, "{}", order.body);
    assert_eq!(order.heading(), "Order 42");
    assert!(order.body.contains("The PEP permitted <code>read</code>"), "{}", order.body);

    let write = call(&demo, "POST", "/orders/42", &cookie);
    assert_eq!(write.status, 403, "{}", write.body);
    assert_eq!(write.heading(), "Not allowed");
    assert!(write.body.contains("The PEP denied <code>write</code> on order 42"), "{}", write.body);

    let rp = reference(&demo);
    let login = login_of(ALLOWED, Some(ACR));
    assert_status_from_decision(&page, &rp.decide(&login, &Access::new("read", "attribute-protected", "attr1")), "GET /attribute-protected");
    assert_status_from_decision(&order, &rp.decide(&login, &Access::new("read", "order", "42")), "GET /orders/42");
    assert_status_from_decision(&write, &rp.decide(&login, &Access::new("write", "order", "42")), "POST /orders/42");
    assert!(*demo.pdp.pip_queries.lock().unwrap() > 0, "attr1 came from the PIP");
}

#[test]
fn a_user_whose_attr1_is_not_abc123_or_absent_is_refused_the_attribute_page() {
    let demo = start_demo("denied");
    let rp_wait = sign_in(&demo, DENIED, Some(ACR));
    wait_for_policy(&demo, &rp_wait);
    let rp = reference(&demo);
    for user in [DENIED, NO_ATTR1] {
        let cookie = sign_in(&demo, user, Some(ACR));
        let page = call(&demo, "GET", "/attribute-protected", &cookie);
        assert_eq!(page.status, 403, "{user}: {}", page.body);
        assert_eq!(page.heading(), "Not allowed", "{user}");
        assert!(page.body.contains("The PEP denied it"), "{user}: {}", page.body);
        let login = login_of(user, Some(ACR));
        let decision = rp.decide(&login, &Access::new("read", "attribute-protected", "attr1"));
        assert!(matches!(decision, Decision::Deny { .. }), "{user}: {decision:?}");
        assert_status_from_decision(&page, &decision, user);

        // The acr is all an order needs: this person may read it, not write it.
        let order = call(&demo, "GET", "/orders/42", &cookie);
        assert_eq!(order.status, 200, "{user}: {}", order.body);
        assert_status_from_decision(&order, &rp.decide(&login, &Access::new("read", "order", "42")), user);
        let write = call(&demo, "POST", "/orders/42", &cookie);
        assert_eq!(write.status, 403, "{user}: {}", write.body);
        assert_eq!(write.heading(), "Not allowed");
    }
}

#[test]
fn a_sign_in_without_an_acr_cannot_read_an_order() {
    let demo = start_demo("no-acr");
    let cookie = sign_in(&demo, ALLOWED, None);
    wait_for_policy(&demo, &cookie);
    let order = call(&demo, "GET", "/orders/42", &cookie);
    assert_eq!(order.status, 403, "{}", order.body);
    assert_eq!(order.heading(), "Not allowed");
    assert!(order.body.contains("The PEP denied <code>read</code> on order 42"), "{}", order.body);
    let rp = reference(&demo);
    let login = login_of(ALLOWED, None);
    assert_status_from_decision(&order, &rp.decide(&login, &Access::new("read", "order", "42")), "GET /orders/42 without acr");

    // attr1 is a directory attribute, not a claim: the page needs no acr.
    let page = call(&demo, "GET", "/attribute-protected", &cookie);
    assert_eq!(page.status, 200, "{}", page.body);
    assert_status_from_decision(&page, &rp.decide(&login, &Access::new("read", "attribute-protected", "attr1")), "GET /attribute-protected without acr");
}

#[test]
fn signed_out_is_401_on_both_pages() {
    let demo = start_demo("signed-out");
    for (method, path) in [("GET", "/attribute-protected"), ("GET", "/orders/42"), ("POST", "/orders/42")] {
        let page = call(&demo, method, path, "");
        assert_eq!(page.status, 401, "{method} {path}: {}", page.body);
        assert_eq!(page.heading(), "Sign in first", "{method} {path}");
        let stale = call(&demo, method, path, "oidc_session=not-a-session");
        assert_eq!(stale.status, 401, "{method} {path} with an unknown session");
    }
    // Signed in, then signed out from the menu's form.
    let cookie = sign_in(&demo, ALLOWED, Some(ACR));
    wait_for_policy(&demo, &cookie);
    assert_eq!(call(&demo, "GET", "/attribute-protected", &cookie).status, 200);
    let out = call(&demo, "POST", "/logout", &cookie);
    assert_eq!(out.status, 303);
    for (method, path) in [("GET", "/attribute-protected"), ("GET", "/orders/42")] {
        assert_eq!(call(&demo, method, path, &cookie).status, 401, "{method} {path} after sign-out");
    }
}

/// Every sign-in is followed at the transmitter, not only the one that
/// started the receiver (gnap-caep-risc-rust #44 found its demo tracked
/// only that one): `/callback` tracks each, so Add Subject goes for each
/// person, and Sign out withdraws a person once their last sign-in here ends.
#[test]
fn the_demo_follows_every_sign_in_at_the_transmitter() {
    let tx = crate::suite::start_transmitter();
    *tx.subject_endpoints.lock().unwrap() = true;
    let demo = start_demo_with("subjects", json!({"ssf": {"transmitter": tx.url, "pollIntervalMs": 60000}}));
    let calls = || tx.subject_calls.lock().unwrap().clone();
    let subject = |person: &str| json!({"format": "iss_sub", "iss": tx.url, "sub": person});
    let added = || calls().into_iter().filter(|(kind, _)| kind == "add").map(|(_, body)| body["subject"].clone()).collect::<Vec<_>>();
    let removed = || calls().into_iter().filter(|(kind, _)| kind == "remove").map(|(_, body)| body["subject"].clone()).collect::<Vec<_>>();

    let first = sign_in(&demo, ALLOWED, Some(ACR));
    let status: Value = serde_json::from_str(&call(&demo, "GET", "/live-status", &first).body).unwrap();
    assert!(status["receiver"].as_str().unwrap_or("").starts_with("polling stream"), "the receiver runs: {status}");
    assert_eq!(added(), vec![subject(ALLOWED)], "the first sign-in");
    let second = sign_in(&demo, DENIED, Some(ACR));
    let third = sign_in(&demo, ALLOWED, Some(ACR));
    assert_eq!(added(), vec![subject(ALLOWED), subject(DENIED)], "a later person is added too; a person already added is not added again");
    assert_eq!(calls()[0].1["verified"], json!(true));

    assert_eq!(call(&demo, "POST", "/logout", &first).status, 303);
    assert!(removed().is_empty(), "the allowed user is still signed in here (the third sign-in)");
    assert_eq!(call(&demo, "POST", "/logout", &second).status, 303);
    assert_eq!(removed(), vec![subject(DENIED)]);
    assert_eq!(call(&demo, "POST", "/logout", &third).status, 303);
    assert_eq!(removed(), vec![subject(DENIED), subject(ALLOWED)], "the allowed user's last sign-in ended");
}
