// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! Add Subject and Remove Subject (SSF 1.0 sections 8.1.3.2 and 8.1.3.3;
//! iya-sts#2234: a stream carries events only about people with an active
//! session on its application). `SignalsReceiver::track` tells the
//! transmitter of a person's sign-in, and the end of their last one here
//! (`untrack`, or an event that ends it) withdraws them, only for a subject
//! the transmitter accepted. A refusal or failure is reported and counted,
//! never retried, and never fails the sign-in.

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use crate::suite::{deliver, start_transmitter, Transmitter};
use crate::value::JsonMap;
use crate::{resolve_config, Event, ReceiverOptions, RelyingParty, SignalsReceiver};

type Lines = Arc<Mutex<Vec<String>>>;

fn options(lines: &Lines) -> ReceiverOptions {
    let seen = Arc::clone(lines);
    ReceiverOptions {
        headers: Some(Arc::new(|| vec![("authorization".into(), "Bearer app-token".into())])),
        poll_interval_ms: 60_000,
        on_error: Some(Arc::new(move |line: &str| seen.lock().unwrap().push(line.to_string()))),
        ..ReceiverOptions::default()
    }
}

/// A running receiver on `tx` (the tests poll by hand).
fn running(tx: &Transmitter, lines: &Lines, opts: ReceiverOptions) -> SignalsReceiver {
    let _ = lines;
    let receiver = SignalsReceiver::new(&tx.url, Arc::new(|_, _| {}), opts).unwrap();
    receiver.start().unwrap();
    receiver
}

fn session(local_id: &str, person: &str, email: &str, idp: &str) -> JsonMap {
    let mut out = JsonMap::new();
    out.insert("local_id".into(), json!(local_id));
    if !person.is_empty() {
        out.insert("person".into(), json!(person));
    }
    if !email.is_empty() {
        out.insert("email".into(), json!(email));
    }
    if !idp.is_empty() {
        out.insert("idp_session".into(), json!(idp));
    }
    out
}

fn iss_sub(tx: &Transmitter, person: &str) -> Value {
    json!({"format": "iss_sub", "iss": tx.url, "sub": person})
}

fn calls(tx: &Transmitter) -> Vec<(String, Value)> {
    tx.subject_calls.lock().unwrap().clone()
}

fn removed(tx: &Transmitter) -> Vec<Value> {
    calls(tx).into_iter().filter(|(kind, _)| kind == "remove").map(|(_, body)| body["subject"].clone()).collect()
}

#[test]
fn a_sign_in_adds_its_subject_and_the_last_sign_out_removes_it() {
    let tx = start_transmitter();
    *tx.subject_endpoints.lock().unwrap() = true;
    let lines: Lines = Arc::default();
    let receiver = running(tx, &lines, options(&lines));
    let stream = receiver.stream().unwrap()["stream_id"].clone();

    receiver.track(session("L-a1", "alice", "Alice@Example.com", "IDP-A1"));
    assert_eq!(calls(tx), vec![("add".to_string(), json!({"stream_id": stream, "subject": iss_sub(tx, "alice"), "verified": true}))],
        "iss_sub with the transmitter as issuer, as events are matched; verified: the person came from a verified ID token");
    receiver.track(session("L-a2", "alice", "", "IDP-A2"));
    assert_eq!(calls(tx).len(), 1, "a person the transmitter accepted is not added again");

    receiver.untrack("L-a1");
    assert!(removed(tx).is_empty(), "alice still has L-a2 here");
    receiver.untrack("L-a2");
    assert_eq!(calls(tx).last().unwrap(), &("remove".to_string(), json!({"stream_id": stream, "subject": iss_sub(tx, "alice")})), "Remove Subject carries no verified member");
    receiver.untrack("L-a2");
    assert_eq!(removed(tx).len(), 1, "untracking twice removes once");

    // No subject identifier: the email events about the person carry, lowercased.
    receiver.track(session("L-d1", "", "Dana@Example.com", ""));
    assert_eq!(calls(tx).last().unwrap().1["subject"], json!({"format": "email", "email": "dana@example.com"}));
    receiver.untrack("L-d1");
    assert_eq!(removed(tx).last().unwrap(), &json!({"format": "email", "email": "dana@example.com"}));

    // The same local session tracked again (a refreshed record) keeps its person.
    receiver.track(session("L-b1", "bob", "", ""));
    receiver.track(session("L-b1", "bob", "", ""));
    assert_eq!(calls(tx).iter().filter(|(_, b)| b["subject"] == iss_sub(tx, "bob")).count(), 1, "no remove-and-add for the same sign-in");

    let health = receiver.health();
    assert_eq!((health.subjects_added, health.subjects_removed, health.subject_refusals, health.subject_failures), (3, 2, 0, 0));
    assert!(lines.lock().unwrap().is_empty(), "{:?}", lines.lock().unwrap());
    receiver.stop();
}

#[test]
fn a_session_ended_by_an_event_removes_the_subject_when_it_was_the_last() {
    let tx = start_transmitter();
    *tx.subject_endpoints.lock().unwrap() = true;
    let lines: Lines = Arc::default();
    let ended = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = Arc::clone(&ended);
    let receiver = SignalsReceiver::new(&tx.url, Arc::new(move |ids, _| seen.lock().unwrap().extend(ids)), options(&lines)).unwrap();
    receiver.start().unwrap();
    receiver.track(session("L-a1", "alice", "", "IDP-A1"));
    receiver.track(session("L-a2", "alice", "", "IDP-A2"));
    receiver.track(session("L-b1", "bob", "", "IDP-B1"));
    let complex = |person: &str, idp: &str| json!({"format": "complex", "user": iss_sub(tx, person), "session": {"format": "opaque", "id": idp}});

    deliver(tx, &Event::get("sessionRevoked"), complex("alice", "IDP-A1"), json!({}), None);
    receiver.poll_once().unwrap();
    assert_eq!(*ended.lock().unwrap(), vec!["L-a1".to_string()]);
    assert!(removed(tx).is_empty(), "alice still has L-a2");

    deliver(tx, &Event::get("sessionRevoked"), complex("bob", "IDP-B1"), json!({}), None);
    receiver.poll_once().unwrap();
    assert_eq!(removed(tx), vec![iss_sub(tx, "bob")], "bob's only session ended: removed on the poll");

    deliver(tx, &Event::get("accountDisabled"), iss_sub(tx, "alice"), json!({}), None);
    receiver.poll_once().unwrap();
    assert_eq!(removed(tx), vec![iss_sub(tx, "bob"), iss_sub(tx, "alice")]);
    receiver.untrack("L-a2");
    assert_eq!(removed(tx).len(), 2, "already gone: nothing more to remove");
    assert_eq!(receiver.health().subjects_removed, 2);
    receiver.stop();
}

#[test]
fn a_refused_or_failed_subject_call_is_reported_and_never_fails_the_sign_in() {
    let tx = start_transmitter();
    *tx.subject_endpoints.lock().unwrap() = true;
    let lines: Lines = Arc::default();
    let receiver = running(tx, &lines, options(&lines));
    let ended = |r: &SignalsReceiver| r.health().sessions_ended;

    // iya-sts#2234: 403 when the person has no active session there (a race).
    *tx.subject_status.lock().unwrap() = 403;
    receiver.track(session("L-e1", "erin", "", "IDP-E1"));
    assert_eq!(calls(tx).len(), 1, "one call, no retry");
    let health = receiver.health();
    assert_eq!((health.subjects_added, health.subject_refusals, health.subject_failures), (0, 1, 0));
    assert!(health.last_subject_error.contains("Add Subject (iss_sub) for a signed-in person on stream s1 answered 403"), "{}", health.last_subject_error);
    assert!(!health.last_subject_error.contains("erin"), "the person's identifier stays out of the line");
    assert_eq!(lines.lock().unwrap().len(), 1, "on_error got it");
    // The sign-in stands: an event about erin still ends it.
    deliver(tx, &Event::get("sessionRevoked"), json!({"format": "complex", "user": iss_sub(tx, "erin"), "session": {"format": "opaque", "id": "IDP-E1"}}), json!({}), None);
    *tx.subject_status.lock().unwrap() = 0;
    receiver.poll_once().unwrap();
    assert_eq!(ended(&receiver), 1, "erin was tracked");
    assert_eq!(calls(tx).len(), 1, "a subject the transmitter never accepted is not removed");

    // Accepted, then the removal fails: counted, reported, not retried.
    receiver.track(session("L-e2", "erin", "", ""));
    assert_eq!(receiver.health().subjects_added, 1);
    *tx.subject_status.lock().unwrap() = 500;
    receiver.untrack("L-e2");
    receiver.untrack("L-e2");
    let health = receiver.health();
    assert_eq!((health.subjects_removed, health.subject_failures), (0, 1));
    assert_eq!(removed(tx).len(), 1);
    assert!(lines.lock().unwrap().last().unwrap().contains("Remove Subject (iss_sub) for a signed-out person on stream s1 answered 500"), "{:?}", lines.lock().unwrap());
    receiver.stop();
}

#[test]
fn subject_calls_are_skipped_without_endpoints_when_not_running_or_switched_off() {
    let lines: Lines = Arc::default();
    // The transmitter publishes no add/remove subject endpoint.
    let bare = start_transmitter();
    let receiver = running(bare, &lines, options(&lines));
    receiver.track(session("L-f1", "frank", "", ""));
    receiver.untrack("L-f1");
    receiver.stop();
    assert!(calls(bare).is_empty());

    let tx = start_transmitter();
    *tx.subject_endpoints.lock().unwrap() = true;
    // Switched off in the options.
    let off = running(tx, &lines, ReceiverOptions { add_subjects: false, ..options(&lines) });
    off.track(session("L-f2", "frank", "", ""));
    off.untrack("L-f2");
    off.stop();
    // Never started (as with signals off: there is no stream), and stopped.
    let idle = SignalsReceiver::new(&tx.url, Arc::new(|_, _| {}), options(&lines)).unwrap();
    idle.track(session("L-f3", "frank", "", ""));
    idle.untrack("L-f3");
    let stopped = running(tx, &lines, options(&lines));
    stopped.stop();
    stopped.track(session("L-f4", "frank", "", ""));
    stopped.untrack("L-f4");
    assert!(calls(tx).is_empty(), "{:?}", calls(tx));
    assert!(ReceiverOptions::default().add_subjects, "on by default");
    assert!(lines.lock().unwrap().is_empty());
}

#[test]
fn a_session_tracked_before_start_is_added_when_the_stream_is_known() {
    let tx = start_transmitter();
    *tx.subject_endpoints.lock().unwrap() = true;
    let lines: Lines = Arc::default();
    let receiver = SignalsReceiver::new(&tx.url, Arc::new(|_, _| {}), options(&lines)).unwrap();
    receiver.track(session("L-g1", "gina", "", ""));
    assert!(calls(tx).is_empty(), "no stream yet");
    receiver.start().unwrap();
    assert_eq!(calls(tx), vec![("add".to_string(), json!({"stream_id": "s1", "subject": iss_sub(tx, "gina"), "verified": true}))]);
    receiver.stop();
}

/// The calls are made as stream management is: with the relying party's
/// token, and a DPoP proof for the endpoint when that token is DPoP-bound.
/// `ssf.addSubjects: false` in its configuration turns them off.
#[test]
fn the_relying_partys_token_carries_the_calls_and_its_configuration_can_turn_them_off() {
    let tx = start_transmitter();
    *tx.subject_endpoints.lock().unwrap() = true;
    let op = crate::profile_test::start_op(crate::profile_test::dpop_cfg());
    let rp = Arc::new(crate::profile_test::rp_for(op, json!({"ssf": {"transmitter": tx.url}})));
    let receiver = SignalsReceiver::new(&tx.url, Arc::new(|_, _| {}), ReceiverOptions { relying_party: Some(Arc::clone(&rp)), poll_interval_ms: 60_000, ..ReceiverOptions::default() }).unwrap();
    receiver.start().unwrap();
    receiver.track(session("L-h1", "hana", "", ""));
    receiver.untrack("L-h1");
    receiver.stop();
    assert_eq!(calls(tx).len(), 2);
    let proofs = tx.proofs.lock().unwrap().clone();
    for path in ["/ssf/subjects:add", "/ssf/subjects:remove"] {
        assert!(proofs.iter().any(|(method, p, _)| method == "POST" && p == path), "a DPoP proof for {path}: {proofs:?}");
    }

    let quiet = start_transmitter();
    *quiet.subject_endpoints.lock().unwrap() = true;
    let off = Arc::new(crate::profile_test::rp_for(op, json!({"ssf": {"transmitter": quiet.url, "addSubjects": false}})));
    let receiver = SignalsReceiver::new(&quiet.url, Arc::new(|_, _| {}), ReceiverOptions { relying_party: Some(off), poll_interval_ms: 60_000, ..ReceiverOptions::default() }).unwrap();
    receiver.start().unwrap();
    receiver.track(session("L-h2", "hana", "", ""));
    receiver.untrack("L-h2");
    receiver.stop();
    assert!(calls(quiet).is_empty());
}

#[test]
fn ssf_add_subjects_must_be_a_boolean() {
    let base = |flag: Value| {
        let mut doc = JsonMap::new();
        doc.insert("issuer".into(), json!("https://idp.example"));
        doc.insert("metadataUrl".into(), json!("https://idp.example/.well-known/openid-configuration"));
        doc.insert("clientId".into(), json!("app"));
        doc.insert("clientSecret".into(), json!("s"));
        doc.insert("redirectUri".into(), json!("http://127.0.0.1/callback"));
        doc.insert("ssf".into(), json!({"transmitter": "https://idp.example", "addSubjects": flag}));
        doc
    };
    let err = resolve_config(&base(json!("yes")), ".").err().expect("refused");
    assert_eq!(err.code, "config");
    assert!(err.message.contains("ssf.addSubjects must be true or false"), "{}", err.message);
    let kept = resolve_config(&base(json!(false)), ".").unwrap();
    assert_eq!(kept.get("ssf").and_then(|ssf| ssf.get("addSubjects")), Some(&json!(false)));
    let omitted = resolve_config(&base(Value::Null), ".").unwrap();
    assert!(omitted.get("ssf").and_then(|ssf| ssf.get("addSubjects")).is_none(), "omitted means on");
    let err = RelyingParty::create(base(json!(1))).err().expect("refused at create too");
    assert!(err.message.contains("ssf.addSubjects"), "{}", err.message);
}
