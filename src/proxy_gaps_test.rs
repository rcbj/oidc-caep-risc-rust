// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The bounded session store, the receiver's health, its prompt stop and error
//! hook, and (feature `tokio`) the async API.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::suite::{deliver, manual, provider_config, query_of, start_provider, start_transmitter};
use crate::{apply_defaults, Event, Login, MemorySessionStore, ReceiverOptions, RelyingParty, SessionStore, SignalsReceiver};

fn login(sub: &str) -> Login {
    Login { subject: sub.to_string(), ..Login::default() }
}

#[test]
fn the_memory_store_is_bounded_oldest_first() {
    let store = MemorySessionStore::new(2, 0);
    store.set("a", login("a"));
    store.set("b", login("b"));
    store.set("a", login("a2"));
    assert_eq!(store.stats().evicted, 0, "rewriting a session takes no room");
    store.set("c", login("c"));
    assert!(store.get("b").is_none(), "b was the oldest write");
    assert_eq!(store.get("a").unwrap().subject, "a2");
    assert_eq!(store.get("c").unwrap().subject, "c");
    let stats = store.stats();
    assert_eq!((stats.entries, stats.max_entries, stats.evicted, stats.ttl_sec), (2, 2, 1, 0));
    store.remove("a");
    store.set("d", login("d"));
    assert_eq!(store.stats().evicted, 1, "a removal made room");
}

#[test]
fn the_memory_store_expires_entries() {
    let store = MemorySessionStore::new(10, 1);
    store.set("a", login("a"));
    store.set("b", login("b"));
    assert!(store.get("a").is_some());
    std::thread::sleep(Duration::from_millis(1100));
    assert!(store.get("a").is_none(), "an expired entry is never answered");
    assert_eq!(store.purge_expired(), 1, "b is purged");
    let stats = store.stats();
    assert_eq!((stats.entries, stats.expired), (0, 2));
}

#[test]
fn the_default_store_has_the_documented_bounds() {
    let stats = MemorySessionStore::default().stats();
    assert_eq!((stats.max_entries, stats.ttl_sec), (crate::DEFAULT_SESSION_MAX_ENTRIES, crate::DEFAULT_SESSION_TTL_SEC));
    let mut config = json!({"redirectUri": "https://app.example/cb"}).as_object().cloned().unwrap();
    apply_defaults(&mut config).unwrap();
    assert_eq!(config["sessionMaxEntries"], 10_000);
    assert_eq!(config["sessionTtlSec"], 86_400);
    for bad in [json!(0), json!(-1), json!(1.5), json!("many")] {
        let mut config = json!({"redirectUri": "https://app.example/cb", "sessionMaxEntries": bad}).as_object().cloned().unwrap();
        assert!(apply_defaults(&mut config).is_err(), "sessionMaxEntries {bad} is refused");
    }
    let mut config = json!({"redirectUri": "https://app.example/cb", "sessionTtlSec": 0}).as_object().cloned().unwrap();
    apply_defaults(&mut config).unwrap();
}

#[test]
fn a_relying_party_bounds_its_session_cache_by_configuration() {
    let stub = start_provider();
    let rp = RelyingParty::create(provider_config(stub, json!({"sessionMaxEntries": 1}))).unwrap();
    for id in ["s1", "s2"] {
        let request = rp.authorize().unwrap();
        let (_, location) = manual(&request.url);
        rp.complete_session(&query_of(&location), &request, id).unwrap();
    }
    assert!(rp.session("s1").is_none(), "the oldest sign-in made room");
    assert!(rp.session("s2").is_some());
}

fn bearer(ok: Arc<AtomicBool>) -> Option<Arc<dyn Fn() -> Vec<(String, String)> + Send + Sync>> {
    Some(Arc::new(move || {
        let token = if ok.load(Ordering::SeqCst) { "Bearer app-token" } else { "Bearer wrong" };
        vec![("authorization".into(), token.into())]
    }))
}

#[test]
fn the_receiver_reports_its_health() {
    let tx = start_transmitter();
    let ok = Arc::new(AtomicBool::new(true));
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let lines_cb = Arc::clone(&lines);
    let receiver = SignalsReceiver::new(&tx.url, Arc::new(|_, _| {}), ReceiverOptions {
        headers: bearer(Arc::clone(&ok)),
        poll_interval_ms: 60_000,
        on_error: Some(Arc::new(move |line: &str| lines_cb.lock().unwrap().push(line.to_string()))),
        ..ReceiverOptions::default()
    })
    .unwrap();
    let before = receiver.health();
    assert!(!before.running && before.started_at.is_none());
    assert!(!before.is_healthy(3600.0));
    assert_eq!(before.poll_interval_ms, 60_000);
    receiver.start().unwrap();
    let started = receiver.health();
    assert!(started.running);
    assert_eq!(started.stream_id, "s1");
    assert!(started.is_healthy(60.0), "a receiver that just started is healthy");
    receiver.track(json!({"local_id": "L1", "person": "urn:uuid:carol", "idp_session": "IDP-C1"}).as_object().cloned().unwrap());
    deliver(tx, &Event::get("sessionRevoked"), json!({"format": "complex", "user": {"format": "iss_sub", "iss": tx.url, "sub": "urn:uuid:carol"}, "session": {"format": "opaque", "id": "IDP-C1"}}), json!({}), None);
    receiver.poll_once().unwrap();
    let polled = receiver.health();
    assert!(polled.last_success_at.is_some() && polled.polls >= 1);
    assert_eq!((polled.sets_accepted, polled.sessions_ended, polled.consecutive_failures), (1, 1, 0));
    ok.store(false, Ordering::SeqCst);
    let mut failed = false;
    for _ in 0..3 {
        if receiver.poll_once().is_err() {
            failed = true;
            break;
        }
    }
    assert!(failed, "a poll with a refused token fails");
    let broken = receiver.health();
    assert!(broken.consecutive_failures >= 1 && broken.failed_polls >= 1);
    assert!(broken.last_error.contains("401"), "{}", broken.last_error);
    assert!(broken.last_error_at.is_some());
    assert!(broken.is_healthy_at(broken.last_success_at.unwrap() + 10.0, 30.0));
    assert!(!broken.is_healthy_at(broken.last_success_at.unwrap() + 31.0, 30.0), "no success within the window");
    let started_at = Instant::now();
    receiver.stop();
    assert!(started_at.elapsed() < Duration::from_secs(2), "stop wakes the sleeping poll thread");
    assert!(!receiver.health().running);
    ok.store(true, Ordering::SeqCst);
}

#[test]
fn a_failed_start_is_in_the_health_and_errors_reach_the_hook() {
    let receiver = SignalsReceiver::new("http://127.0.0.1:1", Arc::new(|_, _| {}), ReceiverOptions::default()).unwrap();
    assert!(receiver.start().is_err());
    let health = receiver.health();
    assert!(!health.running);
    assert!(health.last_error.starts_with("start: "), "{}", health.last_error);

    let tx = start_transmitter();
    let ok = Arc::new(AtomicBool::new(true));
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let lines_cb = Arc::clone(&lines);
    let receiver = SignalsReceiver::new(&tx.url, Arc::new(|_, _| {}), ReceiverOptions {
        headers: bearer(Arc::clone(&ok)),
        poll_interval_ms: 100,
        on_error: Some(Arc::new(move |line: &str| lines_cb.lock().unwrap().push(line.to_string()))),
        ..ReceiverOptions::default()
    })
    .unwrap();
    receiver.start().unwrap();
    ok.store(false, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(10);
    while lines.lock().unwrap().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    receiver.stop();
    let got = lines.lock().unwrap().clone();
    assert!(got.iter().any(|line| line.starts_with("ssf: poll failed")), "{got:?}");
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn the_async_api_signs_in_off_the_runtime_threads() {
    let stub = start_provider();
    let rp = Arc::new(RelyingParty::create_async(provider_config(stub, json!({}))).await.unwrap());
    let request = rp.authorize_async(crate::AuthorizeOptions::default()).await.unwrap();
    let url = request.url.clone();
    let location = tokio::task::spawn_blocking(move || manual(&url).1).await.unwrap();
    let query: HashMap<String, String> = query_of(&location);
    let login = rp.complete_session_async(query, request, "async-1".into()).await.unwrap();
    assert_eq!(login.session_id, "async-1");
    assert!(rp.session("async-1").is_some());
    let access = rp.session_access_token_async("async-1".into()).await.unwrap();
    assert_eq!(access.access_token, login.access_token);

    let tx = start_transmitter();
    let receiver = Arc::new(
        SignalsReceiver::new(&tx.url, Arc::new(|_, _| {}), ReceiverOptions {
            headers: bearer(Arc::new(AtomicBool::new(true))),
            poll_interval_ms: 60_000,
            ..ReceiverOptions::default()
        })
        .unwrap(),
    );
    receiver.start_async().await.unwrap();
    receiver.poll_once_async().await.unwrap();
    assert!(receiver.health().last_success_at.is_some());
    receiver.stop_async().await;
    assert!(!receiver.health().running);
}
