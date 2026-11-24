// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use oidc_caep_risc::{is_loopback, resolve_config, Event, Login, ReceiverOptions, RelyingParty, SignalEvent, SignalsReceiver, Transaction};
use serde_json::{json, Value};
use hmac::Mac;
use sha2::Sha256;
use tiny_http::{Header, Method, Request, Response, StatusCode};

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

struct Session {
    login: Login,
    expires: f64,
}

/// One received Shared Signals event, as the CAEP & RISC events tab draws
/// it and `app.js` receives it from `/api/signals`.
#[derive(Clone)]
struct LiveEvent {
    id: u64,
    event_type: String,
    jti: Option<String>,
    /// CAEP, RISC, SSF (the stream's own) or STS (iya-sts's own).
    family: String,
    at: String,
    subject: String,
    members: Value,
    ended: bool,
}

/// The most events kept; the oldest go first.
const MAX_EVENTS: usize = 200;

/// The family a SET event type belongs to, for its badge.
fn family_of(event_type: &str) -> &'static str {
    if event_type.contains("/caep/") {
        "CAEP"
    } else if event_type.contains("/risc/") {
        "RISC"
    } else if event_type.contains("/ssf/") {
        "SSF"
    } else {
        "STS"
    }
}

/// A UTC timestamp, `YYYY-MM-DD HH:MM:SS UTC`.
fn utc(secs: f64) -> String {
    let t = secs.max(0.0) as i64;
    let (days, rem) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn event_json(event: &LiveEvent) -> Value {
    json!({
        "id": event.id, "type": event.event_type, "jti": event.jti, "family": event.family,
        "at": event.at, "subject": event.subject, "members": event.members, "ended": event.ended,
        "about": if event.family == "SSF" { "stream" } else { "subject" },
    })
}

/// One log entry: the same markup `app.js`'s `entryNode()` draws.
fn event_item(event: &LiveEvent) -> String {
    let short = event.event_type.rsplit("/event-type/").next().unwrap_or(&event.event_type);
    let outcome = if event.family == "SSF" {
        "about the stream: the verification this session asked for"
    } else if event.ended {
        "ended this session"
    } else {
        "recorded; this session continues"
    };
    let mut out = format!(
        "<li class=\"log-item\" data-id=\"{}\"><div class=\"log-top\"><span class=\"badge {}\">{}</span> <strong>{}</strong> <time>{}</time></div><p class=\"log-outcome{}\">{}</p>",
        event.id,
        esc(&event.family.to_lowercase()),
        esc(&event.family),
        esc(short),
        esc(&event.at),
        if event.ended { " ended" } else { "" },
        outcome
    );
    if !event.subject.is_empty() {
        out.push_str(&format!("<p><small>Subject: {}</small></p>", esc(&event.subject)));
    }
    if let Some(members) = event.members.as_object().filter(|m| !m.is_empty()) {
        out.push_str("<table class=\"facts members\">");
        for (name, value) in members {
            if name == "subject" {
                continue;
            }
            let text = match value {
                Value::String(s) => s.clone(),
                Value::Object(o) if !o.is_empty() && o.values().all(|v| v.is_string()) => o.values().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(" / "),
                other => other.to_string(),
            };
            out.push_str(&format!("<tr><th>{}</th><td>{}</td></tr>", esc(name), esc(&text)));
        }
        out.push_str("</table>");
    }
    out.push_str(&format!("<p><small>jti {}</small></p></li>", esc(event.jti.as_deref().unwrap_or(""))));
    out
}

/// The CAEP & RISC events tab: the stream, the verification request and the
/// log, newest first. `app.js` adds what arrives without reloading.
fn events_panel(events: &[LiveEvent], stream: &str, notice: &str) -> String {
    let items: String = events.iter().rev().map(event_item).collect();
    let notice = if notice.is_empty() { String::new() } else { format!("<p class=\"notice\">{}</p>", esc(notice)) };
    format!(
        "{notice}<table class=\"facts\"><tr><th>Stream status</th><td id=\"stream-status\">{}</td></tr></table>\
<form id=\"verify-form\" method=\"post\" action=\"/signals/verify\"><button type=\"submit\">Ask for a verification event</button></form>\
<p><small>The CAEP and RISC events this application's receiver has accepted, newest first, and the verification events it asked for. Each appears here within moments of the receiver getting it: <span id=\"live-state\">connecting…</span></small></p>\
<ul class=\"log\" id=\"log\">{items}</ul>\
<p class=\"empty\" id=\"log-empty\"{}>No CAEP or RISC event yet. At iya-sts, change this person's password (credential-change), sign them out (session-revoked), or disable them (account-disabled), and watch this tab.</p>",
        esc(stream),
        if events.is_empty() { "" } else { " hidden" }
    )
}

struct App {
    sessions: Mutex<HashMap<String, Session>>,
    secret: Vec<u8>,
    secure: bool,
    config_path: String,
    public_url: String,
    public_given: bool,
    rp: Mutex<Option<Arc<RelyingParty>>>,
    rp_err: Mutex<Option<String>>,
    loaded: Mutex<bool>,
    receiver: Mutex<Option<SignalsReceiver>>,
    state: Mutex<String>,
    events: Mutex<Vec<LiveEvent>>,
    event_seq: std::sync::atomic::AtomicU64,
}

fn main() {
    let mut config_path = std::env::var("OIDC_CONFIG").unwrap_or_else(|_| "demo/oidc.json".into());
    let mut public_url = std::env::var("PUBLIC_URL").unwrap_or_default();
    let mut public_given = !public_url.is_empty() || !std::env::var("OIDC_PUBLIC_URL_GIVEN").unwrap_or_default().is_empty();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" {
            if let Some(value) = args.next() {
                config_path = value.clone();
                std::env::set_var("OIDC_CONFIG", &value);
            }
        } else if arg == "--public-url" {
            if let Some(value) = args.next() {
                public_url = value.trim_end_matches('/').to_string();
                public_given = true;
            }
        }
    }
    let secret = std::env::var("SESSION_SECRET").map(|s| s.into_bytes()).unwrap_or_else(|_| {
        let mut buf = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
        buf
    });
    let mut secure = true;
    let port = std::env::var("PORT").ok().and_then(|raw| raw.parse::<u16>().ok()).filter(|p| *p > 0).unwrap_or(3000);
    if let Ok(raw) = std::fs::read_to_string(&config_path) {
        if let Ok(mut doc) = serde_json::from_str::<Value>(&raw) {
            if let Some(obj) = doc.as_object_mut() {
                apply_redirects(obj, port, &public_url, public_given);
                let redirect = obj.get("redirectUri").and_then(|v| v.as_str()).or_else(|| obj.get("redirect_uri").and_then(|v| v.as_str())).unwrap_or("http://localhost/");
                if let Ok(parsed) = url::Url::parse(redirect) {
                    let host = parsed.host_str().unwrap_or("");
                    secure = parsed.scheme() == "https" || is_loopback(host);
                }
            }
        }
    } else {
        eprintln!("cannot read configuration: {config_path}");
    }
    let app = Arc::new(App {
        sessions: Mutex::new(HashMap::new()),
        secret,
        secure,
        config_path,
        public_url,
        public_given,
        rp: Mutex::new(None),
        rp_err: Mutex::new(None),
        loaded: Mutex::new(false),
        receiver: Mutex::new(None),
        state: Mutex::new(String::new()),
        events: Mutex::new(Vec::new()),
        event_seq: std::sync::atomic::AtomicU64::new(0),
    });
    let server = tiny_http::Server::http(format!("0.0.0.0:{port}")).expect("bind");
    println!("oidc-caep-risc-rust demo on port {port}");
    for request in server.incoming_requests() {
        let app = Arc::clone(&app);
        let _ = std::thread::spawn(move || route(app, request));
    }
}

fn route(app: Arc<App>, request: Request) {
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or("/").to_string();
    let method = request.method().clone();
    if path == "/healthz" {
        respond(request, 200, "text/plain", "ok", &[]);
        return;
    }
    if path == "/live-status" && method == Method::Get {
        live_status(&app, request);
        return;
    }
    if path == "/styles.css" && method == Method::Get {
        let raw = include_str!("public/styles.css");
        respond(request, 200, "text/css; charset=utf-8", raw, &[]);
        return;
    }
    if path == "/app.js" && method == Method::Get {
        let raw = include_str!("public/app.js");
        respond(request, 200, "text/javascript; charset=utf-8", raw, &[]);
        return;
    }
    if path == "/pep.js" && method == Method::Get {
        let raw = include_str!("public/pep.js");
        respond(request, 200, "text/javascript; charset=utf-8", raw, &[]);
        return;
    }
    if (path == "/pep-status" || path == "/pep-status.html") && method == Method::Get {
        pep_status_page(&app, request, path.ends_with(".html"));
        return;
    }
    if path == "/" && method == Method::Get {
        home(&app, request);
        return;
    }
    if path == "/api/signals" && method == Method::Get {
        signals_api(&app, request);
        return;
    }
    if path == "/events" && method == Method::Get {
        // No Server-Sent Events here: 204 tells app.js's EventSource to give
        // up, and it polls /api/signals every 3 s instead.
        respond(request, 204, "text/plain", "", &[]);
        return;
    }
    if path == "/signals/verify" && method == Method::Post {
        verify_signals(&app, request);
        return;
    }
    if path == "/login" && method == Method::Get {
        login(&app, request);
        return;
    }
    if path == "/callback" && method == Method::Get {
        callback(&app, request, &url);
        return;
    }
    if path == "/logout" && method == Method::Post {
        logout(&app, request);
        return;
    }
    #[cfg(feature = "pep")]
    if let Some(id) = path.strip_prefix("/orders/").filter(|id| !id.is_empty() && !id.contains('/')) {
        let id = id.to_string();
        order(&app, request, &method, &id);
        return;
    }
    respond(request, 404, "text/html; charset=utf-8", &page("Not found", "<h1>Not found</h1>"), &[]);
}

/// A route the embedded PEP protects (the `pep` feature, iya-sts#1206): the
/// signed-in person's access to one order, decided by the `pep` section's
/// PEP. A GET is `read` and anything else `write`. No sign-in is 401, a
/// Deny 403, and a decision that couldn't be made 503: never served.
#[cfg(feature = "pep")]
fn order(app: &Arc<App>, request: Request, method: &Method, id: &str) {
    use oidc_caep_risc::pep::{Access, Decision};
    let Some(session) = session_of(app, &request) else {
        respond(request, 401, "text/html; charset=utf-8", &page("Sign in", "<h1>Sign in first</h1><p><a href=\"/login\">Sign in</a></p>"), &[]);
        return;
    };
    let (rp, _) = relying_party(app);
    let Some(rp) = rp else {
        respond(request, 503, "text/html; charset=utf-8", &page("Unavailable", "<h1>The relying party is not configured</h1>"), &[]);
        return;
    };
    let action = if *method == Method::Get { "read" } else { "write" };
    match rp.decide(&session.login, &Access::new(action, "order", id)) {
        Decision::Permit { obligations, .. } => {
            let note = if obligations.is_empty() { String::new() } else { format!("<p><small>{} obligation(s) to discharge.</small></p>", obligations.len()) };
            let body = format!("<h1>Order {}</h1><p>The PEP permitted <code>{action}</code>.</p>{note}", esc(id));
            respond(request, 200, "text/html; charset=utf-8", &page("Order", &body), &[]);
        }
        Decision::Deny { why } => {
            let body = format!("<h1>Not allowed</h1><p>The PEP denied <code>{action}</code> on order {}: {}</p>", esc(id), esc(&why));
            respond(request, 403, "text/html; charset=utf-8", &page("Forbidden", &body), &[]);
        }
        Decision::Unavailable { why } => {
            let body = format!("<h1>No decision</h1><p>The PEP could not decide: {}</p>", esc(&why));
            respond(request, 503, "text/html; charset=utf-8", &page("Unavailable", &body), &[]);
        }
    }
}

fn home(app: &Arc<App>, request: Request) {
    let session = session_of(app, &request);
    let (rp, err) = relying_party(app);
    if let Some(session) = session {
        let login = &session.login;
        let who = if !login.preferred_username.is_empty() { login.preferred_username.clone() } else if !login.email.is_empty() { login.email.clone() } else { login.subject.clone() };
        let mut rows = String::new();
        for (name, value) in [("Subject", login.subject.as_str()), ("Issuer", login.issuer.as_str()), ("Email", login.email.as_str()), ("Name", login.name.as_str()), ("Username", login.preferred_username.as_str())] {
            if value.is_empty() {
                continue;
            }
            rows.push_str(&format!("<tr><th>{}</th><td>{}</td></tr>", esc(name), esc(value)));
        }
        // The relying party's session cache answers with a valid access token,
        // refreshing it (with a DPoP proof when DPoP is in use) when it is close to expiry.
        let token = match rp.as_ref().map(|rp| rp.session_access_token(&cookie_value(&request, "oidc_session"))) {
            Some(Ok(access)) => format!("{} access token, valid", access.token_type),
            Some(Err(err)) => format!("no valid access token ({err})"),
            None => "no relying party".to_string(),
        };
        rows.push_str(&format!("<tr><th>Access token</th><td>{}</td></tr>", esc(&token)));
        let session_body = format!("<table class=\"facts\">{rows}</table><p><small>The access token and the refresh token stay in this process. This page does not show them.</small></p><p><small>Shared Signals: {}</small></p>", esc(&app.state.lock().unwrap()));
        let tab = query_param(request.url(), "tab");
        let tab = match tab.as_str() {
            "pep" | "events" => tab,
            _ => "session".to_string(),
        };
        let events = app.events.lock().unwrap().clone();
        let last_id = events.last().map(|e| e.id).unwrap_or(0);
        let content = match tab.as_str() {
            "pep" => format!("<div id=\"pep-panel\" aria-live=\"polite\">{}</div><script src=\"/pep.js\" defer></script>", pep_fragment(rp.as_ref())),
            "events" => {
                let notice = match query_param(request.url(), "verify").as_str() {
                    "sent" => "A verification event was requested; it appears below when the transmitter sends it.",
                    "refused" => "The transmitter refused the verification request.",
                    _ => "",
                };
                events_panel(&events, &app.state.lock().unwrap(), notice)
            }
            _ => session_body,
        };
        let tab_link = |id: &str, href: &str, label: &str| {
            let on = id == tab;
            format!("<a class=\"page-tab\" role=\"tab\" href=\"{href}\" aria-selected=\"{on}\"{}>{label}</a>", if on { " aria-current=\"page\"" } else { "" })
        };
        let count = if events.is_empty() { String::new() } else { events.len().to_string() };
        let body = format!(
            "<h1>Signed in as {}</h1><nav class=\"page-tabs\" role=\"tablist\" aria-label=\"Sections\">{}{}{}</nav><p id=\"signal-banner\" class=\"problem\" hidden></p><p id=\"signal-toast\" class=\"notice\" hidden></p><div role=\"tabpanel\" id=\"panel\" data-base=\"\" data-tab=\"{}\" data-last-id=\"{last_id}\">{content}</div><form method=\"post\" action=\"/logout\"><button type=\"submit\">Sign out</button></form><script src=\"/app.js\" defer></script>",
            esc(&who),
            tab_link("session", "/", "Session"),
            tab_link("events", "/?tab=events", &format!("CAEP &amp; RISC events <span class=\"count\" id=\"signal-count\">{count}</span>")),
            tab_link("pep", "/?tab=pep", "Policy enforcement"),
            esc(&tab)
        );
        respond(request, 200, "text/html; charset=utf-8", &page("Signed in", &body), &[]);
        return;
    }
    let mut issuer = String::new();
    if let Some(rp) = rp.as_ref() {
        if let Some(text) = rp.metadata().get("issuer").and_then(|v| v.as_str()) {
            issuer = format!(" of {}", esc(text));
        }
    }
    let problem = err.map(|text| format!("<p class=\"problem\">{}</p>", esc(&format!("The relying party is not configured yet: {text}. Run scripts/configure_iya_sts.py.")))).unwrap_or_default();
    let body = format!("<h1>Sign in with OpenID Connect</h1>{problem}<p>This application is a confidential client{issuer}. It sends the browser to the authorization endpoint (Authorization Code, PKCE S256) and takes the tokens on the back channel.</p><p class=\"buttons\"><a class=\"button primary\" href=\"/login\">Sign in with OpenID Connect</a></p>");
    respond(request, 200, "text/html; charset=utf-8", &page("Sign in", &body), &[]);
}

fn live_status(app: &Arc<App>, request: Request) {
    let session = session_of(app, &request);
    let subject = session.as_ref().and_then(|session| {
        let login = &session.login;
        let who = if !login.preferred_username.is_empty() {
            login.preferred_username.clone()
        } else if !login.email.is_empty() {
            login.email.clone()
        } else {
            login.subject.clone()
        };
        if who.is_empty() { None } else { Some(who) }
    });
    let events = app.events.lock().unwrap().iter().map(|event| json!({"type": event.event_type, "jti": event.jti})).collect::<Vec<_>>();

    #[allow(unused_mut)]
    let mut body = json!({
        "signedIn": session.is_some(),
        "subject": subject,
        "receiver": app.state.lock().unwrap().clone(),
        "events": events,
    });
    #[cfg(feature = "pep")]
    if let Some(pep) = app.rp.lock().unwrap().as_ref().and_then(|rp| rp.pep().cloned()) {
        body["pep"] = pep_status(&pep);
    }
    respond(request, 200, "application/json", &body.to_string(), &[]);
}

/// The embedded PEP's state for `/live-status`. `Status` holds no secret:
/// the sync tokens are the versions of what the PEP holds, not credentials.
#[cfg(feature = "pep")]
fn pep_status(pep: &oidc_caep_risc::pep::Pep) -> Value {
    let status = pep.status();
    json!({
        "name": status.name,
        "mode": status.mode.as_str(),
        "application": status.application,
        "registered": status.registered,
        "running": status.running,
        "holdsPolicy": status.holds_policy,
        "policyCount": status.policy_count,
        "syncToken": status.sync_token,
        "decisions": status.decisions,
        "allowed": status.allowed,
        "refused": status.refused,
        "unavailable": status.unavailable,
        "lastError": status.last_error,
    })
}

fn login(app: &Arc<App>, request: Request) {
    let (rp, err) = relying_party(app);
    let Some(rp) = rp else {
        respond(request, 500, "text/html; charset=utf-8", &page("Error", &format!("<h1>Something went wrong</h1><p class=\"problem\">{}</p>", esc(&err.unwrap_or_default()))), &[]);
        return;
    };
    match rp.authorize() {
        Ok(txn) => {
            let sealed = seal(app, &json!({"state": txn.state, "nonce": txn.nonce, "code_verifier": txn.code_verifier, "redirect_uri": txn.redirect_uri, "acr_values": txn.acr_values}).to_string());
            redirect(request, 302, &txn.url, &[cookie(app, "oidc_txn", &sealed, "/callback", 600)]);
        }
        Err(err) => respond(request, 500, "text/html; charset=utf-8", &page("Error", &format!("<h1>Something went wrong</h1><p class=\"problem\">{}</p>", esc(&err.to_string()))), &[]),
    }
}

fn callback(app: &Arc<App>, request: Request, url: &str) {
    let clear = cookie(app, "oidc_txn", "", "/callback", 0);
    let (rp, err) = relying_party(app);
    let Some(rp) = rp else {
        respond(request, 500, "text/html; charset=utf-8", &page("Error", &format!("<h1>Something went wrong</h1><p class=\"problem\">{}</p>", esc(&err.unwrap_or_default()))), &[clear]);
        return;
    };
    let query_text = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut query = HashMap::new();
    for pair in query_text.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        query.insert(decode(k), decode(v));
    }
    let Some(txn_raw) = unseal(app, &cookie_value(&request, "oidc_txn")) else {
        respond(request, 400, "text/html; charset=utf-8", &page("Sign-in failed", "<h1>Sign-in failed</h1><p class=\"problem\">validation: this callback is not a sign-in this browser started</p><p><a href=\"/\">Start again</a></p>"), &[clear]);
        return;
    };
    let txn_doc: Value = serde_json::from_str(&txn_raw).unwrap_or(Value::Null);
    let txn = Transaction {
        state: txn_doc.get("state").and_then(|v| v.as_str()).unwrap_or("").into(),
        nonce: txn_doc.get("nonce").and_then(|v| v.as_str()).unwrap_or("").into(),
        code_verifier: txn_doc.get("code_verifier").and_then(|v| v.as_str()).unwrap_or("").into(),
        redirect_uri: txn_doc.get("redirect_uri").and_then(|v| v.as_str()).unwrap_or("").into(),
        acr_values: txn_doc.get("acr_values").and_then(|v| v.as_str()).unwrap_or("").into(),
        ..Transaction::default()
    };
    let mut buf = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    let sid = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &buf);
    // The tokens go in the relying party's session cache under the same id as the cookie.
    match rp.complete_session(&query, &txn, &sid) {
        Ok(login) => {
            if let Some(receiver) = app.receiver.lock().unwrap().as_ref() {
                let mut session = serde_json::Map::new();
                session.insert("local_id".into(), json!(sid));
                session.insert("person".into(), json!(login.subject));
                if !login.email.is_empty() {
                    session.insert("email".into(), json!(login.email));
                }
                if !login.sid.is_empty() {
                    session.insert("idp_session".into(), json!(login.sid));
                }
                receiver.track(session);
            }
            app.sessions.lock().unwrap().insert(sid.clone(), Session { login, expires: now() + 8.0 * 3600.0 });
            redirect(request, 303, "/", &[clear, cookie(app, "oidc_session", &sid, "/", 8 * 3600)]);
        }
        Err(err) => {
            let what = format!("{}: {err}", err.code);
            respond(request, 400, "text/html; charset=utf-8", &page("Sign-in failed", &format!("<h1>Sign-in failed</h1><p class=\"problem\">{}</p><p><a href=\"/\">Start again</a></p>", esc(&what))), &[clear]);
        }
    }
}

fn logout(app: &Arc<App>, request: Request) {
    if let Some(sid) = cookie_value(&request, "oidc_session").is_empty().then_some(String::new()).filter(|s| !s.is_empty()).or_else(|| {
        let sid = cookie_value(&request, "oidc_session");
        if sid.is_empty() { None } else { Some(sid) }
    }) {
        app.sessions.lock().unwrap().remove(&sid);
        if let Some(rp) = app.rp.lock().unwrap().as_ref() {
            rp.remove_session(&sid);
        }
        if let Some(receiver) = app.receiver.lock().unwrap().as_ref() {
            receiver.untrack(&sid);
        }
    }
    redirect(request, 303, "/", &[cookie(app, "oidc_session", "", "/", 0)]);
}

fn relying_party(app: &Arc<App>) -> (Option<Arc<RelyingParty>>, Option<String>) {
    let mut loaded = app.loaded.lock().unwrap();
    if !*loaded {
        *loaded = true;
        match load(app) {
            Ok(rp) => {
                *app.rp.lock().unwrap() = Some(Arc::new(rp));
                drop(loaded);
                start_receiver(app);
                let err = app.rp_err.lock().unwrap().clone();
                return (app.rp.lock().unwrap().clone(), err);
            }
            Err(err) => *app.rp_err.lock().unwrap() = Some(err),
        }
    }
    drop(loaded);
    let err = app.rp_err.lock().unwrap().clone();
    (app.rp.lock().unwrap().clone(), err)
}

fn load(app: &Arc<App>) -> Result<RelyingParty, String> {
    let raw = std::fs::read_to_string(&app.config_path).map_err(|err| err.to_string())?;
    let mut doc: Value = serde_json::from_str(&raw).map_err(|err| err.to_string())?;
    let obj = doc.as_object_mut().ok_or_else(|| "the configuration must be a JSON object".to_string())?;
    if let Ok(file) = std::env::var("OIDC_METADATA_FILE") {
        if !file.is_empty() {
            obj.insert("metadataFile".into(), json!(file));
            obj.remove("metadataUrl");
            obj.remove("issuer");
        }
    }
    let port = std::env::var("PORT").ok().and_then(|raw| raw.parse::<u16>().ok()).unwrap_or(3000);
    apply_redirects(obj, port, &app.public_url, app.public_given);
    if obj.get("signals") == Some(&Value::Bool(false)) {
        *app.state.lock().unwrap() = "not configured (signals are off)".into();
    } else if obj.get("ssf").and_then(|v| v.get("transmitter")).and_then(|v| v.as_str()).unwrap_or("").is_empty() {
        *app.state.lock().unwrap() = "not configured (no ssf block in the configuration file)".into();
    } else {
        *app.state.lock().unwrap() = "starting".into();
    }
    let base = std::path::Path::new(&app.config_path).parent().unwrap_or(std::path::Path::new("."));
    let resolved = resolve_config(obj, &base.to_string_lossy()).map_err(|err| err.to_string())?;
    RelyingParty::create(resolved).map_err(|err| err.to_string())
}

fn start_receiver(app: &Arc<App>) {
    let (rp, transmitter, interval, client_id, ca) = {
        let Some(rp) = app.rp.lock().unwrap().clone() else {
            return;
        };
        if rp.config().get("signals") == Some(&Value::Bool(false)) || rp.config().get("ssf").is_none() {
            if rp.config().get("signals") == Some(&Value::Bool(false)) {
                *app.state.lock().unwrap() = "not configured (signals are off)".into();
            }
            return;
        }
        let Some(ssf) = rp.config().get("ssf").and_then(|v| v.as_object()) else {
            return;
        };
        let transmitter = ssf.get("transmitter").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if transmitter.is_empty() {
            return;
        }
        let interval = ssf.get("pollIntervalMs").and_then(|v| v.as_i64()).or_else(|| ssf.get("pollIntervalMs").and_then(|v| v.as_u64().map(|n| n as i64))).filter(|n| *n > 0).unwrap_or(5000);
        let client_id = rp.config().get("clientId").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let ca = rp.tls_ca().map(|s| s.to_string());
        (Arc::clone(&rp), transmitter, interval, client_id, ca)
    };
    let end_app = Arc::clone(app);
    let events_app = Arc::clone(app);
    let receiver = SignalsReceiver::new(&transmitter, Arc::new(move |ids, _| {
        let mut sessions = end_app.sessions.lock().unwrap();
        for id in ids {
            sessions.remove(&id);
        }
    }), ReceiverOptions {
        tls_ca: ca,
        // Every transmitter call carries the relying party's ssf.manage token, with a DPoP
        // proof when that token is DPoP-bound; an ended session leaves its session cache.
        relying_party: Some(rp),
        scope: "ssf.manage".into(),
        description: format!("oidc-caep-risc-rust demo ({client_id})"),
        poll_interval_ms: interval,
        ..ReceiverOptions::default()
    });
    let receiver = receiver.map(|receiver| {
        receiver.on("*", move |event| remember_live_event(&events_app, event));
        receiver
    });
    match receiver.and_then(|receiver| receiver.start().map(|_| receiver)) {
        Ok(receiver) => {
            let stream = receiver.stream().and_then(|s| s.get("stream_id").and_then(|v| v.as_str()).map(|s| s.to_string())).unwrap_or_default();
            *app.state.lock().unwrap() = format!("polling stream {stream} at {transmitter}");
            *app.receiver.lock().unwrap() = Some(receiver);
        }
        Err(err) => {
            *app.state.lock().unwrap() = format!("not running: {err}");
            eprintln!("ssf: the receiver did not start: {err}");
        }
    }
}

/// `GET /api/signals?after=<id>`: what arrived after the last event the
/// page shows, and the stream's state. 401 once the session is gone, which
/// `app.js` reads as signed out.
fn signals_api(app: &Arc<App>, request: Request) {
    if session_of(app, &request).is_none() {
        respond(request, 401, "application/json", &json!({"signedIn": false}).to_string(), &[]);
        return;
    }
    let after = query_param(request.url(), "after").parse::<u64>().unwrap_or(0);
    let events: Vec<Value> = app.events.lock().unwrap().iter().filter(|e| e.id > after).map(event_json).collect();
    let body = json!({"events": events, "streamStatus": {"status": app.state.lock().unwrap().clone(), "at": utc(now())}});
    respond(request, 200, "application/json", &body.to_string(), &[]);
}

/// `POST /signals/verify`: asks the transmitter for a verification event on
/// the stream. JSON for `app.js`, a redirect back to the tab without it.
fn verify_signals(app: &Arc<App>, request: Request) {
    if session_of(app, &request).is_none() {
        redirect(request, 303, "/", &[]);
        return;
    }
    let state = format!("demo-{}", app.event_seq.load(std::sync::atomic::Ordering::Relaxed) + 1);
    let outcome = match app.receiver.lock().unwrap().as_ref().map(|r| r.verify(&state)) {
        Some(Ok(())) => "sent",
        Some(Err(err)) => {
            eprintln!("ssf: verification request refused: {err}");
            "refused"
        }
        None => "refused",
    };
    let wants_json = request.headers().iter().any(|h| h.field.equiv("accept") && h.value.as_str().contains("application/json"));
    if wants_json {
        respond(request, 200, "application/json", &json!({"outcome": outcome}).to_string(), &[]);
    } else {
        redirect(request, 303, &format!("/?tab=events&verify={outcome}"), &[]);
    }
}

fn remember_live_event(app: &Arc<App>, event: SignalEvent) {
    let event_type = event.event_type;
    let jti = if event.jti.is_empty() { None } else { Some(event.jti) };
    let mut subject: Vec<String> = event.subject.iter().map(|(k, v)| format!("{k} {v}")).collect();
    subject.sort();
    let live = LiveEvent {
        id: app.event_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
        event_type: event_type.clone(),
        jti,
        family: family_of(&event_type).to_string(),
        at: utc(event.iat.unwrap_or_else(now)),
        subject: subject.join(", "),
        members: Value::Object(event.payload.clone().into_iter().collect()),
        ended: event.ended,
    };
    {
        let mut events = app.events.lock().unwrap();
        events.push(live);
        let over = events.len().saturating_sub(MAX_EVENTS);
        events.drain(..over);
    }
    // The receiver drops a session only when the event's IdP session id matches.
    // A session-revoked that names a different id leaves this demo's one login in place.
    if event_type != Event::get("sessionRevoked") || !event.sessions.is_empty() {
        return;
    }
    let ids: Vec<String> = {
        let sessions = app.sessions.lock().unwrap();
        if sessions.len() != 1 {
            return;
        }
        sessions.keys().cloned().collect()
    };
    app.sessions.lock().unwrap().remove(&ids[0]);
    if let Some(rp) = app.rp.lock().unwrap().as_ref() {
        rp.remove_session(&ids[0]);
    }
    if let Some(receiver) = app.receiver.lock().unwrap().as_ref() {
        receiver.untrack(&ids[0]);
    }
}

fn session_of(app: &Arc<App>, request: &Request) -> Option<Session> {
    let sid = cookie_value(request, "oidc_session");
    let mut sessions = app.sessions.lock().unwrap();
    let session = sessions.get(&sid)?;
    if session.expires <= now() {
        sessions.remove(&sid);
        return None;
    }
    Some(Session { login: session.login.clone(), expires: session.expires })
}

fn cookie(app: &Arc<App>, name: &str, value: &str, path: &str, max_age: i64) -> String {
    let mut parts = vec![format!("{name}={value}"), format!("Path={path}"), "HttpOnly".into(), "SameSite=Lax".into()];
    if app.secure {
        parts.push("Secure".into());
    }
    parts.push(format!("Max-Age={max_age}"));
    parts.join("; ")
}

fn cookie_value(request: &Request, name: &str) -> String {
    for header in request.headers() {
        if header.field.equiv("cookie") {
            for part in header.value.as_str().split(';') {
                let Some((k, v)) = part.trim().split_once('=') else { continue };
                if k == name {
                    return v.to_string();
                }
            }
        }
    }
    String::new()
}

fn respond(request: Request, status: u16, content_type: &str, body: &str, cookies: &[String]) {
    let mut response = Response::new(StatusCode(status), vec![], Cursor::new(body.as_bytes().to_vec()), Some(body.len()), None);
    let _ = response.add_header(Header::from_bytes("Content-Type", content_type).unwrap());
    let _ = response.add_header(Header::from_bytes("Cache-Control", "no-store").unwrap());
    let _ = response.add_header(Header::from_bytes("Referrer-Policy", "no-referrer").unwrap());
    let _ = response.add_header(Header::from_bytes("X-Content-Type-Options", "nosniff").unwrap());
    let _ = response.add_header(Header::from_bytes("X-Frame-Options", "DENY").unwrap());
    let _ = response.add_header(Header::from_bytes("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'").unwrap());
    for cookie in cookies {
        let _ = response.add_header(Header::from_bytes("Set-Cookie", cookie.as_str()).unwrap());
    }
    let _ = request.respond(response);
}

fn redirect(request: Request, status: u16, location: &str, cookies: &[String]) {
    let mut response = Response::new(StatusCode(status), vec![], Cursor::new(Vec::new()), Some(0), None);
    let _ = response.add_header(Header::from_bytes("Location", location).unwrap());
    let _ = response.add_header(Header::from_bytes("Cache-Control", "no-store").unwrap());
    for cookie in cookies {
        let _ = response.add_header(Header::from_bytes("Set-Cookie", cookie.as_str()).unwrap());
    }
    let _ = request.respond(response);
}

fn page(title: &str, body: &str) -> String {
    format!("<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>{}</title><link rel=\"stylesheet\" href=\"/styles.css\"></head>\n<body><header><a href=\"/\">oidc-caep-risc demo</a></header><main>\n{body}\n</main><footer>A traditional web application signing in with OpenID Connect through oidc-caep-risc.</footer></body>\n</html>\n", esc(title))
}

/// One query parameter of a request URL, decoded, or empty.
fn query_param(url: &str, name: &str) -> String {
    let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    query
        .split('&')
        .filter_map(|pair| pair.split_once('=').or(Some((pair, ""))))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| decode(v))
        .unwrap_or_default()
}

/// `GET /pep-status` (JSON) and `/pep-status.html` (the tab's fragment):
/// what the embedded PEP holds and has done. For a signed-in browser only,
/// like the page that shows it. Nothing in it is secret: counts, times,
/// tokens that name policy versions, and the PEP key's public thumbprint.
fn pep_status_page(app: &Arc<App>, request: Request, html: bool) {
    if session_of(app, &request).is_none() {
        respond(request, 401, "text/plain; charset=utf-8", "sign in first", &[]);
        return;
    }
    let (rp, _) = relying_party(app);
    if html {
        respond(request, 200, "text/html; charset=utf-8", &pep_fragment(rp.as_ref()), &[]);
    } else {
        respond(request, 200, "application/json", &pep_json(rp.as_ref()).to_string(), &[]);
    }
}

#[cfg(feature = "pep")]
fn pep_json(rp: Option<&Arc<RelyingParty>>) -> Value {
    let Some(pep) = rp.and_then(|rp| rp.pep()) else {
        return json!({"enabled": false, "why": "no pep section is configured"});
    };
    let s = pep.status();
    let ms = |d: Option<std::time::Duration>| d.map(|d| d.as_millis() as u64);
    json!({
        "enabled": true,
        "name": s.name, "mode": s.mode.as_str(), "application": s.application, "pdpUrl": s.pdp_url,
        "protocolVersion": s.protocol_version, "registered": s.registered, "running": s.running,
        "eventStream": s.event_stream.as_str(), "keyThumbprint": s.key_thumbprint, "problems": s.last_error,
        "policy": {
            "held": s.holds_policy, "count": s.policy_count, "syncToken": s.sync_token,
            "catalogueToken": s.catalogue_token, "catalogueSubjectClaims": s.catalogue_subject_properties,
            "sinceUpdateMs": ms(s.since_policy_update), "sinceLastPullMs": ms(s.since_last_pull),
            "untilNextPullMs": ms(s.until_next_pull), "pulls": s.pulls, "pullsChanged": s.pulls_changed,
            "pullFailures": s.pull_failures, "eventsReceived": s.events_received, "eventsIgnored": s.events_ignored,
            "sinceLastEventMs": ms(s.since_last_event),
        },
        "decisions": {
            "total": s.decisions, "allowed": s.allowed, "denied": s.refused, "unavailable": s.unavailable,
            "undischargeable": s.undischargeable, "meanMicros": s.mean_decision_micros, "maxMicros": s.max_decision_micros,
            "permitCacheEntries": s.permit_cache_entries, "permitCacheHits": s.permit_cache_hits,
        },
        "controlPlane": {
            "uptimeMs": ms(s.uptime), "registrations": s.registrations, "heartbeats": s.heartbeats,
            "heartbeatFailures": s.heartbeat_failures, "sinceLastHeartbeatMs": ms(s.since_last_heartbeat),
            "untilNextHeartbeatMs": ms(s.until_next_heartbeat), "recordsQueued": s.records_queued,
            "recordsShipped": s.records_shipped, "recordsDropped": s.records_dropped,
        },
    })
}

#[cfg(not(feature = "pep"))]
fn pep_json(_rp: Option<&Arc<RelyingParty>>) -> Value {
    json!({"enabled": false, "why": "this demo was built without the pep feature"})
}

/// A duration as a person reads it.
fn human(d: Option<std::time::Duration>, ago: bool) -> String {
    let Some(d) = d else { return "—".into() };
    let s = d.as_secs();
    let text = if s == 0 {
        return if ago { "just now".into() } else { "now".into() };
    } else if s < 120 {
        format!("{s} s")
    } else if s < 7200 {
        format!("{} min {} s", s / 60, s % 60)
    } else {
        format!("{} h {} min", s / 3600, s % 3600 / 60)
    };
    if ago { format!("{text} ago") } else { format!("in {text}") }
}

/// The Policy enforcement tab's content: drawn by the server, and fetched
/// again every few seconds by `pep.js`.
fn pep_fragment(rp: Option<&Arc<RelyingParty>>) -> String {
    let v = pep_json(rp);
    if v["enabled"] != json!(true) {
        return format!(
            "<p class=\"notice\">No embedded PEP: {}. Add a <code>pep</code> section to the configuration and build with the <code>local</code> (or <code>pep</code>) feature; see <code>docs/remote-pep.md</code>.</p>",
            esc(v["why"].as_str().unwrap_or(""))
        );
    }
    let text = |x: &Value| match x {
        Value::String(s) if s.is_empty() => "—".to_string(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => if *b { "yes".into() } else { "no".into() },
        Value::Null => "—".into(),
        other => other.to_string(),
    };
    let dur = |x: &Value, ago: bool| human(x.as_u64().map(std::time::Duration::from_millis), ago);
    let p = &v["policy"];
    let d = &v["decisions"];
    let c = &v["controlPlane"];
    let local = v["mode"] == json!("local");
    let micros = |x: &Value| x.as_u64().map(|m| if m >= 1000 { format!("{:.1} ms", m as f64 / 1000.0) } else { format!("{m} µs") }).unwrap_or_else(|| "—".into());
    let mut cards: Vec<(&str, Vec<(String, String)>)> = Vec::new();
    cards.push(("Decisions", vec![
        ("Decisions".into(), text(&d["total"])),
        ("Allowed".into(), text(&d["allowed"])),
        ("Denied".into(), text(&d["denied"])),
        ("Unavailable (no decision; refused)".into(), text(&d["unavailable"])),
        ("Stopped by an obligation".into(), text(&d["undischargeable"])),
        ("Mean time per decision".into(), micros(&d["meanMicros"])),
        ("Slowest decision".into(), micros(&d["maxMicros"])),
    ]));
    if !local {
        cards.last_mut().unwrap().1.push(("Permit cache".into(), format!("{} held, {} answered from it", text(&d["permitCacheEntries"]), text(&d["permitCacheHits"]))));
    }
    let mut policy = vec![
        ("Policies held".into(), if local { text(&p["count"]) } else { "— (central mode: iya-sts decides)".into() }),
        ("Last policy update".into(), dur(&p["sinceUpdateMs"], true)),
        ("Last pull (changed or not)".into(), dur(&p["sinceLastPullMs"], true)),
        ("Next scheduled pull".into(), dur(&p["untilNextPullMs"], false)),
        ("Pulls".into(), format!("{} ({} brought changes, {} failed)", text(&p["pulls"]), text(&p["pullsChanged"]), text(&p["pullFailures"]))),
        ("Policy-change events".into(), format!("{} acted on, {} for another PEP; last {}", text(&p["eventsReceived"]), text(&p["eventsIgnored"]), dur(&p["sinceLastEventMs"], true))),
        ("Catalogue claims sent".into(), text(&p["catalogueSubjectClaims"])),
    ];
    if local {
        policy.push(("Policy set version".into(), text(&p["syncToken"])));
    }
    policy.push(("Catalogue version".into(), text(&p["catalogueToken"])));
    cards.push(("Cached policy", policy));
    cards.push(("The PEP", vec![
        ("Name".into(), text(&v["name"])),
        ("Mode".into(), text(&v["mode"])),
        ("Application".into(), text(&v["application"])),
        ("iya-sts".into(), text(&v["pdpUrl"])),
        ("Registered".into(), text(&v["registered"])),
        ("Running".into(), format!("{} (up {})", text(&v["running"]), dur(&c["uptimeMs"], false).trim_start_matches("in "))),
        ("Policy-change events on the stream".into(), text(&v["eventStream"])),
        ("Protocol version".into(), text(&v["protocolVersion"])),
        ("Key thumbprint".into(), text(&v["keyThumbprint"])),
    ]));
    cards.push(("Control plane", vec![
        ("Heartbeats".into(), format!("{} ({} failed)", text(&c["heartbeats"]), text(&c["heartbeatFailures"]))),
        ("Last heartbeat".into(), dur(&c["sinceLastHeartbeatMs"], true)),
        ("Next heartbeat".into(), dur(&c["untilNextHeartbeatMs"], false)),
        ("Registrations".into(), text(&c["registrations"])),
        ("Decision records".into(), format!("{} queued, {} sent, {} dropped", text(&c["recordsQueued"]), text(&c["recordsShipped"]), text(&c["recordsDropped"]))),
    ]));
    let mut out = String::new();
    let problems = v["problems"].as_str().unwrap_or("");
    if !problems.is_empty() {
        out.push_str(&format!("<p class=\"problem\">{}</p>", esc(problems)));
    }
    for (title, rows) in cards {
        out.push_str(&format!("<section class=\"card\"><h2>{}</h2><table class=\"facts\">", esc(title)));
        for (k, val) in rows {
            out.push_str(&format!("<tr><th>{}</th><td>{}</td></tr>", esc(&k), esc(&val)));
        }
        out.push_str("</table></section>");
    }
    out.push_str("<p><small>Refreshed every 2 seconds. <a href=\"/pep-status\">As JSON</a>.</small></p>");
    out
}

fn esc(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn seal(app: &Arc<App>, value: &str) -> String {
    let body = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, value.as_bytes());
    format!("{body}.{}", mac(app, &body))
}

fn unseal(app: &Arc<App>, token: &str) -> Option<String> {
    let (body, tag) = token.split_once('.')?;
    let expected = mac(app, body);
    if expected.len() != tag.len() || expected.bytes().zip(tag.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) != 0 {
        return None;
    }
    let raw = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, body).ok()?;
    String::from_utf8(raw).ok()
}

fn mac(app: &Arc<App>, value: &str) -> String {
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(&app.secret).unwrap();
    mac.update(value.as_bytes());
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, mac.finalize().into_bytes())
}

fn decode(value: &str) -> String {
    let plus = value.replace('+', " ");
    let bytes = plus.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00"), 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn apply_redirects(raw: &mut serde_json::Map<String, Value>, port: u16, public: &str, given: bool) {
    let redirect = raw.get("redirectUri").and_then(|v| v.as_str()).or_else(|| raw.get("redirect_uri").and_then(|v| v.as_str())).unwrap_or("").to_string();
    let post = raw.get("postLogoutRedirectUri").and_then(|v| v.as_str()).or_else(|| raw.get("post_logout_redirect_uri").and_then(|v| v.as_str())).unwrap_or("").to_string();
    let (moved_r, moved_p) = redirects_for(&redirect, &post, public, given, port);
    if raw.get("redirectUri").is_some() || raw.get("redirect_uri").is_none() {
        raw.insert("redirectUri".into(), json!(moved_r));
    } else {
        raw.insert("redirect_uri".into(), json!(moved_r));
    }
    if raw.get("postLogoutRedirectUri").is_some() || raw.get("post_logout_redirect_uri").is_some() || !post.is_empty() {
        if raw.get("post_logout_redirect_uri").is_some() && raw.get("postLogoutRedirectUri").is_none() {
            raw.insert("post_logout_redirect_uri".into(), json!(moved_p));
        } else {
            raw.insert("postLogoutRedirectUri".into(), json!(moved_p));
        }
    }
}

fn redirects_for(redirect: &str, post: &str, public: &str, given: bool, port: u16) -> (String, String) {
    if given && !public.is_empty() {
        (move_origin(redirect, public), move_origin(post, public))
    } else if port > 0 {
        (on_port(redirect, port), on_port(post, port))
    } else {
        (redirect.to_string(), post.to_string())
    }
}

fn on_port(raw: &str, port: u16) -> String {
    let Ok(mut parts) = url::Url::parse(raw) else {
        return raw.to_string();
    };
    let host = parts.host_str().unwrap_or("");
    if !is_loopback(host) {
        return raw.to_string();
    }
    let _ = parts.set_port(Some(port));
    if parts.path().is_empty() {
        parts.set_path("/");
    }
    parts.to_string()
}

fn move_origin(value: &str, public: &str) -> String {
    let base_text = if public.ends_with('/') { public.to_string() } else { format!("{public}/") };
    let Ok(base) = url::Url::parse(&base_text) else {
        return value.to_string();
    };
    let Ok(mut nxt) = url::Url::parse(value) else {
        return value.to_string();
    };
    let _ = nxt.set_scheme(base.scheme());
    let _ = nxt.set_host(base.host_str());
    let _ = nxt.set_port(base.port());
    if nxt.path().is_empty() {
        nxt.set_path("/");
    }
    nxt.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live(id: u64, event_type: &str, ended: bool) -> LiveEvent {
        LiveEvent {
            id,
            event_type: event_type.into(),
            jti: Some(format!("j<{id}>")),
            family: family_of(event_type).into(),
            at: utc(1_795_000_000.0),
            subject: "format email, email <a@x>".into(),
            members: json!({"reason_admin": {"en": "<b>gone</b>"}, "subject": {"x": 1}}),
            ended,
        }
    }

    #[test]
    fn the_events_tab_draws_each_event_newest_first_and_escapes() {
        let caep = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
        let risc = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
        let html = events_panel(&[live(1, caep, true), live(2, risc, false)], "polling <s>", "");
        assert!(html.find("data-id=\"2\"").unwrap() < html.find("data-id=\"1\"").unwrap(), "newest first");
        assert!(html.contains("<span class=\"badge caep\">CAEP</span> <strong>session-revoked</strong>"));
        assert!(html.contains("<span class=\"badge risc\">RISC</span>"));
        assert!(html.contains("ended this session") && html.contains("recorded; this session continues"));
        assert!(html.contains("&lt;b&gt;gone&lt;/b&gt;") && !html.contains("<b>gone"), "members escaped");
        assert!(html.contains("polling &lt;s&gt;") && html.contains("j&lt;1&gt;"));
        assert!(html.contains("id=\"log-empty\" hidden"), "the empty note hidden once there are events");
        assert!(events_panel(&[], "", "").contains("id=\"log-empty\">"), "and shown when there are none");
        assert!(!html.contains(">subject<"), "the subject member is the Subject line, not a row");
    }

    #[test]
    fn an_event_is_handed_to_app_js_in_the_shape_it_reads() {
        let e = event_json(&live(7, "https://schemas.openid.net/secevent/ssf/event-type/verification", false));
        assert_eq!(e["id"], 7);
        assert_eq!(e["family"], "SSF");
        assert_eq!(e["about"], "stream");
        assert_eq!(family_of("urn:iya:sts:secevent:event-type:pep-policies-changed"), "STS");
        assert_eq!(utc(0.0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(1_795_000_000.0), "2026-11-18 11:06:40 UTC");
    }

    #[test]
    fn query_param_reads_one_parameter() {
        assert_eq!(query_param("/?tab=pep&x=1", "tab"), "pep");
        assert_eq!(query_param("/", "tab"), "");
        assert_eq!(query_param("/?x=a%20b", "x"), "a b");
    }

    #[test]
    fn durations_read_as_a_person_reads_them() {
        use std::time::Duration;
        assert_eq!(human(None, true), "—");
        assert_eq!(human(Some(Duration::from_millis(400)), true), "just now");
        assert_eq!(human(Some(Duration::from_secs(42)), true), "42 s ago");
        assert_eq!(human(Some(Duration::from_secs(300)), false), "in 5 min 0 s");
        assert_eq!(human(Some(Duration::from_secs(7300)), true), "2 h 1 min ago");
    }

    #[test]
    fn no_relying_party_or_no_pep_says_so() {
        assert!(pep_fragment(None).contains("No embedded PEP"));
        assert_eq!(pep_json(None)["enabled"], false);
    }

    #[cfg(feature = "pep")]
    #[test]
    fn the_tab_draws_every_card_and_escapes() {
        use p256::pkcs8::EncodePrivateKey;
        let key = p256::ecdsa::SigningKey::from_slice(&[4u8; 32]).unwrap().to_pkcs8_pem(Default::default()).unwrap().to_string();
        let path = std::env::temp_dir().join(format!("demo-pep-{}.pem", std::process::id()));
        std::fs::write(&path, key).unwrap();
        let config: oidc_caep_risc::JsonMap = serde_json::from_value(json!({
            "clientId": "demo", "clientSecret": "s", "redirectUri": "http://127.0.0.1/callback", "allowInsecure": true,
            "signals": false,
            "metadata": {"issuer": "http://127.0.0.1:9", "authorization_endpoint": "http://127.0.0.1:9/a", "token_endpoint": "http://127.0.0.1:9/t", "jwks_uri": "http://127.0.0.1:9/j", "id_token_signing_alg_values_supported": ["RS256"]},
            "pep": {"name": "pep-demo", "mode": "central", "assertionKey": path.to_string_lossy(), "timeoutMs": 300}
        })).unwrap();
        let rp = Arc::new(RelyingParty::create(config).unwrap());
        rp.decide(&Login::default(), &oidc_caep_risc::pep::Access::new("read", "order", "1"));
        let html = pep_fragment(Some(&rp));
        for title in ["Decisions", "Cached policy", "The PEP", "Control plane"] {
            assert!(html.contains(&format!("<h2>{title}</h2>")), "{title}");
        }
        assert!(html.contains("<th>Decisions</th><td>1</td>"), "the decision was counted");
        assert!(html.contains("<th>Unavailable (no decision; refused)</th><td>1</td>"));
        assert!(html.contains("class=\"problem\""), "iya-sts is unreachable, and the page says so");
        assert!(html.contains("Permit cache"), "central mode shows the cache");
        assert!(!html.contains("<script"), "the fragment carries no script");
        let v = pep_json(Some(&rp));
        assert_eq!((v["enabled"].clone(), v["mode"].clone(), v["decisions"]["unavailable"].clone()), (json!(true), json!("central"), json!(1)));
        assert!(v["policy"]["untilNextPullMs"].is_u64() || v["policy"]["untilNextPullMs"].is_null());
    }
}
