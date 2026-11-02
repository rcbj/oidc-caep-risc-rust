// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use oidc_caep_risc::{resolve_config, Login, ReceiverOptions, RelyingParty, SignalsReceiver, Transaction};
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

struct App {
    sessions: Mutex<HashMap<String, Session>>,
    secret: Vec<u8>,
    secure: bool,
    config_path: String,
    public_url: String,
    public_given: bool,
    rp: Mutex<Option<RelyingParty>>,
    rp_err: Mutex<Option<String>>,
    loaded: Mutex<bool>,
    receiver: Mutex<Option<SignalsReceiver>>,
    state: Mutex<String>,
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
                    secure = parsed.scheme() == "https" || host == "localhost" || host == "127.0.0.1";
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
    if path == "/" && method == Method::Get {
        home(&app, request);
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
    respond(request, 404, "text/html; charset=utf-8", &page("Not found", "<h1>Not found</h1>"), &[]);
}

fn home(app: &Arc<App>, request: Request) {
    let session = session_of(app, &request);
    let (guard, err) = relying_party(app);
    let rp = guard.as_ref();
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
        let body = format!("<h1>Signed in as {}</h1><table class=\"facts\">{rows}</table><p><small>The access token and the refresh token stay in this process. This page does not show them.</small></p><p><small>Shared Signals: {}</small></p><form method=\"post\" action=\"/logout\"><button type=\"submit\">Sign out</button></form>", esc(&who), esc(&app.state.lock().unwrap()));
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

fn login(app: &Arc<App>, request: Request) {
    let (guard, err) = relying_party(app);
    let rp = guard.as_ref();
    let Some(rp) = rp else {
        respond(request, 500, "text/html; charset=utf-8", &page("Error", &format!("<h1>Something went wrong</h1><p class=\"problem\">{}</p>", esc(&err.unwrap_or_default()))), &[]);
        return;
    };
    match rp.authorize() {
        Ok(txn) => {
            let sealed = seal(app, &json!({"state": txn.state, "nonce": txn.nonce, "code_verifier": txn.code_verifier, "redirect_uri": txn.redirect_uri}).to_string());
            redirect(request, 302, &txn.url, &[cookie(app, "oidc_txn", &sealed, "/callback", 600)]);
        }
        Err(err) => respond(request, 500, "text/html; charset=utf-8", &page("Error", &format!("<h1>Something went wrong</h1><p class=\"problem\">{}</p>", esc(&err.to_string()))), &[]),
    }
}

fn callback(app: &Arc<App>, request: Request, url: &str) {
    let clear = cookie(app, "oidc_txn", "", "/callback", 0);
    let (guard, err) = relying_party(app);
    let rp = guard.as_ref();
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
        url: String::new(),
        max_age: None,
        expected_sub: String::new(),
    };
    match rp.complete(&query, &txn) {
        Ok(login) => {
            let mut buf = vec![0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
            let sid = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &buf);
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
        if let Some(receiver) = app.receiver.lock().unwrap().as_ref() {
            receiver.untrack(&sid);
        }
    }
    redirect(request, 303, "/", &[cookie(app, "oidc_session", "", "/", 0)]);
}

fn relying_party(app: &Arc<App>) -> (std::sync::MutexGuard<'_, Option<RelyingParty>>, Option<String>) {
    let mut loaded = app.loaded.lock().unwrap();
    if !*loaded {
        *loaded = true;
        match load(app) {
            Ok(rp) => {
                *app.rp.lock().unwrap() = Some(rp);
                drop(loaded);
                start_receiver(app);
                let err = app.rp_err.lock().unwrap().clone();
                return (app.rp.lock().unwrap(), err);
            }
            Err(err) => *app.rp_err.lock().unwrap() = Some(err),
        }
    }
    drop(loaded);
    let err = app.rp_err.lock().unwrap().clone();
    (app.rp.lock().unwrap(), err)
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
    let (transmitter, interval, client_id, ca, skip) = {
        let guard = app.rp.lock().unwrap();
        let Some(rp) = guard.as_ref() else {
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
        (transmitter, interval, client_id, ca, false)
    };
    let _ = skip;
    let headers_app = Arc::clone(app);
    let end_app = Arc::clone(app);
    let receiver = SignalsReceiver::new(&transmitter, Arc::new(move |ids, _| {
        let mut sessions = end_app.sessions.lock().unwrap();
        for id in ids {
            sessions.remove(&id);
        }
    }), ReceiverOptions {
        tls_ca: ca,
        headers: Some(Arc::new(move || {
            let guard = headers_app.rp.lock().unwrap();
            let Some(rp) = guard.as_ref() else {
                return Vec::new();
            };
            match rp.client_credentials("ssf.manage") {
                Ok(access) if !access.access_token.is_empty() => vec![("authorization".into(), format!("Bearer {}", access.access_token))],
                _ => Vec::new(),
            }
        })),
        description: format!("oidc-caep-risc-rust demo ({client_id})"),
        poll_interval_ms: interval,
        ..ReceiverOptions::default()
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
    let _ = response.add_header(Header::from_bytes("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'").unwrap());
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
    if host != "localhost" && host != "127.0.0.1" && host != "::1" {
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
