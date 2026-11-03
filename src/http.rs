// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::io::Read;
use std::time::Duration;

use crate::error::OidcError;

pub const MAX_BODY: usize = 2_000_000;

pub struct Answer {
    pub status: u16,
    pub content_type: String,
    pub body: String,
    /// The `DPoP-Nonce` response header, or empty.
    pub dpop_nonce: String,
    /// The `WWW-Authenticate` response header, or empty.
    pub www_authenticate: String,
}

/// Back-channel HTTP. Redirects are not followed. The process proxy environment is ignored.
pub fn send(raw_url: &str, method: &str, headers: &[(String, String)], body: Option<&str>, ca: Option<&str>, code: &str) -> Result<Answer, OidcError> {
    let parts = url::Url::parse(raw_url).map_err(|_| OidcError::new(code, format!("{raw_url} is not an http(s) URL")))?;
    if parts.scheme() != "http" && parts.scheme() != "https" || parts.host_str().is_none() {
        return Err(OidcError::new(code, format!("{raw_url} is not an http(s) URL")));
    }
    let agent = agent(ca, code)?;
    let mut req = agent.request(method, raw_url);
    for (key, value) in headers {
        req = req.set(key, value);
    }
    let result = if let Some(text) = body {
        req.send_string(text)
    } else if method.eq_ignore_ascii_case("POST") || method.eq_ignore_ascii_case("PUT") {
        req.send_string("")
    } else {
        req.call()
    };
    let response = match result {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(ureq::Error::Transport(err)) => {
            let text = err.to_string();
            if text.to_ascii_lowercase().contains("timed out") || text.to_ascii_lowercase().contains("timeout") {
                return Err(OidcError::new(code, format!("{raw_url} did not answer within 15 s")));
            }
            return Err(OidcError::new(code, format!("{raw_url}: {text}")));
        }
    };
    let status = response.status();
    let content_type = response.header("content-type").unwrap_or("").to_string();
    let dpop_nonce = response.header("dpop-nonce").unwrap_or("").to_string();
    let www_authenticate = response.all("www-authenticate").join(", ");
    let mut buf = Vec::new();
    let mut reader = response.into_reader().take(MAX_BODY as u64 + 1);
    reader.read_to_end(&mut buf).map_err(|err| OidcError::new(code, format!("{raw_url}: {err}")))?;
    if buf.len() > MAX_BODY {
        return Err(OidcError::new(code, format!("{raw_url} answered more than {MAX_BODY} bytes")));
    }
    let body = String::from_utf8_lossy(&buf).into_owned();
    Ok(Answer { status, content_type, body, dpop_nonce, www_authenticate })
}

fn agent(ca: Option<&str>, code: &str) -> Result<ureq::Agent, OidcError> {
    let mut builder = ureq::AgentBuilder::new().timeout(Duration::from_secs(15)).redirects(0).try_proxy_from_env(false);
    if let Some(pem) = ca.filter(|text| !text.is_empty()) {
        let mut tls = native_tls::TlsConnector::builder();
        let mut found = false;
        for block in pem.split("-----END CERTIFICATE-----") {
            let trimmed = block.trim();
            if !trimmed.contains("BEGIN CERTIFICATE") {
                continue;
            }
            let one = format!("{trimmed}\n-----END CERTIFICATE-----\n");
            let cert = native_tls::Certificate::from_pem(one.as_bytes()).map_err(|_| OidcError::new(code, "the configured tlsCa is not a PEM trust anchor"))?;
            tls.add_root_certificate(cert);
            found = true;
        }
        if !found {
            return Err(OidcError::new(code, "the configured tlsCa is not a PEM trust anchor"));
        }
        let connector = tls.build().map_err(|err| OidcError::new(code, format!("the configured tlsCa is not a PEM trust anchor: {err}")))?;
        builder = builder.tls_connector(std::sync::Arc::new(connector));
    }
    Ok(builder.build())
}
