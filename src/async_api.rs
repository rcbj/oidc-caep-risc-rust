// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The async API (cargo feature `tokio`), for an application on a tokio runtime.
//!
//! Every call that may reach the network — discovery, the pushed authorization
//! request, the token endpoint, the JWKS, UserInfo, the transmitter — runs on
//! tokio's blocking pool (`spawn_blocking`), never on a runtime worker thread, so a
//! slow provider stalls no other task. The HTTP client underneath is still `ureq`:
//! each call holds one blocking-pool thread for its duration (at most the 15 s HTTP
//! timeout per request), and dropping the future does not cancel the request, which
//! runs to completion and is then discarded. Calls that never touch the network
//! (`session`, `remove_session`, `health`, `track`, `untrack`) stay synchronous;
//! they take a mutex for a map operation and are safe to call from async code.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::OidcError;
use crate::rp::{Access, AuthorizeOptions, Login, RelyingParty, Transaction};
use crate::ssf::SignalsReceiver;
use crate::value::JsonMap;

async fn blocking<T, F>(work: F) -> Result<T, OidcError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, OidcError> + Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result,
        Err(err) => Err(OidcError::new("protocol", format!("the blocking call did not complete: {err}"))),
    }
}

impl RelyingParty {
    /// `create`, off the runtime's threads (discovery is a network call).
    pub async fn create_async(config: JsonMap) -> Result<Self, OidcError> {
        blocking(move || RelyingParty::create(config)).await
    }

    /// `from_file`, off the runtime's threads.
    pub async fn from_file_async(path: String) -> Result<Self, OidcError> {
        blocking(move || RelyingParty::from_file(&path)).await
    }

    /// `authorize_options` (a pushed authorization request is a network call).
    pub async fn authorize_async(self: &Arc<Self>, opts: AuthorizeOptions) -> Result<Transaction, OidcError> {
        let rp = Arc::clone(self);
        blocking(move || rp.authorize_options(opts)).await
    }

    /// `complete`: the code redeemed and the ID token verified.
    pub async fn complete_async(self: &Arc<Self>, query: HashMap<String, String>, txn: Transaction) -> Result<Login, OidcError> {
        let rp = Arc::clone(self);
        blocking(move || rp.complete(&query, &txn)).await
    }

    /// `complete_session`: `complete`, and the sign-in kept under `session_id`.
    pub async fn complete_session_async(self: &Arc<Self>, query: HashMap<String, String>, txn: Transaction, session_id: String) -> Result<Login, OidcError> {
        let rp = Arc::clone(self);
        blocking(move || rp.complete_session(&query, &txn, &session_id)).await
    }

    /// `session_access_token`: the cached token, or a refresh.
    pub async fn session_access_token_async(self: &Arc<Self>, session_id: String) -> Result<Access, OidcError> {
        let rp = Arc::clone(self);
        blocking(move || rp.session_access_token(&session_id)).await
    }

    /// `refresh`.
    pub async fn refresh_async(self: &Arc<Self>, refresh_token: String, scope: String, previous: Option<Login>) -> Result<Login, OidcError> {
        let rp = Arc::clone(self);
        blocking(move || rp.refresh(&refresh_token, &scope, previous.as_ref())).await
    }

    /// `client_credentials`.
    pub async fn client_credentials_async(self: &Arc<Self>, scope: String) -> Result<Access, OidcError> {
        let rp = Arc::clone(self);
        blocking(move || rp.client_credentials(&scope)).await
    }

    /// `userinfo`.
    pub async fn userinfo_async(self: &Arc<Self>, access_token: String, token_type: String, expected_sub: String) -> Result<JsonMap, OidcError> {
        let rp = Arc::clone(self);
        blocking(move || rp.userinfo(&access_token, &token_type, &expected_sub)).await
    }
}

impl SignalsReceiver {
    /// `start`: discovery, the keys and the stream, then polling on its own thread.
    pub async fn start_async(self: &Arc<Self>) -> Result<(), OidcError> {
        let receiver = Arc::clone(self);
        blocking(move || receiver.start()).await
    }

    /// `stop`, waiting for a transmitter call in flight off the runtime's threads.
    pub async fn stop_async(self: &Arc<Self>) {
        let receiver = Arc::clone(self);
        let _ = blocking(move || {
            receiver.stop();
            Ok(())
        })
        .await;
    }

    /// `poll_once`.
    pub async fn poll_once_async(self: &Arc<Self>) -> Result<bool, OidcError> {
        let receiver = Arc::clone(self);
        blocking(move || receiver.poll_once()).await
    }
}
