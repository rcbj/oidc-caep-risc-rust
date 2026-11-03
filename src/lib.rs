// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

mod b64;
mod config;
mod discovery;
mod dpop;
mod error;
mod http;
mod idtoken;
mod keys;
mod pkce;
mod rp;
mod ssf;
mod value;

pub use b64::{b64url_decode, b64url_encode};
pub use config::{apply_defaults, check_redirect, is_loopback, read_config_file, resolve_config, Resolved};
pub use discovery::DEFAULT_SCOPES;
pub use dpop::{Dpop, DPOP_ALG};
pub use error::OidcError;
pub use idtoken::{hash_claim, validate_id_token};
pub use pkce::{code_challenge_s256, random_token};
pub use rp::{Access, AuthorizeOptions, EndSessionOptions, Login, MemorySessionStore, RelyingParty, SessionStore, Transaction, SESSION_REFRESH_MARGIN_SEC};
pub use ssf::{subject_of, verify_compact_jws, Event, ReceiverOptions, SignalEvent, SignalsReceiver};
pub use value::JsonMap;

#[cfg(test)]
mod profile_test;
#[cfg(test)]
mod suite;
#[cfg(test)]
mod trust_chain_test;
