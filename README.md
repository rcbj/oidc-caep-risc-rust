# oidc-caep-risc-rust

A confidential OpenID Connect relying party for a traditional Rust application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`tokenEndpointAuthMethod` `"none"`) is refused. ID tokens are accepted only in `RS256` by default. The crate verifies `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`, `EdDSA` (Ed25519), and HMAC when the application names it; Shared Signals SETs are verified in every asymmetric algorithm of that list. DPoP (RFC 9449) is used whenever the provider offers it.

JSON configuration keys match the Python library `oidc-caep-risc`. `signals` omitted or `true` keeps CAEP and RISC on. `signals: false` does not start the receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the scope list after the default scopes are applied. `DEFAULT_SCOPES` still names those two scopes. The shipped demo leaves `signals` on (the key is omitted).

The license is MIT. A pull request merged into `main` publishes the crate to crates.io after the test workflow succeeds on that commit. A direct push does not. The token is the `CARGO_REGISTRY_TOKEN` repository secret. A release happens when the library's files changed since the last release's tag: `publish.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published.

## Usage

```rust
let rp = std::sync::Arc::new(oidc_caep_risc::RelyingParty::from_file("oidc.json")?);
let request = rp.authorize()?;
// redirect the browser to request.url; keep state, nonce, code_verifier and acr_values
let who = rp.complete_session(&query, &request, &my_session_id)?;
// later, for an API call: a valid access token (refreshed when under 30 seconds remain)
let access = rp.session_access_token(&my_session_id)?;
let claims = rp.userinfo(&access.access_token, &access.token_type, &who.subject)?;
// sign-out
rp.remove_session(&my_session_id);
```

Tokens stay in this process. Keep the transaction until the browser returns. `complete` does the same exchange without caching.

## Settings

The same camelCase keys work in a configuration file (`from_file`, `resolve_config`) and in an object handed to `RelyingParty::create`; both paths fill the same defaults and apply the same checks (`apply_defaults`).

| Key | Default | Meaning |
|---|---|---|
| `par` | `auto` | `auto` pushes when the provider has a PAR endpoint, and always when it sets `require_pushed_authorization_requests`. `always` fails at creation without an endpoint. `never` fails at creation when the provider requires PAR. |
| `dpop` | `auto` | `auto` uses DPoP when the provider lists `ES256` in `dpop_signing_alg_values_supported`. `always` fails at creation otherwise. `never` sends no proofs. |
| `dpopKey` | none | A P-256 private key in PEM (inline, `file:`, `env:`, or a path), for several processes sharing one DPoP key. Without it the key is generated at creation and held in memory only. |
| `idTokenSigningAlgs` | `["RS256"]` | The ID token algorithms accepted, intersected with what the provider advertises; creation fails when nothing is left. `none` is never accepted; `HS256`/`HS384`/`HS512` only when named here. |
| `idTokenSignedResponseAlg` | none | Pins one algorithm; the provider must advertise it. |
| `requireIdTokenTypAndAtHash` | `true` | The ID token header must carry `typ` `JWT` or `application/jwt` (any case), and an ID token issued with an access token must carry a matching `at_hash`. `false` checks each only when present. |
| `acrValues` | none | A string or a list. Sent as `acr_values`; the ID token from the code exchange must carry an `acr` that is one of them. `AuthorizeOptions::acr_values` replaces it per request. The refresh path does not re-check `acr`. |
| `clockToleranceSec` | `30` | Skew allowed on `exp`, `nbf` and `iat`. An `iat` further in the future is refused. |
| `maxIdTokenAgeSec` | `600` | The oldest `iat` accepted. |
| `sessionMaxEntries` | `10000` | The most sign-ins the default session store (`MemorySessionStore`) keeps. Past it, a new session drops the oldest-written one. A whole number, 1 or more. |
| `sessionTtlSec` | `86400` | How long the default store keeps a sign-in after it was last written (sign-in or refresh). `0`: until removed or evicted. An expired entry is never answered. |
| `redirectUri`, `postLogoutRedirectUri` | | https, or http on `localhost`, `127.0.0.1` or `[::1]`. `allowInsecure` does not relax this (it lets a development provider's own endpoints use http). A per-request `AuthorizeOptions::redirect_uri` is held to the same rule. |

## DPoP

With DPoP in use, the relying party sends `dpop_jkt` on the authorization request (in the PAR body when it pushes) and a proof (`typ` `dpop+jwt`, `jwk`, `jti`, `htm`, `htu` without query or fragment, `iat`) on every PAR and token request (code, refresh, client credentials). A token response must then say `token_type` `DPoP` (any case); without a proof it must say `Bearer`. Resource requests made with a DPoP-bound token (`userinfo`, every call `SignalsReceiver` makes when given `relying_party`, and `resource_headers` for the application's own calls) carry `Authorization: DPoP` and a proof with `ath`. A 400 `use_dpop_nonce` from the authorization server, or a 401 whose `WWW-Authenticate` says `DPoP error="use_dpop_nonce"`, is retried once with the `DPoP-Nonce` it gave; the latest nonce of each origin goes on the next proof.

## Session cache

`complete_session(query, txn, session_id)` keeps the sign-in under a session identifier the application chooses (empty makes one, returned as `Login::session_id`). `session_access_token(session_id)` returns the cached access token while it has more than 30 seconds left, and otherwise refreshes it (with a DPoP proof when DPoP is in use) and updates the cache; a failed refresh removes the entry and returns the refusal. `remove_session` clears an entry (sign-out). A `SignalsReceiver` built with `relying_party` removes the sessions a CAEP `session-revoked` (or any ending event) ends. The default store is `MemorySessionStore`, bounded by `sessionMaxEntries` and `sessionTtlSec` (`MemorySessionStore::new(max, ttl_sec)` builds one directly; `stats()` reports entries, bounds, and how many expired or were evicted; `purge_expired()` drops expired entries now, which a write also does when it needs room). An application that must never lose a live session to eviction keeps its own sessions below the bound and removes each one it ends. `set_session_store` takes any `SessionStore`, such as one shared by several processes.

## Shared Signals receiver health

`SignalsReceiver::health()` returns a `ReceiverHealth`: `running`, `stream_id`, `started_at`, `last_poll_at`, `last_success_at`, `last_error` and `last_error_at` (a failed `start` is recorded as `start: ...`), `consecutive_failures`, `polls`, `failed_polls`, `sets_accepted`, `sets_refused`, `sessions_ended`, `poll_interval_ms`, and the subject calls' counters (`subjects_added`, `subjects_removed`, `subject_refusals`, `subject_failures`, `last_subject_error`; see below). Times are seconds since the Unix epoch; nothing in it is a token, an event, or a subject. `is_healthy(max_age_sec)` is true while the receiver runs and a poll succeeded (or it started) within that many seconds. A receiver that fails every poll keeps backing off (four times the interval, at most 60 s) and says so here, so an application can fall back to another liveness check. `ReceiverOptions::on_error` receives each failed poll, refused SET, or panicking handler as one line (no token) instead of stderr. `stop()` wakes the poll thread at once and waits only for a transmitter call already in flight; the receiver polls on its one thread and spawns none per poll.

## Shared Signals subjects (Add Subject, Remove Subject)

A subscribing application should receive CAEP and RISC events only about people with an active session on it (iya-sts#2234: an application's stream carries events only about such subjects, and Add Subject is refused 403 for a subject without one). So the receiver tells the transmitter whom it follows (SSF 1.0 sections 8.1.3.2 and 8.1.3.3), which also makes it correct against a transmitter whose `default_subjects` is `NONE`. `SignalsReceiver::track` (a new local sign-in) calls the transmitter's `add_subject_endpoint` for the person, once per person: `{"stream_id", "subject", "verified": true}`, the subject in the form the receiver matches events on, `iss_sub` with the transmitter's issuer and the sign-in's `person`, else `email` (lowercased). `untrack` (a local sign-out) and a session ended by a received event call `remove_subject_endpoint` only when no other tracked sign-in of that person remains, and only for a subject the transmitter accepted. The calls are authorized as stream management is (with `relying_party`, its `ssf.manage` token and, when DPoP-bound, a proof). They are made inline and add no thread or timer: `track` and `untrack` on the caller's thread, an event-ended removal on the poll thread, each bounded by the 15 s HTTP timeout; sessions tracked before `start` are added when `start` has the stream. Nothing is retried, and a sign-in never fails because of a subject call: a refusal (a 403 is expected in a race, when the person's session at the transmitter ended first) or a failure goes to `on_error` (one line, no identifier of the person) and to `health()`: `subjects_added`, `subjects_removed`, `subject_refusals`, `subject_failures`, `last_subject_error`. The calls are skipped while the receiver is not running (with `signals: false` it never starts), when the transmitter publishes no such endpoint, and when switched off: `ReceiverOptions::add_subjects` (default `true`) or `ssf.addSubjects: false` in the relying party's configuration (`resolve_config` and `apply_defaults` refuse anything but a boolean). The demo tracks every sign-in at `/callback` and untracks at Sign out. A stream that names subjects carries only events about them, and the embedded PEP's `pep-policies-changed` is about the application, so a receiver whose relying party's PEP wants events also adds `{"format": "opaque", "id": <application>}` at `start` and never removes it (found live by wsfed-caep-rust: after the first sign-in the policy change came by poll, not by event).

## Async (feature `tokio`)

With `features = ["tokio"]`, every call that can reach the network has an `_async` twin: `RelyingParty::create_async`, `from_file_async`, `authorize_async`, `complete_async`, `complete_session_async`, `session_access_token_async`, `refresh_async`, `client_credentials_async`, `userinfo_async`, and `SignalsReceiver::start_async`, `stop_async`, `poll_once_async` (the methods take `self: &Arc<Self>`). They run the blocking call on tokio's blocking pool, so no runtime worker thread waits on the network. The HTTP client is still `ureq`: each call holds one blocking-pool thread for as long as it takes (at most the 15 s timeout per request), and dropping the future does not cancel the request. `session`, `remove_session` and `health` never touch the network and stay synchronous. `track` and `untrack` are synchronous too, but may make one Add or Remove Subject call; on a runtime, call them inside `spawn_blocking`.

## Embedded PEP (features `pep` and `local`)

Ask iya-sts's authorization policy whether a signed-in person may act on a resource, through the embedded Remote PEP (the shared [`iya-pep`](https://github.com/rcbj/iya-pep-rust) crate; iya-sts [#1206](https://github.com/rcbj/iya-sts/issues/1206)). **[docs/remote-pep.md](docs/remote-pep.md) is the full guide**: setting up iya-sts, choosing `central` or `local`, every configuration member, obligations, policy-change events, operating it and troubleshooting.

```toml
oidc-caep-risc = { version = "…", features = ["pep"] }    # central: AuthZEN at iya-sts
oidc-caep-risc = { version = "…", features = ["local"] }  # local too: decided in process
```

```json
"pep": { "name": "pep-orders", "mode": "local", "assertionKey": "pep-key.pem" }
```

```rust
match rp.decide_session(&session_id, &Access::new("read", "order", "42")) {
    Decision::Permit { obligations, .. } => { /* discharge them, then serve */ }
    Decision::Deny { .. } => { /* 403 */ }
    Decision::Unavailable { .. } => { /* 403: fail closed, never a Permit */ }
}
// or let the PEP choose: 200 for a Permit, 403 for a Deny and an Unavailable alike
let status = rp.decide_session(&session_id, &Access::new("read", "order", "42")).http_status();
```

The section is off unless present, and a build without the feature refuses it. A section without `mode` is `local`, so a build with `pep` alone must say `"mode": "central"`. Every PEP failure is `Unavailable` (no policy held, iya-sts unreachable or answering badly, a panic while deciding), and `Decision::http_status()` answers it 403. `central`'s Permit cache (`permitCacheMs`) is emptied by a failed evaluation or heartbeat. With `signals` on the PEP starts as `down`; the receiver reports its stream (`requested` or `excluded` at start and after each good poll, `down` after a failed poll and on `stop()`), and while the stream is not `requested` a `local` PEP polls at `pollIntervalMs`. The PEP's key must be its own, and only the claims the realm's AuthZEN catalogue declares are sent. The demo protects `GET /orders/<id>` with the PEP and answers with `http_status()`.

## Tests

```bash
docker build --target test .
```

The suite runs in a container, with every feature (`cargo test --all-features`), and checks the library also builds without them.

The tests build an in-process stub provider and a stub transmitter. They do not need a live iya-sts.

**AuthZEN, central against local (#46).** `src/tests/authzen_cases.json` is one table: catalogue rows (typed values, bags, dotted paths, short category and datatype names), policies in ALFA with the XACML iya-sts stored for them, and 54 cases, each a sign-in's claims, an `Access` and the answer the host must see (Permit with its obligations, Deny, or Unavailable). `src/authzen_test.rs` runs it twice through `RelyingParty::decide` and `decide_session`. In `cargo test`, a `local` PEP per application against a stub PDP that serves the table must give every expected answer. `python3 scripts/live_iya_sts.py --authzen` (or `LIVE_AUTHZEN=1`; `scripts/live_authzen.py`) starts a fresh iya-sts (`IYA_STS_IMAGE` built from #2026–#2028; `LIVE_STS_PORT` defaults to 18526), provisions two applications (`authzen-docs`, decided by the realm root, and `authzen-ledger`, which enforces fine-grained authorization), the table's users, catalogue and policies, and a `central` and a `local` PEP per application, each with its own P-256 key (0600, never printed) certified and bound by `issue-pep-credential`. Then it runs the ignored test `authzen_test::live_central_equals_local` in `rust:1-bookworm` on the host network (`-v iya-pep-cargo:/cargo`), which fails once, listing every case where central and local differ or either differs from the table. The last JSON it prints has `cases`, `centralEqualsLocal`, `asExpected`, the `mismatches` and `xacmlDriftFromTable`. `AUTHZEN_XACML_OUT=<file>` saves the XACML iya-sts stored, for the table. A case marked `knownLocalDefect` must still be wrong in the offline run; the live run ignores the mark. Its first runs against #2026–#2028 failed 5 of 54 cases, all on `authzen-ledger`: iya-sts's `central` evaluation of an application's own policy resolved no `PolicyIdReference` (500, so `Unavailable`; 4 cases), and iya-pep's `local` mapping lacked the `urn:sts:xacml:fga:stage` fact (1 case). Both are fixed (iya-sts feature/2027 2983a43d0, iya-pep 3f145ef), and on 2026-11-24 the live run was 54 of 54, central == local == expected. No case is marked `knownLocalDefect` now.

`python3 scripts/live_iya_sts.py` is the live half. It starts iya-sts when `IYA_STS_URL` is unset, copies this checkout (without `demo/generated`) to a scratch build context, runs the install script there (which writes the client secret and the trust chain), then builds the demo image, checks the image carries that chain and nothing else of `demo/generated`, runs the demo with only the client secret mounted and `TLS_CA_REFRESH=0`, signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. `--pep` (or `LIVE_PEP=1`) adds the embedded PEP (#46) and needs an iya-sts with #2026–#2028 (the nightly does not pass it until they reach `main`; point `IYA_STS_IMAGE` at an image built from them). It sets the PEP up the way a user does, by running the install script with `--pep central` (see *The demo with its embedded PEP*), and makes a copy of the configuration that says `local`. The demo runs with a `central` `pep` section, mounting only the client secret and the PEP's key: `GET /orders/42` must be 200 and `POST /orders/42` 403. Then again with `OIDC_CONFIG` naming the image's `demo/oidc.pep-local.json` (`local`): the same two, then the application's own policy moves to one that denies `read`, and within `PEP_FLIP_TIMEOUT` seconds (30) the GET must be 403 with `pep-policies-changed` received (the fallback poll stays at its 300 s default, so `via` is `event`). The result's `pep` object holds each check, and `/live-status` carries the PEP's `status()` under `pep`. `LIVE_KEEP=1` leaves both containers running after the run for a post-mortem. It never binds port 3000 or 8081. The nightly workflow runs the unit suite and this script. `.github/workflows/nightly.yml` runs at 07:02 UTC (`2 7 * * *`) and on `workflow_dispatch`. `IYA_STS_IMAGE` starts a fresh container from an image already built; without it or `IYA_STS_URL` the script clones and builds iya-sts `main`. `LIVE_STS_PORT` defaults to 18516 and `LIVE_DEMO_PORT` to 18616; the script refuses 3000, 8081, and 18481 through 18495. Registration runs `scripts/configure_iya_sts.py` with the host's stdlib python3, never Cargo. The live script always starts a fresh iya-sts. The install script may be run again against the same one, as long as the client secret file it wrote is still there: it adds the demo's values to the existing client (a single-valued attribute `add` refuses, such as `oauthIdTokenSignedResponseAlg`, is `set` instead; until then a second run stopped there) and, with `--pep`, keeps the PEP's account and key, and the policy once the application enforces one. No script prints a password or secret, or a path or plan derived from one (the dry run shows `<client secret>`): the client secret and a generated test-user password (`demo/generated/<user>.password`) are files created 0600, and only the password file's path is printed. Every `ssl` context in `scripts/` sets TLS 1.2 as the minimum.

## Credentials

Every credential the library, the demo and the install script use, who makes it, where it lives and what it proves. No value of any of them is ever printed, logged, put in an image or written into this repository: the files below are created 0600 under `demo/generated/`, which `.gitignore` excludes and `.dockerignore` keeps out of the image (only `demo/generated/idp-ca.pem`, a public trust chain, goes in).

### The application's own credentials

The relying party is the confidential OAuth client `oidc-caep-risc-demo` (`clientId`, or `client_id`, in `demo/oidc.json`). These credentials are the application's, used for signing people in and for its Shared Signals stream.

| Credential | Type / algorithm | Made or issued by | Where it lives | Used for | How iya-sts learns of it | Rotation |
|---|---|---|---|---|---|---|
| Client ID | a name, not a secret | the install script registers it (`applications/create`) | `clientId` in `demo/oidc.json` | naming the client at the authorization and token endpoints | the registration | — |
| Client secret | a random string (`secrets.token_urlsafe(32)`), sent as `client_secret_basic` (default) or `client_secret_post` (`tokenEndpointAuthMethod`) | the install script, on the run that creates the application | `clientSecret: "file:generated/client-secret"`, i.e. `demo/generated/client-secret`, 0600 (also accepted: `env:NAME`, or the value itself) | authenticating the client at the token endpoint: the code exchange, refresh, and the client-credentials grant below | sent once, as `oauthClientSecret` in the create call | the script never rotates it: a re-run keeps the file, and refuses when the application exists but the file is gone. Set a new secret on the application in iya-sts, put it in the file, restart the demo |
| `private_key_jwt` key (optional) | a private key in PEM; the assertion is signed with `privateKeyAlg` (default `RS256`), `iss` = `sub` = the client ID, `aud` = the endpoint, a fresh `jti`, 60 s lifetime | you | `privateKey` (inline PEM, `file:`, `env:`, or a path), with `tokenEndpointAuthMethod: "private_key_jwt"` | client authentication instead of the secret | not by the install script: register the public key on the application yourself | make a new key, register its public half, replace the file, restart |
| DPoP key | ES256 (P-256) | generated in memory when the relying party is created, or yours in `dpopKey` (inline PEM, `file:`, `env:`, or a path) | memory only, or wherever `dpopKey` points (shared by several processes) | binding every token the client gets (RFC 9449): proofs on PAR and token requests, `dpop_jkt` on the authorization request, and `Authorization: DPoP` with a proof on UserInfo and transmitter calls. `dpop`: `auto` (when the provider lists ES256), `always`, `never` | its public key travels in each proof; the token is bound to its thumbprint | the generated key is new at every start; for `dpopKey`, replace the key and restart. Tokens bound to the old key are no longer usable |
| The Shared Signals token | an access token from the client-credentials grant, scope `ssf.manage`, DPoP-bound when DPoP is on | iya-sts, to the client authenticated as above | memory only | every call `SignalsReceiver` makes when built with `relying_party`: discovery, the stream, polls, verification, Add and Remove Subject | the install script registers the `client_credentials` grant and gives the application the `SSF_READ` and `SSF_MANAGE` roles that authorize `ssf.read` and `ssf.manage` | asked for again when it expires |
| The test user's password | a password | `OIDC_DEMO_USER_PASSWORD` when set, else generated by iya-sts (`credential: "generate"`) | `demo/generated/<user>.password` (default `oidc-demo-user.password`), 0600; only its path is printed | signing the test user in to try the demo | set at `users/create` (or `users/set-password` when the user exists and `OIDC_DEMO_USER_PASSWORD` is set) | set `OIDC_DEMO_USER_PASSWORD` and re-run the script, or change it in iya-sts |

People's sessions are not credentials of the application: their tokens stay in the relying party's session cache, in memory, and the demo's pages show a fingerprint and the decoded claims, never a value.

### The embedded PEP's credentials

The PEP (`pep` section; features `pep` and `local`) is a separate identity at iya-sts: it never signs in as the application or as a person. [docs/remote-pep.md](docs/remote-pep.md#credentials) has the detail.

| Credential | Type / algorithm | Made or issued by | Where it lives | Used for | How iya-sts learns of it | Rotation |
|---|---|---|---|---|---|---|
| The service account | an account with no password (`credential: "none"`, `serviceAccount: true`) in the `remote-peps` group | the install script (`--pep`; name `pep-oidc-demo`, `--pep-name`) | iya-sts's directory; `pep.name` in the configuration | the identity the PEP's tokens are issued to | `users/create` and `groups/add-member` | — |
| The PEP's key | EC P-256 (ES256) | made locally with the host's `openssl`; only a certificate request leaves the machine | `pep.assertionKey: "demo/generated/pep-key.pem"`, 0600, never printed, never in the image (Compose mounts it) | an RFC 7523 assertion (`iss` = `sub` = the account, 120 s) for a DPoP-bound access token as the remote-PEP client (`sts-remote-pep`, `pep.clientId`), and every DPoP proof made with that token: registration, heartbeat, the catalogue and policy pulls and the PIP (`xacml:pep`), the decision records (`xacml:pep-audit`), and AuthZEN evaluations in `central` (`authzen:evaluate`) | `issue-pep-credential` certifies the key from its request and binds the PEP to the demo's application | make a new key and certify it (`revokePrevious: true` retires the old one); the PEP reads a changed file again. With the install script: delete the key file and re-run it |

`RelyingParty::create` refuses a PEP key that is the `private_key_jwt` key or the DPoP key (by JWK thumbprint). One key per identity: if the PEP's key were the application's, whoever held the one would hold the other, iya-sts could not tell the PEP's calls from the application's, and a key rotated for one would break the other.

### Install-time only

| Credential | Where it comes from | Used for | Kept? |
|---|---|---|---|
| The management client secret | `ADMIN_API_CLIENT_SECRET` (or `STS_ADMIN_API_CLIENT_SECRET`) in the environment of `scripts/configure_iya_sts.py`; it is iya-sts's `adminApi.clientSecret`, the secret of the seeded `sts-api-client` | a client-credentials token as `sts-api-client` (HTTP Basic), scope `admin:read admin:write`, resource `<realm>/admin-api`, for every `/admin-api` call the script makes | never: not written to a file, not printed, not in the plan `--dry-run` shows |

The demo never sees it. The live scripts pass it to the containers they start as `-e NAME`.

### Trust material

- **`tlsCa`** (`generated/idp-ca.pem`, relative to `demo/`) is iya-sts's TLS listener chain (leaf, TLS Issuing CA, Intermediate, Root), saved by the install script (`scripts/trust_chain.py`) from `GET /tls/server-certificate`, or the handshake's chain. The fetch itself is not verified (trust on first use): compare the anchor's SHA-256 the script prints with the Root CA on iya-sts's Server configuration, PKI page. It is public, and the only file of `demo/generated` the image carries.
- **What it verifies:** the library's TLS connections to iya-sts (discovery, token, UserInfo, JWKS, PAR, and the Shared Signals transmitter), with the host name checked against the leaf; the PEP's connections too, unless its section names its own `tlsCa`. The install script uses the same chain for its own `/admin-api` calls once it has saved it.
- **Signatures:** ID tokens are verified against the provider's JWKS (`jwks_uri`, fetched over that TLS), in the algorithms `idTokenSigningAlgs` allows; Shared Signals SETs against the transmitter's JWKS. The PEP's pulls arrive over TLS on its own DPoP-bound token.

### Development and product iya-sts

What changes for these credentials with iya-sts's mode (its `docs/v1.2.0/configuration.md` and `remote-pep.md`):
- **The listener's Root.** In development mode iya-sts's listener certificate chains to a service Root regenerated on every start, so `tlsCa` goes stale at each iya-sts restart: run the install script (or `python3 scripts/trust_chain.py --config demo/oidc.json`) again and rebuild the image. `demo/entrypoint.sh` refreshes it at start unless `TLS_CA_REFRESH=0`.
- **The management client secret.** Unless `adminApi.clientSecret` is set before iya-sts starts, the seeded `sts-api-client`'s secret is minted at every start and cannot be read back; in product mode that setting is the way into `/admin-api`. The live scripts set it on the container they start.
- **`remote-peps`.** Development mode seeds the group with a member, `cn=remote-pep-1`; product mode seeds it empty and does not create that account. The install script makes and adds the demo's own account either way.
- **The test user.** Product mode requires a second factor of everybody unless `authn.allowOptionalSecondFactor` is on, so the test user is asked to enrol one at its first sign-in. The test user and its password file are for trying the demo, not for a deployment.

## iya-sts trust chain (`tlsCa`)

`tlsCa` names iya-sts's TLS listener CA trust chain; in `demo/oidc.json` it is `generated/idp-ca.pem` (relative to `demo/`). The library adds every certificate in that file as a trust anchor of its TLS connector, so the whole chain works and the path ends at the Root. It also verifies the host name against the leaf's subjectAltName (a DNS name, or an IP literal such as `127.0.0.1`). It reads the file for discovery, the token, UserInfo and JWKS requests, and the Shared Signals receiver.

`scripts/configure_iya_sts.py` writes it on every run (through `scripts/trust_chain.py`'s `save_trust_chain()`): the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain the TLS handshake presents when that endpoint is missing. It prints the path, the trust anchor's subject, and its SHA-256; compare the anchor with the Root CA on iya-sts's Server configuration, PKI page. The fetch itself is not verified (trust on first use). `python3 scripts/trust_chain.py --config demo/oidc.json` refreshes only the chain.

The demo image build copies that file in: `.dockerignore` admits only `demo/generated/idp-ca.pem` from `demo/generated/` (the client secret stays out), and `COPY demo demo`, after `cargo build`, puts it at `/app/demo/generated/idp-ca.pem`, where `tlsCa` names it. A build with no chain file yet (a fresh clone, CI) still succeeds and carries none. Run the install script, then build the image; after running it against a different iya-sts, rebuild (`docker compose up --build`). The entrypoint still refreshes the chain from the provider at start unless `TLS_CA_REFRESH=0`, and Compose also mounts `demo/generated`, which holds the same file.

## Layout

| Path | What it is |
|---|---|
| `src` | The library, crate `oidc-caep-risc`. |
| `src/suite.rs` | `cargo test` ports of the Python relying-party and Shared Signals tests. |
| `src/profile_test.rs` | DPoP, acr, PAR required, the ID token algorithms, typ and at_hash, creation defaults, and the session cache. |
| `demo` | `demo/main.rs`. Config is `demo/oidc.json`. |
| `scripts/configure_iya_sts.py` | Registers the confidential client on iya-sts and saves its listener CA trust chain where `tlsCa` names it. Loopback redirects follow the running container's `PORT`, then the shell `PORT`. `--pep central\|local` also sets up the embedded PEP and writes its `pep` section. |
| `scripts/trust_chain.py` | Saves iya-sts's listener CA trust chain. |
| `src/trust_chain_test.rs` | The trust chain tests. |
| `src/authzen_test.rs`, `src/tests/authzen_cases.json` | The AuthZEN case table, its offline `local` run, and the live central-against-local run. |
| `scripts/live_authzen.py` | `live_iya_sts.py --authzen`: provisions iya-sts for the table and runs the live test. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

## Demo

`PORT` defaults to 3000. A loopback redirect and post-logout URL follow `PORT`. Any other host is left as written. An explicit `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL.

```sh
docker compose up --build
```

### The demo with its embedded PEP

One command sets iya-sts up for the demo's PEP and writes its `pep` section (iya-sts with #2026–#2028; `ADMIN_API_CLIENT_SECRET` set as for the plain install):

```sh
python3 scripts/configure_iya_sts.py --pep local     # a bare --pep is local; or --pep central
docker compose up --build
```

`--pep` does `docs/remote-pep.md`'s steps 2 to 6 through `/admin-api`: the service account `pep-oidc-demo` (`--pep-name`) in `remote-peps`; a P-256 key made with the host's `openssl` in `demo/generated/pep-key.pem` (0600, never printed; `.dockerignore` keeps it out of the image and Compose mounts it); the key certified from its own request and the PEP bound to the demo's application; the catalogue row `subject.acr` → `urn:example:acr`; and the demo application's own policy, which it then enforces (fine-grained authorization), permitting `read` on an `order` when the sign-in carried an `acr` and denying everything else. Nothing realm-wide changes but the catalogue row: the realm's root policy is untouched. It writes `"pep": {"name", "mode", "assertionKey": "demo/generated/pep-key.pem"}` into `demo/oidc.json`, keeping any other member of an existing section. Run it again to switch modes: the account and the key are kept and the binding is set again; the policy is written only while the application does not yet enforce one, so an administrator's edits survive (and so does an older version of the script's own policy). `--dry-run` lists every call. The image copies `demo/oidc.json` in at build time, so rebuild after the script writes the section. Signed in, `GET /orders/42` is 200 and `POST /orders/42` 403, each the decision's `http_status()`; `GET /live-status` carries the PEP's `status()` under `pep`.

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` starts `authorize` and redirects. `GET /callback` completes the code exchange. `POST /logout` signs the local session out. `GET /live-status` is JSON for the sign-in and the Shared Signals events this process has accepted, and the PEP's `status()` under `pep` when there is one. It does not include tokens. `GET /orders/<id>` (any method; built with `pep`) is decided by the PEP: 401 without a sign-in, otherwise `http_status()` (200 on a Permit, 403 on a Deny, on `Unavailable`, and with no relying party).

`docker-compose.yml` sets `network_mode: host`. The image sets `ENV PORT=3000`. The health check calls `http://127.0.0.1:${PORT}/healthz`. The running container's `PORT` wins over the shell's when `scripts/configure_iya_sts.py` registers the application.

The demo keeps each sign-in in the relying party's session cache under its session cookie's id, shows whether that session's access token is valid (and whether it is DPoP-bound) on `/`, clears the entry on sign-out and on a session-revoked event, and builds its Shared Signals receiver with `relying_party`, so every transmitter call carries the client-credentials token and, when DPoP is in use, a proof. `scripts/configure_iya_sts.py` registers the client with `id_token_signed_response_alg` `RS256` (iya-sts's `oauthIdTokenSignedResponseAlg`).

Demo JSON uses `file:` and the configuration's own placeholders. It does not contain a generated secret or key.
