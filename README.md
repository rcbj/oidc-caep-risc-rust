# oidc-caep-risc-rust

A confidential OpenID Connect relying party for a traditional Rust application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`tokenEndpointAuthMethod` `"none"`) is refused. ID tokens are accepted only in `RS256` by default. The crate verifies `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`, `EdDSA` (Ed25519), and HMAC when the application names it; Shared Signals SETs are verified in every asymmetric algorithm of that list. DPoP (RFC 9449) is used whenever the provider offers it.

JSON configuration keys match the Python library `oidc-caep-risc`. `signals` omitted or `true` keeps CAEP and RISC on. `signals: false` does not start the receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the scope list after the default scopes are applied. `DEFAULT_SCOPES` still names those two scopes. The shipped demo leaves `signals` on (the key is omitted).

The license is MIT. A pull request merged into `main` publishes the crate to crates.io after the test workflow succeeds on that commit. A direct push does not. The token is the `CARGO_REGISTRY_TOKEN` repository secret. A version already on crates.io stays there; the next release is a new `version` in `Cargo.toml`.

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
| `redirectUri`, `postLogoutRedirectUri` | | https, or http on `localhost`, `127.0.0.1` or `[::1]`. `allowInsecure` does not relax this (it lets a development provider's own endpoints use http). A per-request `AuthorizeOptions::redirect_uri` is held to the same rule. |

## DPoP

With DPoP in use, the relying party sends `dpop_jkt` on the authorization request (in the PAR body when it pushes) and a proof (`typ` `dpop+jwt`, `jwk`, `jti`, `htm`, `htu` without query or fragment, `iat`) on every PAR and token request (code, refresh, client credentials). A token response must then say `token_type` `DPoP` (any case); without a proof it must say `Bearer`. Resource requests made with a DPoP-bound token (`userinfo`, every call `SignalsReceiver` makes when given `relying_party`, and `resource_headers` for the application's own calls) carry `Authorization: DPoP` and a proof with `ath`. A 400 `use_dpop_nonce` from the authorization server, or a 401 whose `WWW-Authenticate` says `DPoP error="use_dpop_nonce"`, is retried once with the `DPoP-Nonce` it gave; the latest nonce of each origin goes on the next proof.

## Session cache

`complete_session(query, txn, session_id)` keeps the sign-in under a session identifier the application chooses (empty makes one, returned as `Login::session_id`). `session_access_token(session_id)` returns the cached access token while it has more than 30 seconds left, and otherwise refreshes it (with a DPoP proof when DPoP is in use) and updates the cache; a failed refresh removes the entry and returns the refusal. `remove_session` clears an entry (sign-out). A `SignalsReceiver` built with `relying_party` removes the sessions a CAEP `session-revoked` (or any ending event) ends. The default store is `MemorySessionStore`; `set_session_store` takes any `SessionStore`, such as one shared by several processes.

## Tests

```bash
docker build --target test .
```

The suite runs in a container.

The tests build an in-process stub provider and a stub transmitter. They do not need a live iya-sts.

`python3 scripts/live_iya_sts.py` is the live half. It starts iya-sts when `IYA_STS_URL` is unset, copies this checkout (without `demo/generated`) to a scratch build context, runs the install script there (which writes the client secret and the trust chain), then builds the demo image, checks the image carries that chain and nothing else of `demo/generated`, runs the demo with only the client secret mounted and `TLS_CA_REFRESH=0`, signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. It never binds port 3000 or 8081. The nightly workflow runs the unit suite and this script. `.github/workflows/nightly.yml` runs at 07:02 UTC (`2 7 * * *`) and on `workflow_dispatch`. `IYA_STS_IMAGE` starts a fresh container from an image already built; without it or `IYA_STS_URL` the script clones and builds iya-sts `main`. `LIVE_STS_PORT` defaults to 18516 and `LIVE_DEMO_PORT` to 18616; the script refuses 3000, 8081, and 18481 through 18495. Registration runs `scripts/configure_iya_sts.py` with the host's stdlib python3, never Cargo. Always use a fresh iya-sts: a second registration of the same client fails. No script prints a password or secret, or a path or plan derived from one (the dry run shows `<client secret>`): the client secret and a generated test-user password (`demo/generated/<user>.password`) are files created 0600, and only the password file's path is printed. Every `ssl` context in `scripts/` sets TLS 1.2 as the minimum.

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
| `scripts/configure_iya_sts.py` | Registers the confidential client on iya-sts and saves its listener CA trust chain where `tlsCa` names it. Loopback redirects follow the running container's `PORT`, then the shell `PORT`. |
| `scripts/trust_chain.py` | Saves iya-sts's listener CA trust chain. |
| `src/trust_chain_test.rs` | The trust chain tests. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

## Demo

`PORT` defaults to 3000. A loopback redirect and post-logout URL follow `PORT`. Any other host is left as written. An explicit `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL.

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` starts `authorize` and redirects. `GET /callback` completes the code exchange. `POST /logout` signs the local session out. `GET /live-status` is JSON for the sign-in and the Shared Signals events this process has accepted. It does not include tokens.

`docker-compose.yml` sets `network_mode: host`. The image sets `ENV PORT=3000`. The health check calls `http://127.0.0.1:${PORT}/healthz`. The running container's `PORT` wins over the shell's when `scripts/configure_iya_sts.py` registers the application.

The demo keeps each sign-in in the relying party's session cache under its session cookie's id, shows whether that session's access token is valid (and whether it is DPoP-bound) on `/`, clears the entry on sign-out and on a session-revoked event, and builds its Shared Signals receiver with `relying_party`, so every transmitter call carries the client-credentials token and, when DPoP is in use, a proof. `scripts/configure_iya_sts.py` registers the client with `id_token_signed_response_alg` `RS256` (iya-sts's `oauthIdTokenSignedResponseAlg`).

Demo JSON uses `file:` and the configuration's own placeholders. It does not contain a generated secret or key.
