# oidc-caep-risc-rust

A confidential OpenID Connect relying party for a traditional Rust application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`tokenEndpointAuthMethod` `"none"`) is refused. The crate signs and verifies RSA (`RS256`, `RS384`, `RS512`) and HMAC ID tokens. PSS, ECDSA, and EdDSA are named where a provider advertises them and are not implemented in this crate.

JSON configuration keys match the Python library `oidc-caep-risc`. `signals` omitted or `true` keeps CAEP and RISC on. `signals: false` does not start the receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the scope list after the default scopes are applied. `DEFAULT_SCOPES` still names those two scopes. The shipped demo leaves `signals` on (the key is omitted).

The license is MIT. A pull request merged into `main` publishes the crate to crates.io after the test workflow succeeds on that commit. A direct push does not. The token is the `CARGO_REGISTRY_TOKEN` repository secret. A version already on crates.io stays there; the next release is a new `version` in `Cargo.toml`.

## Usage

```rust
let rp = oidc_caep_risc::RelyingParty::from_file("oidc.json")?;
let request = rp.authorize()?;
// redirect the browser to request.url; keep state, nonce, and code_verifier
let who = rp.complete(&query, &request)?;
```

Tokens stay in this process. Keep the transaction until the browser returns.

## Tests

```bash
docker build --target test .
```

The suite runs in a container.

The tests build an in-process stub provider and a stub transmitter. They do not need a live iya-sts.

`python3 scripts/live_iya_sts.py` is the live half. It starts iya-sts when `IYA_STS_URL` is unset, copies this checkout (without `demo/generated`) to a scratch build context, runs the install script there (which writes the client secret and the trust chain), then builds the demo image, checks the image carries that chain and nothing else of `demo/generated`, runs the demo with only the client secret mounted and `TLS_CA_REFRESH=0`, signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. It never binds port 3000 or 8081. The nightly workflow runs the unit suite and this script. `.github/workflows/nightly.yml` runs at 07:02 UTC (`2 7 * * *`) and on `workflow_dispatch`. `IYA_STS_IMAGE` starts a fresh container from an image already built; without it or `IYA_STS_URL` the script clones and builds iya-sts `main`. `LIVE_STS_PORT` defaults to 18516 and `LIVE_DEMO_PORT` to 18616; the script refuses 3000, 8081, and 18481 through 18495. Registration runs `scripts/configure_iya_sts.py` with the host's stdlib python3, never Cargo. Always use a fresh iya-sts: a second registration of the same client fails.

## iya-sts trust chain (`tlsCa`)

`tlsCa` names iya-sts's TLS listener CA trust chain; in `demo/oidc.json` it is `generated/idp-ca.pem` (relative to `demo/`). The library adds every certificate in that file as a trust anchor of its TLS connector, so the whole chain works and the path ends at the Root. It also verifies the host name against the leaf's subjectAltName (a DNS name, or an IP literal such as `127.0.0.1`). It reads the file for discovery, the token, UserInfo and JWKS requests, and the Shared Signals receiver.

`scripts/configure_iya_sts.py` writes it on every run (through `scripts/trust_chain.py`'s `save_trust_chain()`): the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain the TLS handshake presents when that endpoint is missing. It prints the path, the trust anchor's subject, and its SHA-256; compare the anchor with the Root CA on iya-sts's Server configuration, PKI page. The fetch itself is not verified (trust on first use). `python3 scripts/trust_chain.py --config demo/oidc.json` refreshes only the chain.

The demo image build copies that file in: `.dockerignore` admits only `demo/generated/idp-ca.pem` from `demo/generated/` (the client secret stays out), and `COPY demo demo`, after `cargo build`, puts it at `/app/demo/generated/idp-ca.pem`, where `tlsCa` names it. A build with no chain file yet (a fresh clone, CI) still succeeds and carries none. Run the install script, then build the image; after running it against a different iya-sts, rebuild (`docker compose up --build`). The entrypoint still refreshes the chain from the provider at start unless `TLS_CA_REFRESH=0`, and Compose also mounts `demo/generated`, which holds the same file.

## Layout

| Path | What it is |
|---|---|
| `src` | The library, crate `oidc-caep-risc`. |
| `src/suite.rs` | `cargo test` ports of the Python relying-party and Shared Signals tests. |
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

Demo JSON uses `file:` and the configuration's own placeholders. It does not contain a generated secret or key.
