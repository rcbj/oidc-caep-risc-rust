# oidc-caep-risc-rust

A confidential OpenID Connect relying party for a traditional Rust application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`none`) is refused.

`signals` defaults to on. `signals: false` turns CAEP and RISC off: the receiver does not start, transmitter metadata is not required, and the authorization request does not include `ssf.read` or `ssf.manage`. `DEFAULT_SCOPES` still names those two scopes. They are removed after that default is applied. The shipped demo omits `signals`, so they stay on.

The license is the MIT License in `LICENSE`. A pull request merged into `main` publishes the crate to crates.io after the test workflow succeeds on that commit. A direct push does not. The token is the `CARGO_REGISTRY_TOKEN` repository secret. A version already on crates.io stays there; the next release is a new `version` in `Cargo.toml`. `develop` and `main` are the branches the test workflow runs.

Rust edition 2021. RSA signatures use the `rsa` crate. PSS, ECDSA, and EdDSA are not implemented.

## Layout

| Path | What it is |
|---|---|
| crate `oidc-caep-risc` | The library. `from_file`, `authorize`, `complete`. |
| `src/suite.rs` | `cargo test`. A stub provider and a stub transmitter. No live iya-sts. |
| `src/trust_chain_test.rs` | The trust chain: the registrar writes all four certificates; the library trusts the file, refuses the leaf alone, a wrong host name, and a foreign leaf sent with the real CA certificates. |
| `demo` | `demo/main.rs` and `demo/public/`. Config is `demo/oidc.json`. |
| `scripts` | `configure_iya_sts.py` registers the confidential client. `trust_chain.py` saves the listener CA trust chain to the file named by `tlsCa`. `live_iya_sts.py` is the live sign-in, separate from the unit suite. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

## Usage

```rust
let rp = oidc_caep_risc::RelyingParty::from_file("oidc.json")?;
let request = rp.authorize()?;
let who = rp.complete(&query, &request)?;
```

Keep the transaction (state, nonce, code verifier) until the browser returns. Tokens stay in this process.

## Tests

```bash
docker build --target test .
```

The `test` stage runs `cargo test` in `rust:1-bookworm`. GitHub Actions uses that command. Do not run Cargo on the host. The demo image does not run the suite.

The stub tests do not start iya-sts. `python3 scripts/live_iya_sts.py` does, unless `IYA_STS_URL` names one that is already running. Its order is the user's: it copies the checkout (no `demo/generated`, `.git`, `target`) to a scratch context, rewrites only that copy's URLs (never `tlsCa`), runs the install script (which writes the client secret and the chain), THEN builds the demo image, checks the image's `demo/generated` holds only `idp-ca.pem` and that it equals the saved file (`tlsCaInImage` in the result), and THEN runs the demo with only `client-secret` mounted and `TLS_CA_REFRESH=0`. Secrets reach docker as `-e NAME`, and no log line carries a sign-in URL (each request is logged by a fixed label). It signs the demo in and checks two Shared Signals events on `GET /live-status`. The nightly workflow runs both. `.github/workflows/nightly.yml` runs at 07:02 UTC (`2 7 * * *`) and on `workflow_dispatch`. `IYA_STS_IMAGE` starts a fresh container from an image already built; without it or `IYA_STS_URL` the script clones and builds iya-sts `main`. `LIVE_STS_PORT` defaults to 18516 and `LIVE_DEMO_PORT` to 18616; the script refuses 3000, 8081, and 18481 through 18495. Registration runs `scripts/configure_iya_sts.py` with the host's stdlib python3, never Cargo. Always use a fresh iya-sts: a second registration of the same client fails.

## Demo

`docker-compose.yml` sets `network_mode: host`. The process binds `PORT`, default 3000. `ENV PORT=3000` in the image keeps an unset value on 3000, and the health check calls `http://127.0.0.1:${PORT}/healthz`.

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` redirects to the provider. `GET /callback` completes the sign-in. `POST /logout` ends the local session. `GET /live-status` reports the sign-in and the Shared Signals events this process has accepted. It does not include tokens.

A loopback redirect follows `PORT` in the running server and in `scripts/configure_iya_sts.py`. Any other host is left as written. An explicit `--public-url` or a non-empty `PUBLIC_URL` replaces the origin and keeps the path. The running container's `PORT` wins over the shell's when the script registers the application. `pollIntervalMs` is a millisecond pause, not a port.

Open `http://127.0.0.1:$PORT` after the provider is up. Do not bind port 3000 or 8081 while another demo or iya-sts is already using them.

## Trust chain (`tlsCa`)

`tlsCa` (default `generated/idp-ca.pem`, relative to `demo/`) is iya-sts's TLS listener CA trust chain. `scripts/configure_iya_sts.py` writes it on every run through `scripts/trust_chain.py`'s `save_trust_chain()`: the whole chain from `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), falling back to the handshake's chain, and prints the path, the anchor's subject and SHA-256. `src/http.rs` already split the file and added every PEM block as a native-tls root (`native_tls::Certificate::from_pem` alone reads only the first), native-tls verifies the host name, and nothing pins, so the library needed no change; `src/trust_chain_test.rs` holds all of that. The demo image carries the chain from build time: `.dockerignore` is `demo/generated/*` then `!demo/generated/idp-ca.pem`, the build stage copies only `demo/main.rs` and `demo/public` (so a new chain does not rebuild the binary), and the final stage's `COPY demo demo` lands it at `/app/demo/generated/idp-ca.pem`. With no chain file the same COPY carries nothing from `demo/generated` and the build succeeds. Rebuild the image after re-running the install script against a different iya-sts. `demo/entrypoint.sh` still refreshes the chain at start unless `TLS_CA_REFRESH=0`. The `HEALTHCHECK` reads `$PORT` (it read `$$PORT`, the shell's PID, until #8).
