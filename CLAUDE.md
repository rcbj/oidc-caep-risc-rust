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
| `demo` | `demo/main.rs` and `demo/public/`. Config is `demo/oidc.json`. |
| `scripts` | `configure_iya_sts.py` registers the confidential client. `trust_chain.py` refreshes the listener CA file named by `tlsCa`. |
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

## Demo

`docker-compose.yml` sets `network_mode: host`. The process binds `PORT`, default 3000. `ENV PORT=3000` in the image keeps an unset value on 3000, and the health check calls `http://127.0.0.1:${PORT}/healthz`.

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` redirects to the provider. `GET /callback` completes the sign-in. `POST /logout` ends the local session.

A loopback redirect follows `PORT` in the running server and in `scripts/configure_iya_sts.py`. Any other host is left as written. An explicit `--public-url` or a non-empty `PUBLIC_URL` replaces the origin and keeps the path. The running container's `PORT` wins over the shell's when the script registers the application. `pollIntervalMs` is a millisecond pause, not a port.

Open `http://127.0.0.1:$PORT` after the provider is up. Do not bind port 3000 while another demo is already using it.
