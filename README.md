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

## Layout

| Path | What it is |
|---|---|
| `src` | The library, crate `oidc-caep-risc`. |
| `src/suite.rs` | `cargo test` ports of the Python relying-party and Shared Signals tests. |
| `demo` | `demo/main.rs`. Config is `demo/oidc.json`. |
| `scripts/configure_iya_sts.py` | Registers the confidential client on iya-sts. Loopback redirects follow the running container's `PORT`, then the shell `PORT`. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

## Demo

`PORT` defaults to 3000. A loopback redirect and post-logout URL follow `PORT`. Any other host is left as written. An explicit `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL.

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` starts `authorize` and redirects. `GET /callback` completes the code exchange. `POST /logout` signs the local session out.

`docker-compose.yml` sets `network_mode: host`. The image sets `ENV PORT=3000`. The health check calls `http://127.0.0.1:${PORT}/healthz`. The running container's `PORT` wins over the shell's when `scripts/configure_iya_sts.py` registers the application.

Demo JSON uses `file:` and the configuration's own placeholders. It does not contain a generated secret or key.
