# Using the iya-sts Remote PEP

This library can ask iya-sts's authorization policy whether a signed-in person (a `Login`) may do something to a resource in your application, through an embedded **Remote PEP** (Policy Enforcement Point). The PEP itself is the shared [`iya-pep`](https://github.com/rcbj/iya-pep-rust) crate; this library builds it from your configuration, turns its OpenID Connect sign-in into the PEP's subject, and hands it policy-change events from its Shared Signals stream. The design is [iya-sts #1206](https://github.com/rcbj/iya-sts/issues/1206).

The PEP never permits by default. A decision is `Permit`, `Deny` or `Unavailable`, and `Unavailable` (no policy held yet, or iya-sts unreachable) must be treated as a refusal.

## Choosing a mode

| | `central` | `local` |
|---|---|---|
| Who decides | iya-sts, per request (`POST /access/v1/evaluation`) | this process, with the PEP's own XACML engine |
| Cargo feature | `pep` | `local` |
| Latency | one HTTPS round trip per decision | none after the first pull |
| When iya-sts is down | every decision is `Unavailable` | decisions continue with the policies held |
| Policy changes | at once | on the `pep-policies-changed` event, or the next poll |
| Decision records | written by iya-sts | sent by the PEP to iya-sts's audit log |

Pick `central` when decisions are infrequent or must reflect a change immediately, and `local` when decisions are on a hot path or must survive a short outage. Both modes give the same answer for the same request: `local` maps the request through the realm's catalogue exactly as iya-sts does, and its engine is held to iya-sts's conformance corpus.

## Before you start: set up iya-sts

You need an iya-sts release with embedded-PEP support (iya-sts #2026, #2027 and #2028). The steps below use the management API; `$API` is `https://<host>/realm/<realm>/admin-api` (or `https://<host>/admin-api` for the default realm) and `$TOKEN` a token for it with write access. Every step has a console equivalent, named after it.

```bash
api() { curl -s -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d "$2" "$API/$1"; }
```

### 1. Register the application

Register the OpenID Connect client in iya-sts as usual; `scripts/configure_iya_sts.py` does it for the demo. Note its identifier: it is the `application` the PEP is bound to (`clientId` by default).

### 2. Create the PEP's service account

The PEP signs in as a service account of its own, never as a person or as the application:

```bash
api users/create '{"username":"pep-orders","invent":false,
  "credential":"none","serviceAccount":true,"owners":["admin-write"],
  "attributes":{"cn":"pep-orders","displayName":"pep-orders"}}'
api groups/add-member '{"group":"remote-peps","member":"pep-orders"}'
```

Console: **Users → New user** (tick **Service account**), then the `remote-peps` group's **Add member**.

### 3. Make the PEP's key, certify it and bind the PEP

Generate the key where the application runs. Only the certificate request leaves the machine:

```bash
openssl ecparam -name prime256v1 -genkey -noout | \
  openssl pkcs8 -topk8 -nocrypt -out pep-key.pem
openssl req -new -key pep-key.pem -subj /CN=pep-orders -out pep-key.csr
api xacml/issue-pep-credential "$(jq -n --rawfile csr pep-key.csr \
  '{name: "pep-orders", csr: $csr, application: "<application id>"}')"
```

`application` binds the PEP to the application in the same call (`POST /admin-api/xacml/set-pep-application` does it on its own). An EC P-256 key is preferred; RSA of 2048 bits or more is accepted. **The key must be the PEP's own**: this library refuses a configuration where it is the `private_key_jwt` key (`privateKeyPem`) and the DPoP key (`dpopKey`, or the one generated at start).

Console: **Protocols → XACML → Remote PEPs**, **Certify the key**, then the PEP's Overview, **Embedded in an application**.

### 4. Declare the claims your policy reads

The PEP sends a subject's claims only through the realm's AuthZEN attribute catalogue: a claim with no catalogue row is not sent (iya-sts would refuse the whole request). Add one row per claim your policy uses, on **Protocols → XACML → AuthZEN** or through `/admin-api/xacml/authzen`. For example, to make `acr` available as `urn:example:acr`:

| `object` | `property` | `attributeId` |
|---|---|---|
| `subject` | `acr` | `urn:example:acr` |

The same applies to `resource.properties`, `action.properties` and `context` members you put on an `Access`. iya-sts's [AuthZEN page](https://rcbj.github.io/iya-sts/v1.2.0/authzen.html), *The realm's conversion rules*, describes the rows.

### 5. Write the policy

The policy that decides is the application's own fine-grained authorization policy when the application enforces fine-grained authorization, and otherwise the realm's root policy. A `local` PEP is sent that policy and everything it references, and nothing else. The subject's id arrives as XACML's `subject-id`, the action's name as `action-id` and the resource's id as `resource-id`; anything else comes through the catalogue rows of step 4, or from iya-sts's PIP for attributes on the person's directory entry.

### 6. (`local` with signals) let the event through

If the application's entry restricts its Shared Signals streams with `ssfAllowedEvents`, add `urn:iya:sts:secevent:event-type:pep-policies-changed` to it. Otherwise the PEP doesn't hear of a change until its fallback poll, and the application's page in the console warns about it.

## Build with the feature

```toml
oidc-caep-risc = { version = "…", features = ["pep"] }    # central
oidc-caep-risc = { version = "…", features = ["local"] }  # local (includes central)
```

Without the feature a `pep` section is refused when the configuration is read, rather than silently ignored.

## Configure

Add a `pep` section to `oidc.json`. The PEP is off unless it is present.

```json
"pep": {
  "name": "pep-orders",
  "mode": "local",
  "assertionKey": "pep-key.pem"
}
```

| Member | Default here | What it is |
|---|---|---|
| `name` | required | The PEP's service account (step 2). |
| `mode` | `central` | `central` or `local`. |
| `assertionKey` | required | The PEP's private key in PEM: a path; a relative one is read from the process's working directory. The file is re-read when it changes. |
| `pdpUrl` | the provider's `issuer` (the realm prefix included) | iya-sts, with `/realm/<id>` for a realm. |
| `application` | `clientId` | The application the PEP is bound to (step 3). |
| `clientId` | `sts-remote-pep` | The client the PEP's assertion is presented through. |
| `signals` | the library's `signals` (on unless `signals: false`) | Whether a signal stream hands over policy-change events. Without one, `local` polls at `pollIntervalMs`. |
| `pollIntervalMs` | 15000 | `local` without a signal stream. |
| `fallbackPollMs` | 300000 | `local` with one, in case an event is lost. |
| `heartbeatIntervalMs` | 30000 | How often the PEP reports to iya-sts. |
| `permitCacheMs` | 0 (off) | `central` only: reuse a Permit for this long, at most 60000. The policy-change event clears it. |
| `supportedObligations` | `[]` | The obligation types your application discharges (see *Obligations*). |
| `decisionRecords` | `true` | `local`: send each decision to iya-sts's audit log. |
| `tlsCa` | the library's `tlsCa` | PEM trust anchors for iya-sts's TLS. |
| `timeoutMs` | 10000 | Per request to iya-sts. |

An unknown member is refused, so a misspelt one doesn't quietly fall back to a default. `RelyingParty::create` and `from_file` start the PEP.

## Decide

```rust
use std::sync::Arc;
use oidc_caep_risc::{ReceiverOptions, RelyingParty, SignalsReceiver};
use oidc_caep_risc::pep::{Access, Decision};

let rp = Arc::new(RelyingParty::from_file("oidc.json")?); // registers the PEP and, in local mode, pulls

// After `rp.complete_session(&query, &txn, &session_id)?`:
let access = Access::new("read", "order", order_id);
match rp.decide_session(&session_id, &access) {
    Decision::Permit { obligations, .. } => serve(obligations),
    Decision::Deny { why } => forbidden(&why),          // 403
    Decision::Unavailable { why } => unavailable(&why), // 503: fail closed
}
// Or with a Login you hold yourself: rp.decide(&login, &access)
```

`Access::new(action, resource_type, resource_id)` carries the AuthZEN action and resource. Add `resource_properties`, `action_properties` or `context` members as your policy needs them, each declared in the catalogue (step 4). The PEP always sets `context.application` to the bound application, whatever you put there.

**The subject** comes from the sign-in, never from a request header:

- **id:** `preferred_username`, else `sub`. iya-sts's PIP resolves a username, a DN or a certificate subject, and `preferred_username` is the directory username.
- **properties:** every ID token claim (`acr`, `amr`, `auth_time`, `email`, …). `subject_with_userinfo(&login, &userinfo)` lays fetched userinfo claims over them.

Only the properties the catalogue declares are sent.

**Ended sessions.** `rp.decide_session(session_id, &access)` looks the sign-in up in the relying party's session cache. A session that is gone (signed out, expired, or ended by a CAEP `session-revoked` the receiver handled) is a Deny, and iya-sts isn't asked.

**Without a `pep` section**, every decision is `Unavailable`.

### Obligations

A `Permit` can carry obligations, which your application must carry out before it grants the access (for example a `step-up` to a stronger `acr`). The PEP only hands you obligations of types you list in `supportedObligations`. A Permit carrying any other obligation is turned into a Deny, so an obligation is never silently dropped. `advice` (local mode) can be ignored.

```json
"pep": { "name": "pep-orders", "assertionKey": "pep-key.pem", "supportedObligations": ["step-up"] }
```

With the `tokio` feature, `iya-pep`'s async wrappers are on too: `rp.pep().unwrap().decide_async(subject, access).await`, where `subject` is `oidc_caep_risc::pep::subject_of(&login)`. They run the same blocking call through `spawn_blocking`.

## Receive policy-change events

In `local` mode, and in `central` mode with a Permit cache, the PEP wants to hear when the policies change. Build the receiver with `relying_party`, as you already do for authorized transmitter calls; it finds the PEP there.

```rust
let receiver = SignalsReceiver::new(&transmitter_url, on_end, ReceiverOptions {
    relying_party: Some(Arc::clone(&rp)), // the PEP comes with the relying party
    ..ReceiverOptions::default()
})?;
receiver.start()?;
```

The receiver then asks its stream for `urn:iya:sts:secevent:event-type:pep-policies-changed`, verifies each SET like every other one, and hands the event to the PEP. The event is only a hint: the PEP pulls with its own credential and never trusts the event's contents. An event naming another PEP is ignored.

## Operate it

- **Health.** `pep().unwrap().status()` reports whether the PEP is registered and running, whether it holds a policy (and which sync token), its decision counters and its current problems. It holds no secret, so it's safe on a health page.
- **In the console.** The PEP appears under **Protocols → XACML → Remote PEPs** with its kind (`embedded`), application, mode, protocol version and whether its stream carries policy-change events. The application's page lists the PEPs bound to it.
- **Rotating the key.** Generate a new key, certify it with `issue-pep-credential` (add `revokePrevious: true` to retire the old one), replace the file, and call `pep().unwrap().reload_key()` (or wait up to 30 s). The tokens bound to the old key are dropped.
- **Audit.** In `local` mode each decision becomes an audit row in iya-sts (`authzen.remote.decision`). In `central` mode iya-sts records its own.

## Troubleshooting

| What you see | Likely cause |
|---|---|
| Every decision `Unavailable`, `status().registered` false, a problem mentioning 403 | The PEP's entry has no binding, or is bound to another application (iya-sts `STS-XACML-0338`, `0339`). Repeat step 3 with the right `application`. |
| `Unavailable` and a problem naming the token endpoint (`invalid_grant`) | The key isn't certified for this account, or the account isn't in `remote-peps` (steps 2 and 3). |
| `Unavailable` with "no policy is held yet" (`local`) | The first pull hasn't succeeded. Check `status().last_error`: a 403 on the policy pull (`STS-XACML-0343`) means the PEP isn't registered as an embedded `local` PEP bound to that application. |
| A registration refused with 400 (`STS-XACML-0340`) | The iya-sts release doesn't support this PEP's protocol version. Upgrade iya-sts or this library. |
| `Deny` saying the evaluation was refused (`local`: "refused (STS-AUTHZEN-0004)"; `central`: "the service refused the evaluation: invalid_request …") | A resource, action or context property you sent has no catalogue row (step 4). Subject claims without a row are dropped, not refused. |
| `Deny` although the policy should permit | The policy reads a claim that has no catalogue row, so it never arrives (step 4). Or a Permit carried an obligation type missing from `supportedObligations`. |
| Policy changes take minutes to apply (`local`) | The stream doesn't carry the event: check the console's *policy-change events* column, and `ssfAllowedEvents` (step 6). |
| The configuration is refused for the assertion key | It is one of this library's own keys. The PEP needs a key of its own. |

## The demo

Built with `local` (the Dockerfile does), the demo protects `GET /orders/<id>` with the PEP when `demo/oidc.json` has a `pep` section: 401 without a sign-in, 200 on a Permit, 403 on a Deny and 503 on `Unavailable`.

## See also

- [`iya-pep`'s README](https://github.com/rcbj/iya-pep-rust#readme): the crate's own API and every configuration member.
- iya-sts's [Remote PEP page](https://rcbj.github.io/iya-sts/v1.2.0/remote-pep.html), *An embedded PEP's application*: the service's side of the binding, registration and the scoped pull.
- iya-sts's [CAEP events page](https://rcbj.github.io/iya-sts/v1.2.0/caep-events.html): the `pep-policies-changed` event.
