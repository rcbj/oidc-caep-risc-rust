# Using the iya-sts Remote PEP

This library can ask iya-sts's authorization policy whether a signed-in person (a `Login`) may do something to a resource in your application, through an embedded **Remote PEP** (Policy Enforcement Point). The PEP itself is the shared [`iya-pep`](https://github.com/rcbj/iya-pep-rust) crate; this library builds it from your configuration, turns its OpenID Connect sign-in into the PEP's subject, and hands it policy-change events from its Shared Signals stream. The design is [iya-sts #1206](https://github.com/rcbj/iya-sts/issues/1206).

The PEP never permits by default. A decision is `Permit`, `Deny` or `Unavailable`, and `Unavailable` (no policy held yet, iya-sts unreachable or answering badly, an engine fault, or a panic while deciding, which the PEP catches) must be treated as a refusal. Every PEP failure is a 403: `Decision::http_status()` is 200 for a Permit and 403 for a Deny and an `Unavailable` alike, never a 5xx a client might retry into a different answer.

## Choosing a mode

| | `central` | `local` |
|---|---|---|
| Who decides | iya-sts, per request (`POST /access/v1/evaluation`) | this process, with the PEP's own XACML engine |
| Cargo feature | `pep` | `local` |
| Latency | one HTTPS round trip per decision | none after the first pull |
| When iya-sts is down | every decision is `Unavailable`, and a Permit cache (if on) is emptied | decisions continue with the policies held |
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

For the demo, `python3 scripts/configure_iya_sts.py --pep local` (a bare `--pep` is `local` too) or `--pep central` does steps 1 to 6 in one run and writes the `pep` section: see *The demo*. The steps below are what it does, for your own application.

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

`application` binds the PEP to the application in the same call (`POST /admin-api/xacml/set-pep-application` does it on its own). An EC P-256 key is preferred; RSA of 2048 bits or more is accepted. **The key must be the PEP's own**: this library refuses a configuration where it is the `private_key_jwt` key (`privateKeyPem`) or the DPoP key (`dpopKey`, or the one generated at start).

Console: **Protocols → XACML → Remote PEPs**, **Certify the key**, then the PEP's Overview, **Embedded in an application**.

### 4. Declare the claims your policy reads

The PEP sends a subject's claims only through the realm's AuthZEN attribute catalogue: a claim with no catalogue row is not sent (iya-sts would refuse the whole request). Add one row per claim your policy uses, on **Protocols → XACML → AuthZEN** or with `POST /admin-api/xacml/authzen/set-attribute`. For example, to make `acr` available as `urn:example:acr`:

```bash
api xacml/authzen/set-attribute '{"object":"subject","property":"acr","attributeId":"urn:example:acr"}'
```

which is the row

| `object` | `property` | `attributeId` |
|---|---|---|
| `subject` | `acr` | `urn:example:acr` |

The same applies to `resource.properties`, `action.properties` and `context` members you put on an `Access`. iya-sts's [AuthZEN page](https://rcbj.github.io/iya-sts/v1.2.0/authzen.html), *The realm's conversion rules*, describes the rows.

### 5. Write the policy

The policy that decides is the application's own fine-grained authorization policy when the application enforces fine-grained authorization, and otherwise the realm's root policy. A `local` PEP is sent that policy and everything it references, and nothing else. The subject's id arrives as XACML's `subject-id`, the action's name as `action-id` and the resource's id as `resource-id`; anything else comes through the catalogue rows of step 4, or from iya-sts's PIP for attributes on the person's directory entry. The resource's type arrives as `urn:sts:xacml:authzen:resource-type`.

For an application that enforces no fine-grained authorization, a root that permits `read` on an `order` when the person's `acr` arrived, and denies everything else, can be written in ALFA (the console's **Policies** tab does the same):

```bash
api xacml/import-alfa "$(jq -n --arg alfa '
namespace orders {
    attribute act { category = actionCat
        id = "urn:oasis:names:tc:xacml:1.0:action:action-id" type = string }
    attribute rtype { category = resourceCat
        id = "urn:sts:xacml:authzen:resource-type" type = string }
    attribute acr { category = subjectCat id = "urn:example:acr" type = string }
    policy ordersRoot {
        id = "urn:example:orders"
        apply firstApplicable
        rule readOrder {
            permit
            target clause act == "read"
            target clause rtype == "order"
            condition integerGreaterThan(stringBagSize(acr), 0)
        }
        rule otherwise { deny }
    }
}' '{name: "orders", alfa: $alfa}')"
api xacml/set-root '{"name":"orders"}'
```

Every change to that policy, or to which policy is the root, is sent to a `local` PEP as `pep-policies-changed` (step 6).

### 6. (`local` with signals) let the event through

If the application's entry restricts its Shared Signals streams with `ssfAllowedEvents`, add `urn:iya:sts:secevent:event-type:pep-policies-changed` to it. Otherwise the PEP doesn't hear of a change until its fallback poll, and the application's page in the console warns about it.

## Build with the feature

```toml
oidc-caep-risc = { version = "…", features = ["pep"] }    # central
oidc-caep-risc = { version = "…", features = ["local"] }  # local (includes central)
```

Without the feature a `pep` section is refused when the configuration is read, rather than silently ignored. A section that names no `mode` is `local`, so a build with `pep` alone must name `"mode": "central"`; otherwise it is refused the same way.

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
| `mode` | `local` | `local` (the PEP pulls its application's policies, caches them in memory and decides in process) or `central` (it asks iya-sts for every decision). |
| `assertionKey` | required | The PEP's private key in PEM: a path; a relative one is read from the process's working directory. The file is re-read when it changes. |
| `pdpUrl` | the provider's `issuer` (the realm prefix included) | iya-sts, with `/realm/<id>` for a realm. |
| `application` | `clientId` | The application the PEP is bound to (step 3). |
| `clientId` | `sts-remote-pep` | The client the PEP's assertion is presented through. |
| `signals` | the library's `signals` (on unless `signals: false`) | Whether a signal stream hands over policy-change events. With it on, the PEP starts as `down` until the receiver reports the stream. |
| `pollIntervalMs` | 15000 | `local`: the poll period while the stream does not carry the event (no stream, `down` or `excluded`). |
| `fallbackPollMs` | 300000 | `local`: the poll period while the stream carries the event (`requested`), in case one is lost. |
| `heartbeatIntervalMs` | 30000 | How often the PEP reports to iya-sts. |
| `permitCacheMs` | 0 (off) | `central` only: reuse a Permit for this long, at most 60000. The policy-change event clears it, and so does a failed evaluation or a failed heartbeat: no cached Permit is served until iya-sts answers an evaluation again. |
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
    Decision::Unavailable { why } => forbidden(&why),   // 403: fail closed
}
// Or with a Login you hold yourself: rp.decide(&login, &access)
// The PEP chooses the status itself: 200 for a Permit, 403 for anything else.
let status = rp.decide_session(&session_id, &access).http_status();
```

Answer the request with `http_status()` rather than your own mapping, so a failure can never become anything but a 403. Whether the person is signed in at all (a 401) is your question, asked before the PEP's. The demo's `GET /orders/<id>` takes its status from it.

`Access::new(action, resource_type, resource_id)` carries the AuthZEN action and resource. Add `resource_properties`, `action_properties` or `context` members as your policy needs them, each declared in the catalogue (step 4). The PEP always sets `context.application` to the bound application, whatever you put there.

**The subject** comes from the sign-in, never from a request header:

- **id:** the username: iya-sts's `username` claim, else `preferred_username`, else `sub`. iya-sts's PIP resolves a username, a DN or a certificate subject. Every ID token iya-sts issues carries `username`; `preferred_username` is a `profile` claim, there only when that scope was granted.
- **properties:** every ID token claim (`acr`, `amr`, `auth_time`, `email`, …). `subject_with_userinfo(&login, &userinfo)` lays fetched userinfo claims over them.

Only the properties the catalogue declares are sent.

**Ended sessions.** `rp.decide_session(session_id, &access)` looks the sign-in up in the relying party's session cache. A session that is gone (signed out, expired, or ended by a CAEP `session-revoked` the receiver handled) is a Deny, and iya-sts isn't asked.

**Without a `pep` section**, every decision is `Unavailable` (a 403).

**`decide` never fails.** No policy held, a service that can't be reached or answers badly, an engine fault, or a panic while deciding is `Unavailable` (a panic's reason goes to `status().last_error`), never a Permit and never an unwinding thread.

### Obligations

A `Permit` can carry obligations, which your application must carry out before it grants the access (for example a `step-up` to a stronger `acr`). The PEP only hands you obligations of types you list in `supportedObligations`. A Permit carrying any other obligation is turned into a Deny, so an obligation is never silently dropped. `advice` can be ignored; `central` carries it only while the realm's `authzen.returnReasons` is on.

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

The receiver then asks its stream for `urn:iya:sts:secevent:event-type:pep-policies-changed`, verifies each SET like every other one, and hands the event to the PEP. A stream that already exists (made before the `pep` section was added, or while the PEP was `central`) is updated with `PATCH` to ask for the event too; if the transmitter refuses, the receiver still starts, the refusal goes to `on_error`, and the PEP's heartbeat reports the event as `excluded`. The event is only a hint: the PEP pulls with its own credential and never trusts the event's contents. An event naming another PEP is ignored.

The same receiver tells the transmitter whom this application follows: Add Subject when `track` follows a person's sign-in, Remove Subject when their last one here ends (`ssf.addSubjects`, default on; see the README's *Shared Signals subjects*). A stream that names subjects carries only events about them, and `pep-policies-changed` is about the application, so when the PEP wants events the receiver also adds the application (`{"format": "opaque", "id": <application>}`) at `start` and never removes it; without that, policy changes would reach a `local` PEP only by its poll once someone had signed in.

The receiver keeps the PEP's view of the stream current: `requested` (or `excluded`) when it starts and after each poll that succeeds, `down` after a poll that fails and once `stop()` is called. A `local` PEP polls at `pollIntervalMs` while the stream is not `requested`, so a change still arrives while the stream cannot carry it, and the heartbeat reports the state.

## Credentials

The PEP has credentials of its own, separate from the application's (the client secret or `private_key_jwt` key, the DPoP key, the Shared Signals token; see the README's *Credentials*).

### The embedded PEP's credentials

- **The service account** (step 2): an account with no password, a member of `remote-peps`, named by `pep.name`. Tokens are issued to it, never to a person or the application.
- **The key** (step 3): EC P-256 preferred (RSA 2048 or more accepted), made where the application runs; only its certificate request is sent. `issue-pep-credential` certifies it for the account and binds the PEP to the application. `pep.assertionKey` names its file (a path); keep the file 0600 and out of images.
- **What it authenticates:** the PEP signs an RFC 7523 assertion (`iss` = `sub` = the account, `aud` the token endpoint, 120 s, a fresh `jti`) and gets a DPoP-bound access token as the remote-PEP client (`pep.clientId`, default `sts-remote-pep`), one per audience: `xacml:pep` (registration, heartbeat, the catalogue and policy pulls, the PIP), `xacml:pep-audit` (the decision records `local` ships), and `authzen:evaluate` (`central`'s evaluations). The same key signs every DPoP proof, so each token is bound to it. No token, key or proof is logged.
- **Its own key:** `RelyingParty::create` refuses an assertion key that is the `private_key_jwt` key or the DPoP key, by JWK thumbprint. Shared, the holder of one credential would hold the other, iya-sts could not tell the PEP's calls from the application's, and rotating one would break the other.
- **Rotation:** see *Operate it* (a new key, `issue-pep-credential` with `revokePrevious: true`, then the file replaced; the PEP reads it again).

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
| Policy changes take minutes to apply (`local`) | The stream is `requested` but the event never arrives, so only the `fallbackPollMs` poll brings the change. The stream doesn't carry the event: check the console's *policy-change events* column, `ssfAllowedEvents` (step 6), and `on_error` for a refused stream update. |
| The configuration is refused for the assertion key | It is one of this library's own keys. The PEP needs a key of its own. |

## The demo

Built with `local` (the Dockerfile does), the demo protects `GET /orders/<id>` with the PEP when `demo/oidc.json` has a `pep` section (a GET is `read`; any other method is `write`, which the demo's policy denies): 401 without a sign-in, then the decision's `http_status()`: 200 on a Permit, and 403 on a Deny and on `Unavailable` (any PEP failure is a 403; the page says whether the PEP denied it or could not decide). With no relying party to ask (the configuration doesn't load) it is 403 too. The demo decides with `decide` on the cookie session's `Login`. `GET /live-status` carries the PEP's `status()` under `pep`.

Set it up in one command:

```bash
python3 scripts/configure_iya_sts.py --pep local    # or --pep central
docker compose up --build
```

This registers the client as without `--pep`, then does steps 2 to 6 (a bare `--pep` is `local`):
- the service account `pep-oidc-demo` (`--pep-name`) in `remote-peps`;
- a P-256 key in `demo/generated/pep-key.pem`, made with `openssl` (0600, never printed, mounted by Compose and never in the image), certified from its own request with the PEP bound to the demo's application;
- the catalogue row `subject.acr` → `urn:example:acr`;
- the demo application's own policy (step 5's, for an application that enforces fine-grained authorization), which it then enforces, so the realm's root is untouched;
- `pep-policies-changed` added to `ssfAllowedEvents` only if the application restricts it.

It writes the `pep` section (`name`, `mode`, `assertionKey`) into `demo/oidc.json`. Running it again keeps the account and the key, sets the binding again and switches the mode. The policy is written only while the application enforces none: once it enforces one, the script leaves it as it is, so edits survive and a newer version of the script's own policy does not reach an existing install. `--dry-run` prints every call. The image copies `demo/oidc.json` in when it is built, so rebuild after the script writes the section (`docker compose up --build`); Compose mounts `demo/generated`, which holds the PEP's key.

**The AuthZEN tests** hold the two modes to one answer. `src/tests/authzen_cases.json` is a table of catalogue rows, policies and 54 cases (a sign-in's claims, an `Access`, and the answer the host must see). `cargo test` runs every case through a `local` PEP against a stub PDP. `python3 scripts/live_iya_sts.py --authzen` provisions a fresh iya-sts with one `central` and one `local` PEP per application and fails on any case where the two answer differently, or differently from the table. It found two differences for an application that enforces fine-grained authorization: `central` answered `Unavailable` (the service's 500) wherever that application's policy reached a policy it references, and `local` missed the `urn:sts:xacml:fga:stage` fact the service adds. Both are fixed (iya-sts's `decideAccess()` resolves the references a local PEP is sent, and iya-pep adds the two FGA facts), and the live run is 54 of 54. Two more things are held equal by iya-pep: advice reaches a `central` PEP only while the realm's `authzen.returnReasons` is on, and a `local` PEP writes the caller fact (`urn:sts:xacml:authzen:caller`) as its entry's DN, which the registration answers, as the service does.

## See also

- [`iya-pep`'s README](https://github.com/rcbj/iya-pep-rust#readme): the crate's own API and every configuration member.
- iya-sts's [Remote PEP page](https://rcbj.github.io/iya-sts/v1.2.0/remote-pep.html), *An embedded PEP's application*: the service's side of the binding, registration and the scoped pull.
- iya-sts's [CAEP events page](https://rcbj.github.io/iya-sts/v1.2.0/caep-events.html): the `pep-policies-changed` event.
