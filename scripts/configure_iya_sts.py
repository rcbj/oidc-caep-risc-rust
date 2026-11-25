# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Register the demo as a confidential OpenID Connect client on a running iya-sts.

The running container's PORT wins over the shell PORT. A loopback redirect follows that
port. An explicit --public-url or PUBLIC_URL replaces the origin and keeps the path.
The default http://localhost:3000 is not an explicit public URL.

--pep central|local also sets the demo up with its embedded PEP, as
docs/remote-pep.md's steps 2 to 6 describe: the PEP's service account in
remote-peps, a P-256 key made here (demo/generated/pep-key.pem, 0600, never
printed and never in the image), that key certified and the PEP bound to the
demo's application, the catalogue row the demo's policy reads, the demo
application's own policy (it enforces fine-grained authorization, so nothing
realm-wide changes), and a `pep` section in the configuration.
"""

import http.client
import json
import os
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

from trust_chain import save_trust_chain, trust_path

ROOT = Path(__file__).resolve().parents[1]
APP_NAME = "oidc-caep-risc-rust demo"
MAX_BYTES = 2 * 1024 * 1024
TIMEOUT_S = 15

# The embedded PEP (--pep). The key's path is relative to the configuration's
# directory here; the `pep` section names it as the demo process reads it,
# from its working directory (the repository root, or /app in the image).
PEP_MODES = ("central", "local")
PEP_NAME = "pep-oidc-demo"
PEP_KEY = "generated/pep-key.pem"
PEP_KEY_IN_SECTION = "demo/generated/pep-key.pem"
PEP_GROUP = "remote-peps"
PEP_EVENT = "urn:iya:sts:secevent:event-type:pep-policies-changed"
ACR_ATTRIBUTE = "urn:example:acr"
# The demo's attribute-protected resource (GET /attribute-protected): the
# test user carries a custom directory attribute, and the demo application's
# own policy permits the resource only to a person whose attr1 is abc123.
# The PEP asks iya-sts's PIP for it (POST /xacml/pip): it is a directory
# attribute, never a claim.
TEST_ATTRIBUTE = "attr1"
TEST_ATTRIBUTE_VALUE = "abc123"
TEST_ATTRIBUTE_ID = "urn:sts:xacml:attribute:" + TEST_ATTRIBUTE
ATTRIBUTE_PROTECTED = "attribute-protected"
# The PolicyIds of the policies this script writes. While the demo
# application enforces one of these, a run writes the current version over
# it; a policy an administrator wrote under another PolicyId is left alone.
OWN_POLICY_IDS = ("urn:example:pepdemo-orders",)


def orders_policy(namespace="pepdemo", read_effect="permit"):
    """ALFA for the demo application's own policy, the one its fine-grained
    authorization decisions are made with:
    - `read` on an `order` is `read_effect`; `permit` also needs the
      subject's acr, which only the catalogue row brings, so a Permit shows
      the claim arrived;
    - `read` on the `attribute-protected` resource is permitted when the
      person's directory attribute attr1 is abc123, which the PEP asks
      iya-sts's PIP for;
    - anything else is denied."""
    condition = "            condition integerGreaterThan(stringBagSize(acr), 0)\n" if read_effect == "permit" else ""
    return (
        f"namespace {namespace} {{\n"
        '    attribute act { category = actionCat\n'
        '        id = "urn:oasis:names:tc:xacml:1.0:action:action-id" type = string }\n'
        '    attribute rtype { category = resourceCat\n'
        '        id = "urn:sts:xacml:authzen:resource-type" type = string }\n'
        f'    attribute acr {{ category = subjectCat id = "{ACR_ATTRIBUTE}" type = string }}\n'
        f'    attribute {TEST_ATTRIBUTE} {{ category = subjectCat id = "{TEST_ATTRIBUTE_ID}" type = string }}\n'
        f"    policy {namespace}Orders {{\n"
        f'        id = "urn:example:{namespace}-orders"\n'
        "        apply firstApplicable\n"
        "        rule readOrder {\n"
        f"            {read_effect}\n"
        '            target clause act == "read"\n'
        '            target clause rtype == "order"\n'
        f"{condition}"
        "        }\n"
        "        rule readAttributeProtected {\n"
        "            permit\n"
        '            target clause act == "read"\n'
        f'            target clause rtype == "{ATTRIBUTE_PROTECTED}"\n'
        f'            target clause {TEST_ATTRIBUTE} == "{TEST_ATTRIBUTE_VALUE}"\n'
        "        }\n"
        "        rule otherwise {\n"
        "            deny\n"
        "        }\n"
        "    }\n"
        "}\n"
    )


def _ssl_context(tls):
    tls = tls or {}
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    ca = tls.get("ca")
    if ca:
        context.load_verify_locations(cadata=ca)
    return context


def send(url, method="GET", headers=None, body=None, tls=None, code="config"):  # noqa: ARG001
    """One HTTP(S) request. Redirects are not followed. The body is capped."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise RuntimeError(f"{url} is not an http(s) URL")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    payload = None if body is None else (body.encode("utf-8") if isinstance(body, str) else body)
    hdrs = {str(k): str(v) for k, v in (headers or {}).items()}
    if payload is not None:
        hdrs["content-length"] = str(len(payload))
    connection = None
    try:
        if parts.scheme == "https":
            connection = http.client.HTTPSConnection(parts.hostname, port, timeout=TIMEOUT_S, context=_ssl_context(tls))
        else:
            connection = http.client.HTTPConnection(parts.hostname, port, timeout=TIMEOUT_S)
        connection.request(method, path, body=payload, headers=hdrs)
        response = connection.getresponse()
        raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise RuntimeError(f"{url} answered more than {MAX_BYTES} bytes")
        content_type = response.getheader("content-type") or ""
        return {"status": response.status, "content_type": content_type, "body": raw.decode("utf-8", "replace")}
    except socket.timeout as err:
        raise RuntimeError(f"{url} did not answer within {TIMEOUT_S} s") from err
    except RuntimeError:
        raise
    except Exception as err:
        raise RuntimeError(f"{url}: {err}") from err
    finally:
        if connection is not None:
            connection.close()
SSF_ROLES = (
    {"scope": "ssf.read", "role": "SSF_READ", "group": "ssf-read"},
    {"scope": "ssf.manage", "role": "SSF_MANAGE", "group": "ssf-manage"},
)
GRANTS = ("authorization_code", "refresh_token", "client_credentials")
MULTIPLE_ACCOUNTS = {"key": "authn.multipleAccounts", "value": True}
LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def usage():
    return """Usage: python scripts/configure_iya_sts.py [--config path] [--idp url] [--public-url url]
                                        [--test-user name | --no-test-user]
                                        [--pep central|local] [--pep-name name] [--dry-run]

  --config        The demo's OpenID Connect configuration (default: demo/oidc.json)
  --idp           iya-sts's base URL; the realm's, e.g. https://host/realm/acme, for a trust realm
                  (default: the origin of the configuration's metadataUrl, or $IYA_STS_URL)
  --public-url    Replace the origin of the file's redirect URIs with this URL, and keep their paths
                  (default: unset; $PUBLIC_URL). Without it, a loopback redirect follows the
                  running demo's PORT, then $PORT. A non-loopback redirect is left as written.
  --test-user     The test user to create (default: oidc-demo-user). Its password is
                  $OIDC_DEMO_USER_PASSWORD, or one is generated and written to
                  generated/<user>.password beside the configuration (mode 0600); only
                  the path is printed. With that variable set, an existing user's
                  password is replaced.
  --no-test-user  Do not create a test user.
  --pep [MODE]    Also set up the embedded PEP in this mode, local (the default: it caches
                  the application's policies and decides in process) or central: its service
                  account, its key (generated/pep-key.pem beside the configuration, 0600,
                  made here and never printed), the key certified and bound to the demo's
                  application, the catalogue row subject.acr, the application's own policy
                  (permit read on an order with an acr; fine-grained authorization enforced),
                  and a `pep` section written into the configuration. Run it again to switch
                  modes: an existing key, account and policy are kept.
  --pep-name      The PEP's service account (default: pep-oidc-demo).
  --dry-run       Print what would be done, and send nothing. Does not write a secret.

The management API secret is ADMIN_API_CLIENT_SECRET or STS_ADMIN_API_CLIENT_SECRET."""


def on_port(url, port):
    """Replace the port of a loopback URL. Anything else is returned unchanged."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if host not in LOOPBACK:
        return url
    hostname = f"[{host}]" if ":" in host else host
    user = ""
    if parts.username:
        user = parts.username
        if parts.password:
            user += f":{parts.password}"
        user += "@"
    netloc = f"{user}{hostname}:{port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme, netloc, path, parts.query, parts.fragment))


def redirects_for(redirect_uri, post_logout_redirect_uri, public_url=None, public_url_given=False, port=None):
    """The redirect URIs to register, or the ones the running server sends."""
    if public_url_given and public_url:
        base = urlsplit(public_url if str(public_url).endswith("/") else f"{public_url}/")

        def move(value):
            nxt = urlsplit(value)
            hostname = base.hostname or ""
            host = f"[{hostname}]" if ":" in hostname else hostname
            netloc = f"{host}:{base.port}" if base.port else host
            return urlunsplit((base.scheme, netloc, nxt.path or "/", nxt.query, nxt.fragment))

        return {"redirectUri": move(redirect_uri), "postLogoutRedirectUri": move(post_logout_redirect_uri)}
    if port:
        return {
            "redirectUri": on_port(redirect_uri, port),
            "postLogoutRedirectUri": on_port(post_logout_redirect_uri, port),
        }
    return {"redirectUri": redirect_uri, "postLogoutRedirectUri": post_logout_redirect_uri}


def demo_port(env_port, container_port):
    """The container's PORT wins. Otherwise the environment. An empty or unusable value is absent."""
    raw = str(container_port or "").strip() or str(env_port or "").strip()
    if not raw:
        return None
    try:
        port = int(raw)
    except ValueError:
        return None
    if str(port) != raw or port < 1 or port > 65535:
        return None
    return port


def parse_args(argv, env=None):
    env = os.environ if env is None else env
    out = {
        "config": str((ROOT / "demo" / "oidc.json").resolve()),
        "idp": str(env.get("IYA_STS_URL") or "").rstrip("/"),
        "publicUrl": str(env.get("PUBLIC_URL") or "http://localhost:3000").rstrip("/"),
        "publicUrlGiven": bool(env.get("PUBLIC_URL")),
        "testUser": "oidc-demo-user",
        "dryRun": False,
        "help": False,
        "idpGiven": bool(env.get("IYA_STS_URL")),
        "pep": "",
        "pepName": PEP_NAME,
    }
    i = 0
    while i < len(argv):
        arg = argv[i]

        def value():
            nonlocal i
            i += 1
            if i >= len(argv):
                raise RuntimeError(f"{arg} needs a value\n{usage()}")
            return argv[i]

        if arg in ("--help", "-h"):
            out["help"] = True
        elif arg == "--config":
            out["config"] = str(Path(value()).resolve())
        elif arg == "--idp":
            out["idp"] = value().rstrip("/")
            out["idpGiven"] = True
        elif arg == "--public-url":
            out["publicUrl"] = value().rstrip("/")
            out["publicUrlGiven"] = True
        elif arg == "--test-user":
            out["testUser"] = value().strip()
        elif arg == "--no-test-user":
            out["testUser"] = ""
        elif arg == "--pep":
            # The mode may be left out: then local, iya-pep's default (the
            # PEP caches the application's policies and decides in process).
            if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                out["pep"] = value().strip()
            else:
                out["pep"] = "local"
            if out["pep"] not in PEP_MODES:
                raise RuntimeError(f"--pep must be central or local, not {out['pep']}")
        elif arg == "--pep-name":
            out["pepName"] = value().strip()
            if not out["pepName"]:
                raise RuntimeError("--pep-name is empty")
        elif arg == "--dry-run":
            out["dryRun"] = True
        else:
            raise RuntimeError(f"Unknown argument {arg}\n{usage()}")
        i += 1
    if out["idp"]:
        parsed = urlsplit(out["idp"])
        if parsed.scheme != "https":
            raise RuntimeError(f"--idp must be https, not {out['idp']}")
    if not out["publicUrl"]:
        raise RuntimeError("--public-url is empty")
    return out


def files_of(config_path, public_url):
    raw = json.loads(Path(config_path).read_text(encoding="utf-8"))
    base = str(Path(config_path).resolve().parent)

    def at(path):
        return path if os.path.isabs(path) else str(Path(base, path).resolve())

    client_id = str(raw.get("clientId") or raw.get("client_id") or "").strip()
    metadata_url = str(raw.get("metadataUrl") or "").strip()
    if not client_id:
        raise RuntimeError(f"{config_path} has no client_id")
    if not metadata_url:
        raise RuntimeError(f"{config_path} has no metadataUrl")
    method = str(raw.get("tokenEndpointAuthMethod") or "client_secret_basic")
    if method == "none":
        raise RuntimeError(f"{config_path} asks for a public client; this demo registers a confidential one")
    secret_raw = str(raw.get("clientSecret") or "")
    if not secret_raw.startswith("file:"):
        raise RuntimeError(f"{config_path}'s clientSecret must be a file: path so this script can write it")
    if isinstance(raw.get("scopes"), list):
        scopes = [str(item).strip() for item in raw["scopes"] if str(item).strip()]
    else:
        scopes = [part for part in str(raw.get("scopes") or "").split() if part]
    if "openid" not in scopes:
        raise RuntimeError(f"{config_path}'s scopes must include openid")
    if "signals" in raw and not isinstance(raw.get("signals"), bool):
        raise RuntimeError(f"{config_path}: signals must be true or false")
    signals = raw.get("signals") is not False
    used = scopes if signals else [scope for scope in scopes if scope not in ("ssf.read", "ssf.manage")]
    origin = public_url if str(public_url).endswith("/") else f"{public_url}/"
    redirect_uri = str(raw.get("redirectUri") or raw.get("redirect_uri") or "").strip() or _join(origin, "callback")
    post = str(raw.get("postLogoutRedirectUri") or raw.get("post_logout_redirect_uri") or "").strip() or _join(origin, "")
    tls = trust_path(raw.get("tlsCa"), base)
    files = {
        "clientId": client_id,
        "redirectUri": redirect_uri,
        "postLogoutRedirectUri": post,
        "scopes": used,
        "tokenEndpointAuthMethod": method,
        "metadataUrl": metadata_url,
        "secretFile": at(secret_raw[5:]),
    }
    if tls:
        files["tlsCa"] = tls
    transmitter = ((raw.get("ssf") or {}) if isinstance(raw.get("ssf"), dict) else {}).get("transmitter")
    if signals and transmitter:
        files["ssfTransmitter"] = str(transmitter).rstrip("/")
    return files


def _join(origin, suffix):
    base = origin if origin.endswith("/") else f"{origin}/"
    if not suffix:
        return base
    return base + suffix


def realm_of(idp):
    parsed = urlsplit(idp)
    if parsed.scheme != "https":
        raise RuntimeError(f"the provider must be https, not {idp}")
    path = parsed.path.rstrip("/")
    if path and not __import__("re").fullmatch(r"/realm/[^/]+", path):
        raise RuntimeError(f"--idp must be iya-sts's base URL or a realm's (/realm/<id>), not {idp}")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return {"origin": origin, "base": f"{origin}{path}"}


def application_fields(files):
    """The application's fields, without its client secret.

    The secret is added to the create call only as it is sent (main()), so the plan, which
    --dry-run prints and errors quote, never holds it.
    """
    return {
        "oauthClientId": files["clientId"],
        "oauthRedirectUri": [files["redirectUri"]],
        "oauthPostLogoutRedirectUri": [files["postLogoutRedirectUri"]],
        "oauthResponseType": ["code"],
        "oauthGrantType": list(GRANTS),
        "oauthAllowedScope": files["scopes"],
        "oauthTokenEndpointAuthMethod": files["tokenEndpointAuthMethod"],
        # id_token_signed_response_alg: the library accepts RS256 ID tokens by default.
        "oauthIdTokenSignedResponseAlg": "RS256",
    }


def user_attributes(username):
    return {
        "cn": f"OIDC Demo {username}",
        "givenName": "OIDC",
        "sn": "Demo",
        "displayName": f"OIDC Demo {username}",
        "mail": f"{username}@oidc-demo.test",
    }


def plan_for(files, base, test_user):
    fields = application_fields(files)
    calls = [{
        "method": "POST",
        "path": f"{base}/admin-api/applications/create",
        "when": "create",
        "why": f"register {files['clientId']}",
        "body": {
            "identifier": files["clientId"],
            "name": APP_NAME,
            "protocols": ["oauth2", "oidc"],
            "fields": fields,
        },
    }]
    for protocol in ("oauth2", "oidc"):
        calls.append({
            "method": "POST",
            "path": f"{base}/admin-api/applications/add",
            "when": "exists",
            "why": f"declare protocol {protocol}",
            "body": {"application": files["clientId"], "attribute": "appAllowedProtocol", "value": protocol},
        })
    for attribute, raw in fields.items():
        if attribute == "oauthClientId":
            # The application's own name: already right on an existing one.
            continue
        values = [str(item) for item in raw] if isinstance(raw, list) else [str(raw)]
        for value in values:
            calls.append({
                "method": "POST",
                "path": f"{base}/admin-api/applications/add",
                "when": "exists",
                "why": f"add {attribute}",
                "body": {"application": files["clientId"], "attribute": attribute, "value": value},
            })
    calls.append({
        "method": "POST",
        "path": f"{base}/admin-api/config/set",
        "when": "always",
        "why": "let one browser hold several accounts",
        "body": MULTIPLE_ACCOUNTS,
    })
    for role in SSF_ROLES:
        if role["scope"] not in files["scopes"]:
            continue
        calls.append({
            "method": "POST",
            "path": f"{base}/admin-api/roles/add-member",
            "when": "always",
            "why": f"hold {role['role']}, which authorizes {role['scope']}",
            "body": {"role": role["role"], "kind": "application", "member": files["clientId"]},
        })
    if test_user:
        calls.append({
            "method": "POST",
            "path": f"{base}/admin-api/users/create",
            "when": "always",
            "why": f"create the test user {test_user}",
            "body": {"username": test_user, "invent": False, "credential": "generate", "attributes": user_attributes(test_user)},
        })
        for role in SSF_ROLES:
            if role["scope"] not in files["scopes"]:
                continue
            calls.append({
                "method": "POST",
                "path": f"{base}/admin-api/groups/add-member",
                "when": "always",
                "why": f"put {test_user} in {role['group']}",
                "body": {"group": role["group"], "member": test_user},
            })
        calls.append({
            "method": "POST",
            "path": f"{base}/admin-api/policies/define-person-attribute",
            "when": "attribute",
            "why": f"define the realm's custom attribute {TEST_ATTRIBUTE} (unless it is defined)",
            "body": {"name": TEST_ATTRIBUTE, "label": "Attribute 1", "syntax": "string", "multiValued": False},
        })
        calls.append({
            "method": "POST",
            "path": f"{base}/admin-api/users/set-attribute",
            "when": "attribute",
            "why": f"give {test_user} {TEST_ATTRIBUTE}={TEST_ATTRIBUTE_VALUE}",
            "body": {"user": test_user, "attribute": TEST_ATTRIBUTE, "value": TEST_ATTRIBUTE_VALUE},
        })
    return calls


def _json_call(url, ca, method="GET", headers=None, body=None):
    answer = send(url, method=method, headers=headers, body=body, tls={"ca": ca} if ca else None, code="config")
    try:
        parsed = json.loads(answer["body"]) if answer["body"] else {}
    except json.JSONDecodeError as err:
        raise RuntimeError(f"{method} {url} answered {answer['status']} with non-JSON: {answer['body'][:300]}") from err
    if not isinstance(parsed, dict):
        parsed = {}
    if answer["status"] in (401, 403):
        raise RuntimeError(f"{method} {url} answered {answer['status']}: {json.dumps(parsed)[:300]}")
    return {"status": answer["status"], "body": parsed}


def _errors_of(body):
    errors = body.get("errors") or []
    if not isinstance(errors, list):
        errors = [errors]
    return [str(item) for item in errors]


def _mint_admin_token(base, ca, secret):
    import base64
    form = f"grant_type=client_credentials&scope={quote('admin:read admin:write')}&resource={quote(base + '/admin-api', safe='')}"
    token = base64.b64encode(f"sts-api-client:{secret}".encode()).decode()
    reply = _json_call(f"{base}/oauth2/token", ca, "POST", {
        "content-type": "application/x-www-form-urlencoded",
        "authorization": f"Basic {token}",
    }, form)
    if reply["status"] != 200 or not isinstance(reply["body"].get("access_token"), str):
        raise RuntimeError(f"the token endpoint answered {reply['status']} {json.dumps(reply['body'])[:300]}")
    return reply["body"]["access_token"]


def _write_private(path, value):
    """Write a file only its owner can read: created 0600, never wider."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(descriptor, "w", encoding="utf-8") as out:
        os.fchmod(out.fileno(), stat.S_IRUSR | stat.S_IWUSR)
        out.write(f"{value}\n")


def pep_plan(files, base, name, mode):
    """What --pep does, for --dry-run. No key and no request leaves here."""
    app = files["clientId"]
    return [
        f"GET  {base}/admin-api/users?user={name}  # create the service account unless it exists",
        f"POST {base}/admin-api/users/create  # {name}: a service account, owned by admin-write, no credential",
        f"POST {base}/admin-api/groups/add-member  # {name} in {PEP_GROUP}",
        f"# make a P-256 key in {PEP_KEY} beside the configuration (0600) unless one is there",
        f"POST {base}/admin-api/xacml/issue-pep-credential  # its certificate request, bound to {app} (a new key or account)",
        f"POST {base}/admin-api/xacml/set-pep-application  # or, with both kept, the binding to {app} again",
        f"POST {base}/admin-api/xacml/authzen/set-attribute  # subject.acr -> {ACR_ATTRIBUTE}",
        f"POST {base}/admin-api/applications/fga-create-policy  # {app}'s own policy, unless it has one",
        f"POST {base}/admin-api/xacml/import-alfa  # the demo policy into it (when {app} enforces none yet, or this script's own)",
        f"POST {base}/admin-api/applications/fga-enable  # {app} enforces fine-grained authorization",
        f"POST {base}/admin-api/applications/add  # {PEP_EVENT} in ssfAllowedEvents, only if {app} restricts them",
        f"# write \"pep\": {{\"name\": \"{name}\", \"mode\": \"{mode}\", \"assertionKey\": \"{PEP_KEY_IN_SECTION}\"}} into the configuration",
    ]


def set_test_attribute(api, user):
    """The realm's custom attribute attr1, and the test user's value of it,
    which GET /attribute-protected is decided on.

    Defining a custom attribute changes the realm's attribute policy, which
    only a Security Administrator may do (a person holding SECURITY_ADMIN,
    with an admin:security token); the management API client this script
    uses holds Admin Write, which does not reach it. So a refusal there is
    not fatal: the rest of the setup goes on, and the script says what a
    Security Administrator does on the console before this is run again.
    Answers whether the test user now holds the value."""
    try:
        defined = api("/policies/define-person-attribute", {
            "name": TEST_ATTRIBUTE, "label": "Attribute 1", "syntax": "string", "multiValued": False,
            "description": "The demo's attribute-protected resource is permitted when this is abc123.",
        })
    except RuntimeError as err:
        # _json_call raises on 401 and 403; only the Security Administrator
        # refusal is expected here, and it is not fatal.
        if "403" not in str(err) or "security administrator" not in str(err).lower():
            raise
        defined = {"status": 403, "body": {"errors": ["Only a Security Administrator may make this change"]}}
    words = " ".join(_errors_of(defined["body"])).lower()
    if defined["status"] == 403 and "security administrator" in words:
        print(f"The custom attribute {TEST_ATTRIBUTE} could not be defined with this credential: only a Security")
        print("Administrator may change the attribute policy. Sign in to the console as one (the bootstrap")
        print(f"administrator is), open Directory > Policies > Attribute policy > Custom attributes, and add")
        print(f"{TEST_ATTRIBUTE} (label \"Attribute 1\", syntax string, one value). Then run this script again to give")
        print(f"{user} {TEST_ATTRIBUTE}={TEST_ATTRIBUTE_VALUE}. (If {TEST_ATTRIBUTE} is defined already, the value is set below.)")
    elif not (defined["status"] == 200 and defined["body"].get("ok") is not False):
        if "already" not in words and "exists" not in words:
            raise RuntimeError(f"defining the custom attribute {TEST_ATTRIBUTE}: refused ({defined['status']}): {json.dumps(defined['body'])[:400]}")
    try:
        answered = api("/users/set-attribute", {"user": user, "attribute": TEST_ATTRIBUTE, "value": TEST_ATTRIBUTE_VALUE})
    except RuntimeError as err:
        print(f"{user} does not have {TEST_ATTRIBUTE} yet: {str(err)[:300]}")
        return False
    if answered["status"] == 200 and answered["body"].get("ok") is not False:
        print(f"{user} has {TEST_ATTRIBUTE}={TEST_ATTRIBUTE_VALUE} (a custom attribute of the realm).")
        return True
    print(f"{user} does not have {TEST_ATTRIBUTE} yet: {' '.join(_errors_of(answered['body']))[:300]}")
    return False


def make_pep_key(key_file, name):
    """A P-256 key made here with openssl, created 0600 (it is never printed,
    and neither is its path's content). Answers nothing: the request is made
    from the file by pep_csr()."""
    key_file.parent.mkdir(parents=True, exist_ok=True)
    old = os.umask(0o077)
    try:
        made = subprocess.run(
            ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key_file)],
            check=False, capture_output=True, text=True,
        )
    finally:
        os.umask(old)
    if made.returncode != 0:
        raise RuntimeError("openssl could not make the PEP's key (is openssl installed?)")
    os.chmod(key_file, 0o600)


def pep_csr(key_file, name):
    """The key's certificate request, the only thing about it that is sent."""
    with tempfile.TemporaryDirectory() as work:
        csr = Path(work) / "pep.csr"
        asked = subprocess.run(
            ["openssl", "req", "-new", "-key", str(key_file), "-subj", f"/CN={name}", "-out", str(csr)],
            check=False, capture_output=True, text=True,
        )
        if asked.returncode != 0:
            raise RuntimeError("openssl could not make the PEP's certificate request from its key")
        return csr.read_text(encoding="utf-8")


def _ok(answer, what, allow=""):
    """An /admin-api act that worked, or one refused only because it is
    already so (`allow`, matched in the refusal's words)."""
    body = answer["body"]
    if answer["status"] == 200 and body.get("ok") is not False:
        return True
    words = " ".join(_errors_of(body)) + " " + str(body.get("why") or "")
    if allow and allow in words.lower():
        return False
    raise RuntimeError(f"{what}: refused ({answer['status']}): {json.dumps(body)[:400]}")


def write_pep_section(config_path, name, mode):
    """The configuration's `pep` section: the name, the mode and the key's
    path; any other member already there is kept."""
    path = Path(config_path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    section = raw.get("pep") if isinstance(raw.get("pep"), dict) else {}
    section.update({"name": name, "mode": mode, "assertionKey": PEP_KEY_IN_SECTION})
    raw["pep"] = section
    path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")


def setup_pep(api, files, config_path, name, mode):
    """docs/remote-pep.md's steps 2 to 6. Safe to run again: an account, a
    key and a policy already there are kept, and the binding is set again."""
    app = files["clientId"]
    # Step 2: the service account, in remote-peps.
    found = api(f"/users?user={quote(name)}", None, "GET")
    made_account = found["body"].get("known") is not True
    if made_account:
        _ok(api("/users/create", {
            "username": name, "invent": False, "credential": "none", "serviceAccount": True,
            "owners": ["admin-write"], "attributes": {"cn": name, "displayName": name},
        }), f"creating the service account {name}")
        print(f"Created the PEP's service account {name}.")
    else:
        print(f"The PEP's service account {name} already exists.")
    _ok(api("/groups/add-member", {"group": PEP_GROUP, "member": name}), f"adding {name} to {PEP_GROUP}")
    # Step 3: the key, certified from its own request, and the binding.
    key_file = Path(config_path).resolve().parent / PEP_KEY
    made_key = not key_file.exists()
    if made_key:
        make_pep_key(key_file, name)
        print(f"Generated the PEP's P-256 key in {key_file} (readable by you only).")
    if made_key or made_account:
        issued = api("/xacml/issue-pep-credential", {"name": name, "csr": pep_csr(key_file, name), "application": app})
        _ok(issued, "certifying the PEP's key")
        print(f"Certified the PEP's key and bound {name} to {app}.")
    else:
        _ok(api("/xacml/set-pep-application", {"name": name, "application": app}), f"binding {name} to {app}")
        print(f"Kept the PEP's key; {name} is bound to {app}.")
    # Step 4: the claim the policy reads.
    _ok(api("/xacml/authzen/set-attribute", {"object": "subject", "property": "acr", "attributeId": ACR_ATTRIBUTE}),
        "the catalogue row subject.acr")
    # Step 5: the application's own policy, written only the first time, so
    # an administrator's edits survive a re-run.
    page = api(f"/applications?application={quote(app, safe='')}", None, "GET")["body"].get("page") or {}
    fga = page.get("fga") or {}
    current_id = (fga.get("policy") or {}).get("policyId") or ""
    if fga.get("enforced") is True and current_id not in OWN_POLICY_IDS:
        print(f"{app} already enforces a policy of its own ({current_id or 'unnamed'}); it is left as it is.")
    elif fga.get("enforced") is True:
        policy = (fga.get("policy") or {}).get("name")
        _ok(api("/xacml/import-alfa", {"name": policy, "alfa": orders_policy()}), f"writing {policy}")
        print(f"{app} enforces this script's policy {policy}; it now holds the current version.")
    else:
        _ok(api("/applications/fga-create-policy", {"application": app}), f"{app}'s own policy", allow="already")
        page = api(f"/applications?application={quote(app, safe='')}", None, "GET")["body"].get("page") or {}
        fga = page.get("fga") or {}
        policy = (fga.get("policy") or {}).get("name") or fga.get("reference")
        if not policy:
            raise RuntimeError(f"{app}'s page names no policy of its own: {json.dumps(fga)[:300]}")
        _ok(api("/xacml/import-alfa", {"name": policy, "alfa": orders_policy()}), f"writing {policy}")
        _ok(api("/applications/fga-enable", {"application": app}), f"enforcing {app}'s own policy")
        print(f"{app} now enforces its own policy {policy}: read on an order needs an acr; read on {ATTRIBUTE_PROTECTED} needs {TEST_ATTRIBUTE}={TEST_ATTRIBUTE_VALUE}; anything else is denied.")
    # Step 6: only an application that restricts its streams needs the event named.
    allowed = (page.get("attributes") or {}).get("ssfAllowedEvents") or []
    if isinstance(allowed, str):
        allowed = [allowed]
    if allowed and PEP_EVENT not in allowed:
        _ok(api("/applications/add", {"application": app, "attribute": "ssfAllowedEvents", "value": PEP_EVENT}),
            "letting pep-policies-changed through ssfAllowedEvents", allow="already")
        print(f"Added {PEP_EVENT} to {app}'s ssfAllowedEvents.")
    write_pep_section(config_path, name, mode)
    print(f"Wrote a {mode} pep section into {config_path}.")


def container_port(cwd=None):
    """PORT from the running oidc-demo container, when compose has one."""
    cwd = str(cwd or ROOT)
    try:
        listed = subprocess.run(
            ["docker", "compose", "ps", "-q", "oidc-demo"],
            cwd=cwd, check=False, capture_output=True, text=True,
        )
        container_id = (listed.stdout or "").strip().split("\n")[0]
        if not container_id:
            return None
        inspected = subprocess.run(
            ["docker", "inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", container_id],
            check=False, capture_output=True, text=True,
        )
        if inspected.returncode != 0:
            return None
        for line in inspected.stdout.split("\n"):
            if line.startswith("PORT="):
                return line[len("PORT="):]
        return None
    except Exception:
        return None


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    args = parse_args(argv)
    if args["help"]:
        print(usage())
        return
    files = files_of(args["config"], args["publicUrl"])
    port = demo_port(os.environ.get("PORT"), container_port())
    redirects = redirects_for(
        files["redirectUri"], files["postLogoutRedirectUri"],
        public_url=args["publicUrl"], public_url_given=args["publicUrlGiven"], port=port,
    )
    files["redirectUri"] = redirects["redirectUri"]
    files["postLogoutRedirectUri"] = redirects["postLogoutRedirectUri"]
    idp = args["idp"] or f"{urlsplit(files['metadataUrl']).scheme}://{urlsplit(files['metadataUrl']).netloc}"
    realm = realm_of(idp)
    origin, base = realm["origin"], realm["base"]
    on_disk = ""
    secret_file = Path(files["secretFile"])
    if secret_file.exists():
        on_disk = secret_file.read_text(encoding="utf-8").strip()
    if args["dryRun"]:
        if files.get("tlsCa"):
            print(f"# would save {origin}'s listener CA trust chain to {files['tlsCa']}")
        # Nothing printed here comes from the client secret or from where
        # clientSecret keeps it: fixed labels, and a plan that holds no secret.
        if not on_disk:
            print("# would write a new client secret to the file clientSecret names (mode 0600)")
        else:
            print("# would keep the client secret in the file clientSecret names")
        print("# the create call also sends the client secret as oauthClientSecret (not shown)")
        for call in plan_for(files, base, args["testUser"]):
            printed = json.dumps(call.get("body") or {}, indent=2)
            print(f"{call['method']} {call['path']}  # {call['when']}: {call['why']}\n{printed}")
        if args["pep"]:
            for line in pep_plan(files, base, args["pepName"], args["pep"]):
                print(line)
        return
    ca = None
    if files.get("tlsCa"):
        chain = save_trust_chain(origin, files["tlsCa"])
        ca = chain["pem"]
        subject = chain["anchor"].subject.rfc4514_string().replace("\n", ", ")
        print(f"Saved {origin}'s listener CA trust chain ({chain['count']} certificate(s)) to {files['tlsCa']}")
        print(f"  trust anchor {subject}")
        print(f"  sha256 {chain['fingerprint']}")
        print("  Compare the anchor with the Root CA on iya-sts's Server configuration, PKI page.")
    admin_secret = os.environ.get("ADMIN_API_CLIENT_SECRET") or os.environ.get("STS_ADMIN_API_CLIENT_SECRET") or ""
    if not admin_secret:
        raise RuntimeError("neither ADMIN_API_CLIENT_SECRET nor STS_ADMIN_API_CLIENT_SECRET is set, so no /admin-api token can be minted.")
    token = _mint_admin_token(base, ca, admin_secret)

    def api(path, body=None, method="POST"):
        headers = {"accept": "application/json", "authorization": f"Bearer {token}"}
        payload = None
        if body is not None:
            headers["content-type"] = "application/json"
            payload = json.dumps(body)
        return _json_call(f"{base}/admin-api{path}", ca, method, headers, payload)

    minted = not on_disk
    secret = on_disk or __import__("secrets").token_urlsafe(32)
    plan = plan_for(files, base, args["testUser"])
    create = next(call for call in plan if call["when"] == "create")
    # The secret joins a copy of the create body as it is sent; the plan never holds it.
    sent = dict(create["body"], fields=dict(create["body"]["fields"], oauthClientSecret=secret))
    created = api("/applications/create", sent)
    fresh = False
    if created["body"].get("ok"):
        fresh = True
        if minted:
            _write_private(files["secretFile"], secret)
        print(f"Registered {files['clientId']}. The client secret is in the file clientSecret names.")
    elif any("already in this registry" in item.lower() or "already in this registry" in item for item in _errors_of(created["body"])):
        if minted:
            raise RuntimeError(f"{files['clientId']} already exists, and the file clientSecret names is missing. This script does not rotate the client secret. Restore that file, or set a new secret on the application, then re-run.")
        print(f"{files['clientId']} is already registered; adding the demo's values. The client secret is unchanged.")
        for call in plan:
            if call["when"] != "exists":
                continue
            added = api(call["path"][len(f"{base}/admin-api"):], call["body"])
            errors = " ".join(_errors_of(added["body"]))
            if not added["body"].get("ok") and "not one of the" in errors and call["path"].endswith("/applications/add"):
                # A single-valued attribute `add` does not take (such as
                # oauthIdTokenSignedResponseAlg) is SET instead; without this a
                # second run against the same iya-sts stopped here.
                added = api("/applications/set", call["body"])
                errors = " ".join(_errors_of(added["body"]))
            if not added["body"].get("ok") and "already" not in errors.lower():
                raise RuntimeError(f"{call['why']}: refused: {json.dumps(added['body'])[:400]}")
    else:
        raise RuntimeError(f"iya-sts refused to create {files['clientId']}: {json.dumps(created['body'])[:500]}")
    for call in plan:
        if call["when"] != "always":
            continue
        if not (call["path"].endswith("/config/set") or call["path"].endswith("/roles/add-member")):
            continue
        answered = api(call["path"][len(f"{base}/admin-api"):], call["body"])
        errors = " ".join(_errors_of(answered["body"]))
        if not answered["body"].get("ok") and "already" not in errors.lower():
            raise RuntimeError(f"{call['why']}: refused: {json.dumps(answered['body'])[:400]}")
        if not answered["body"].get("ok"):
            print(f"  {call['why']}: already so")
    if fresh:
        print("authn.multipleAccounts is on, and the Shared Signals roles were granted for the scopes in the file.")
    if args["testUser"]:
        found = api(f"/users?user={quote(args['testUser'])}", None, "GET")
        password = os.environ.get("OIDC_DEMO_USER_PASSWORD") or ""
        if found["body"].get("known") is True and password:
            set_password = api("/users/set-password", {"user": args["testUser"], "password": password, "passwordConfirm": password})
            if not set_password["body"].get("ok"):
                raise RuntimeError(f"setting {args['testUser']}'s password was refused: {json.dumps(set_password['body'])[:300]}")
            print(f"User {args['testUser']} already exists; its password is now OIDC_DEMO_USER_PASSWORD.")
        elif found["body"].get("known") is True:
            print(f"User {args['testUser']} already exists; its password is unchanged (set OIDC_DEMO_USER_PASSWORD to replace it).")
        else:
            body = {"username": args["testUser"], "invent": False, "attributes": user_attributes(args["testUser"])}
            if password:
                body.update({"credential": "password", "password": password, "passwordConfirm": password})
            else:
                body["credential"] = "generate"
            made = api("/users/create", body)
            if not made["body"].get("ok"):
                raise RuntimeError(f"creating {args['testUser']} was refused: {json.dumps(made['body'])[:300]}")
            print(f"Created user {args['testUser']}.")
            if made["body"].get("password"):
                # Never printed: a password does not belong in a log. It goes to
                # a file only its owner can read, created 0600, in
                # demo/generated beside the configuration (never in an image).
                saved = Path(args["config"]).resolve().parent / "generated" / f"{args['testUser']}.password"
                _write_private(saved, made["body"]["password"])
                print(f"Generated a password for {args['testUser']}; it is in {saved} (readable by you only).")
        for call in plan:
            if not call["path"].endswith("/groups/add-member"):
                continue
            added = api("/groups/add-member", call["body"])
            if not added["body"].get("ok"):
                raise RuntimeError(f"adding {args['testUser']} to a group was refused: {json.dumps(added['body'])[:300]}")
            group = (call["body"] or {}).get("group")
            print(f"{args['testUser']} {'was already' if added['body'].get('changed') is False else 'is now'} in {group}.")
        set_test_attribute(api, args["testUser"])
    if args["pep"]:
        setup_pep(api, files, args["config"], args["pepName"], args["pep"])
    print(f"client_id: {files['clientId']}")
    print(f"metadata:  {files['metadataUrl']}")
    print(f"redirect:  {files['redirectUri']}")
    print(f"auth:      {files['tokenEndpointAuthMethod']}")
    if args["pep"]:
        print(f"pep:       {args['pepName']}, {args['pep']} (GET /orders/42 needs a sign-in with an acr; POST is denied)")
    print("Done. Start the demo with: docker compose up --build")


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)
