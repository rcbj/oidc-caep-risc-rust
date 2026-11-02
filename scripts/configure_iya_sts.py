# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Register the demo as a confidential OpenID Connect client on a running iya-sts.

The running container's PORT wins over the shell PORT. A loopback redirect follows that
port. An explicit --public-url or PUBLIC_URL replaces the origin and keeps the path.
The default http://localhost:3000 is not an explicit public URL.
"""

import http.client
import json
import os
import socket
import ssl
import stat
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

from trust_chain import save_trust_chain, trust_path

ROOT = Path(__file__).resolve().parents[1]
APP_NAME = "oidc-caep-risc-rust demo"
MAX_BYTES = 2 * 1024 * 1024
TIMEOUT_S = 15


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
                                        [--test-user name | --no-test-user] [--dry-run]

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
    print(f"client_id: {files['clientId']}")
    print(f"metadata:  {files['metadataUrl']}")
    print(f"redirect:  {files['redirectUri']}")
    print(f"auth:      {files['tokenEndpointAuthMethod']}")
    print("Done. Start the demo with: docker compose up --build")


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)
