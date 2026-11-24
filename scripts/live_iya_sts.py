#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Sign this demo in to a fresh iya-sts and confirm two Shared Signals events.

Starts the latest main branch of iya-sts in memory mode, with persistence and
clustering off and no request workers, unless IYA_STS_URL is already set.
Registers the demo with the host's python3, signs in through it, emits a
credential-change and a session-revoked event, and requires the demo's
/live-status to show both. The second one also ends the local session.

The unit suite stays `docker build --target test`. This file is the live half.
It uses the host's Python and Docker. The demo runs in a container. Configuring
the client is `python3 scripts/configure_iya_sts.py` on the host, not in a
container. It does not import this library and does not run Cargo. Do not bind
port 3000, 8081, or 18481 through 18495.

IYA_STS_URL, when set, uses an iya-sts that is already running and does not
stop it. This script never removes iya-sts-live-main, iya-sts-live-probe, or a
container whose name starts with sts. Otherwise it clones main (or builds
IYA_STS_SRC) and removes only the container it started. The demo container it
removes is oidc-caep-risc-rust-live-demo. It never runs docker compose up, and
it never uses --network host for iya-sts.

The trust chain goes in the way a user's does. The script copies this checkout
to a scratch build context (without demo/generated, .git or target), points
that copy's demo/oidc.json at this iya-sts and this demo (URLs only; tlsCa is
never rewritten), and runs the install script against it, which writes the
listener CA trust chain to the file tlsCa names (demo/generated/idp-ca.pem).
THEN it builds the demo image, which carries that file from build time, checks
the image's copy equals the saved one and that nothing else of demo/generated
is in the image, and THEN runs the demo with only the client secret mounted,
file by file, and no start-time refresh (TLS_CA_REFRESH=0). Nothing here
fetches the CA for the demo or mounts a CA into its container. This script
reads the saved chain for its own HTTPS client.

--pep (or LIVE_PEP=1) adds the embedded PEP (#46): after the install script it
provisions the PEP through /admin-api as docs/remote-pep.md says (a service
account in remote-peps, a P-256 key made here in demo/generated, 0600 and never
printed, issue-pep-credential with the CSR binding it to the demo's
application, a catalogue row for acr) and deploys a realm root that permits
read on order and nothing else. The demo runs with a pep section in central
mode (with only the client secret and the PEP's key mounted), then again in
local mode, and both times GET /orders/42 must be 200 and POST /orders/42 403.
In local mode the root then moves to a policy that denies read, and the 200
must turn into a 403 within PEP_FLIP_TIMEOUT seconds (30) through the
pep-policies-changed event, with the fallback poll left at its 300 s default
so the poll cannot be what did it. The result's pep object holds each check.

Secrets reach docker and the install script as -e NAME and through the
environment, never on a command line. No log line carries a URL from the
sign-in (its query and path hold opaque handles, and some answer requests that
carried the password): each request is logged by a fixed label.
"""

import base64
import email.message
import http.client
import http.cookiejar
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STS_REPO = "https://github.com/rcbj/iya-sts.git"
CAEP = "https://schemas.openid.net/secevent/caep/event-type/"
CREDENTIAL_CHANGE = CAEP + "credential-change"
SESSION_REVOKED = CAEP + "session-revoked"
FORBIDDEN_PORTS = {3000, 8081, *range(18481, 18496)}
PROTECTED_CONTAINERS = {"iya-sts-live-main", "iya-sts-live-probe"}

PROFILE = {
    "repo": "oidc-caep-risc-rust",
    "login_path": "/login",
    "status_path": "/live-status",
    "configure": ["python3", "scripts/configure_iya_sts.py"],
    "config_file": "demo/oidc.json",
    "password_env": "OIDC_DEMO_USER_PASSWORD",
    "test_user": "oidc-demo-user",
}


class LoopbackCookiePolicy(http.cookiejar.DefaultCookiePolicy):
    """Send a Secure cookie to loopback HTTP. Browsers do this for localhost."""

    def _loopback(self, request):
        host = (request.host or "").split(":")[0].strip("[]")
        return host in ("localhost", "127.0.0.1", "::1")

    def set_ok_secure(self, cookie, request):
        if cookie.secure and self._loopback(request):
            return True
        return http.cookiejar.DefaultCookiePolicy.set_ok_secure(self, cookie, request)

    def return_ok_secure(self, cookie, request):
        if cookie.secure and self._loopback(request):
            return True
        return http.cookiejar.DefaultCookiePolicy.return_ok_secure(self, cookie, request)


class _CookieResponse:
    def __init__(self, headers):
        self._headers = email.message.Message()
        for name, value in headers:
            self._headers[name] = value

    def info(self):
        return self._headers


class FormFinder(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        found = {key.lower(): value for key, value in attrs}
        if tag == "form":
            self._form = {
                "action": found.get("action") or "",
                "method": (found.get("method") or "get").lower(),
                "fields": [],
            }
        elif tag == "input" and self._form is not None and found.get("name"):
            self._form["fields"].append((found["name"], found.get("value") or ""))

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


class Client:
    def __init__(self, ca_file):
        self.jar = http.cookiejar.CookieJar(policy=LoopbackCookiePolicy())
        self.ssl = ssl.create_default_context(cafile=str(ca_file))
        self.ssl.minimum_version = ssl.TLSVersion.TLSv1_2

    def request(self, method, url, body=None, headers=None, timeout=60):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise RuntimeError("refusing a URL that is not http(s)")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        target = urllib.request.Request(url, headers=headers or {}, method=method)
        self.jar.add_cookie_header(target)
        sent = {key.lower(): value for key, value in (headers or {}).items()}
        cookie = target.get_header("Cookie")
        if cookie and "cookie" not in sent:
            sent["cookie"] = cookie
        if body is not None and "content-length" not in sent:
            sent["content-length"] = str(len(body))
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(parts.hostname, port, context=self.ssl, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(parts.hostname, port, timeout=timeout)
        try:
            conn.request(method, path, body=body, headers=sent)
            response = conn.getresponse()
            payload = response.read()
            header_pairs = response.getheaders()
        finally:
            conn.close()
        self.jar.extract_cookies(_CookieResponse(header_pairs), target)
        return response.status, header_pairs, payload


def header_map(pairs):
    found = {}
    for name, value in pairs:
        found.setdefault(name.lower(), []).append(value)
    return found


def one_header(pairs, name):
    values = header_map(pairs).get(name.lower()) or []
    return values[-1] if values else ""


def resolve_url(base, location):
    return urllib.parse.urljoin(base, location)


def origin_of(url):
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def path_of(url):
    return urllib.parse.urlsplit(url).path or "/"


def query_of(url):
    return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)


def run(command, **kwargs):
    print("+ " + " ".join(command), flush=True)
    completed = subprocess.run(command, check=False, text=True, **kwargs)
    if completed.returncode != 0:
        if completed.stdout:
            print(completed.stdout, flush=True)
        if completed.stderr:
            print(completed.stderr, file=sys.stderr, flush=True)
        raise RuntimeError(f"{command[0]} exited {completed.returncode}")
    return completed


def docker(*args, **kwargs):
    return run(["docker", *args], **kwargs)


def docker_rm(name):
    if not name:
        return
    if name in PROTECTED_CONTAINERS or name.startswith("sts"):
        raise RuntimeError(f"refusing to remove {name}")
    subprocess.run(["docker", "rm", "-f", name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wait_port(port, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 2):
                return
        except OSError:
            time.sleep(1)
    raise RuntimeError(f"127.0.0.1:{port} did not accept a connection")


def wait_ready(origin, timeout):
    """Wait for discovery to answer. Readiness only: nothing is trusted from it."""
    parts = urllib.parse.urlsplit(origin)
    context = ssl._create_unverified_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, context=context, timeout=10)
        try:
            conn.request("GET", (parts.path or "").rstrip("/") + "/.well-known/openid-configuration")
            response = conn.getresponse()
            response.read()
            if response.status == 200:
                return
            last = f"answered {response.status}"
        except OSError as err:
            last = str(err)
        finally:
            conn.close()
        time.sleep(2)
    raise RuntimeError(f"{origin} discovery did not answer 200: {last}")


def copy_context(dest):
    """This checkout as a build context, without .git, target or demo/generated."""

    def ignore(directory, names):
        here = Path(directory).resolve()
        skipped = {".git", "__pycache__"} & set(names)
        if here == ROOT:
            skipped |= {"target"} & set(names)
        if here == ROOT / "demo":
            skipped |= {"generated"} & set(names)
        return skipped

    shutil.copytree(ROOT, dest, ignore=ignore)


def rewrite_config(source, dest, sts_origin, demo_origin):
    """Point the demo at this iya-sts and this demo origin. tlsCa is left alone."""
    raw = json.loads(source.read_text(encoding="utf-8"))
    origin = sts_origin.rstrip("/")
    raw["issuer"] = origin
    raw["metadataUrl"] = origin + "/.well-known/openid-configuration"
    ssf = raw.get("ssf")
    if not isinstance(ssf, dict):
        ssf = {}
    ssf["transmitter"] = origin
    ssf["pollIntervalMs"] = 1000
    raw["ssf"] = ssf
    for key in ("redirectUri", "redirect_uri", "postLogoutRedirectUri", "post_logout_redirect_uri"):
        value = raw.get(key)
        if not isinstance(value, str) or not value:
            continue
        parts = urllib.parse.urlsplit(value)
        if (parts.hostname or "") not in ("localhost", "127.0.0.1", "::1"):
            continue
        raw[key] = demo_origin.rstrip("/") + (parts.path or "/")
    dest.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")


def json_body(payload):
    try:
        parsed = json.loads(payload.decode() if payload else "{}")
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def autopost_form(payload):
    parser = FormFinder()
    try:
        parser.feed(payload.decode("utf-8", "replace"))
    except Exception:
        return None
    for form in parser.forms:
        names = {name for name, _value in form["fields"]}
        if names.intersection({"SAMLResponse", "wresult"}) and form["method"] == "post":
            return form
    return None


# What a sign-in request is logged as. A label is one of these constants, never
# text taken from the URL: the URLs carry pending-step handles, codes and state,
# and some come back from requests that carried the password.
LOG_PATHS = (
    "/authn-api/pending/",
    "/authn-api/consent/",
    "/authn-api/mfa/",
    "/gnap-api/approve/",
    "/authn/login",
    "/authn/mfa-setup",
    "/authn/post-login",
    "/oauth2/consent",
    "/oauth2/authorize",
    "/gnap/approve/",
    "/callback",
    "/login",
    "/live-status",
)


class Driver:
    def __init__(self, client, sts_origin, demo_origin, username, password):
        self.client = client
        self.sts_origin = sts_origin.rstrip("/")
        self.demo_origin = demo_origin.rstrip("/")
        self.username = username
        self.password = password

    def sts(self, url):
        return origin_of(url).rstrip("/") == self.sts_origin

    def label(self, url):
        """A constant naming where a request went, never text from the URL."""
        where = "iya-sts" if self.sts(url) else "demo" if origin_of(url).rstrip("/") == self.demo_origin else "elsewhere"
        path = path_of(url)
        for known in LOG_PATHS:
            if path.startswith(known):
                return f"{where} {known}"
        return f"{where} (another path)"

    def get(self, url):
        status, headers, payload = self.client.request("GET", url, headers={"accept": "text/html,application/json"})
        print(f"GET {status} {self.label(url)}", flush=True)
        return status, headers, payload

    def post_json(self, url, body, csrf):
        raw = json.dumps(body).encode()
        status, headers, payload = self.client.request("POST", url, body=raw, headers={
            "accept": "application/json",
            "content-type": "application/json",
            "origin": self.sts_origin,
            "x-csrf-token": csrf,
        })
        print(f"POST {status} {self.label(url)}", flush=True)
        return status, headers, payload

    def open_view(self, shell_url, api_url):
        status, headers, payload = self.get(shell_url)
        if status in (301, 302, 303, 307, 308):
            return {"redirect": resolve_url(shell_url, one_header(headers, "location"))}
        view_status, _headers, view_payload = self.client.request("GET", api_url, headers={"accept": "application/json"})
        print(f"GET {view_status} {self.label(api_url)}", flush=True)
        parsed = json_body(view_payload) or {}
        if view_status in (301, 302, 303, 307, 308):
            return {"redirect": resolve_url(api_url, one_header(_headers, "location"))}
        if not parsed.get("csrf"):
            snippet = (view_payload or payload or b"")[:400].decode("utf-8", "replace")
            raise RuntimeError(f"{self.label(api_url)} answered {view_status} without a csrf token: {snippet}")
        return {"view": parsed.get("view") or {}, "csrf": parsed["csrf"], "json": parsed}

    def act(self, url):
        """One sign-in step. Returns the next absolute URL, or None when the demo has the browser."""
        status, headers, payload = self.get(url)
        if status in (301, 302, 303, 307, 308):
            return resolve_url(url, one_header(headers, "location"))
        path = path_of(url)
        query = query_of(url)
        if self.sts(url) and path.startswith("/authn/login"):
            pending = (query.get("authn") or [""])[0]
            opened = self.open_view(url, f"{self.sts_origin}/authn-api/pending/{urllib.parse.quote(pending)}")
            if opened.get("redirect"):
                return opened["redirect"]
            posted, post_headers, post_body = self.post_json(
                f"{self.sts_origin}/authn-api/pending/{urllib.parse.quote(pending)}/password",
                {"username": self.username, "password": self.password},
                opened["csrf"],
            )
            return self.after_act(url, posted, post_headers, post_body)
        if self.sts(url) and path.startswith("/oauth2/consent"):
            pending = (query.get("consent") or [""])[0]
            opened = self.open_view(url, f"{self.sts_origin}/authn-api/consent/{urllib.parse.quote(pending)}")
            if opened.get("redirect"):
                return opened["redirect"]
            posted, post_headers, post_body = self.post_json(
                f"{self.sts_origin}/authn-api/consent/{urllib.parse.quote(pending)}",
                {"action": "allow"},
                opened["csrf"],
            )
            return self.after_act(url, posted, post_headers, post_body)
        if self.sts(url) and (path.startswith("/authn/mfa-setup") or path.startswith("/authn/post-login")):
            return self.skip_step(url, path)
        if self.sts(url) and path.startswith("/gnap/approve/"):
            return self.approve_gnap(url)
        form = autopost_form(payload) if status == 200 else None
        if form:
            action = resolve_url(url, form["action"])
            encoded = urllib.parse.urlencode(form["fields"]).encode()
            posted, post_headers, _post_body = self.client.request("POST", action, body=encoded, headers={
                "content-type": "application/x-www-form-urlencoded",
                "origin": origin_of(url),
            })
            print(f"POST {posted} {self.label(action)}", flush=True)
            if posted in (301, 302, 303, 307, 308):
                return resolve_url(action, one_header(post_headers, "location"))
            if origin_of(action).rstrip("/") == self.demo_origin:
                return None
            raise RuntimeError(f"the auto-posted form stayed at {self.label(action)} ({posted})")
        if origin_of(url).rstrip("/") == self.demo_origin and status < 400:
            return None
        snippet = payload[:500].decode("utf-8", "replace")
        raise RuntimeError(f"the sign-in stopped at {status} {self.label(url)}: {snippet}")

    def after_act(self, url, status, headers, payload):
        parsed = json_body(payload) or {}
        if status in (301, 302, 303, 307, 308):
            return resolve_url(url, one_header(headers, "location"))
        if parsed.get("location"):
            nxt = parsed.get("next")
            step = parsed.get("step")
            location = resolve_url(self.sts_origin + "/", parsed["location"])
            if nxt == "mfa" and step == "enrol":
                return self.skip_step(location, path_of(location))
            return location
        if parsed.get("ok") is False:
            raise RuntimeError(f"the sign-in act was refused: {json.dumps(parsed)[:500]}")
        snippet = payload[:500].decode("utf-8", "replace")
        raise RuntimeError(f"the sign-in act answered {status} without a location: {snippet}")

    def skip_step(self, url, path):
        query = query_of(url)
        pending = (query.get("mfa") or query.get("authn") or [""])[0]
        if not pending:
            parts = [part for part in path.split("/") if part]
            pending = parts[-1] if parts else ""
        page = "post-login" if path.startswith("/authn/post-login") else "setup"
        operation = "post-login/skip" if page == "post-login" else "skip"
        opened = self.open_view(url, f"{self.sts_origin}/authn-api/mfa/{urllib.parse.quote(pending)}?page={page}")
        if opened.get("redirect"):
            return opened["redirect"]
        view = opened["view"]
        optional = page == "post-login" or (isinstance(view.get("setup"), dict) and view["setup"].get("optional"))
        if not optional:
            raise RuntimeError(f"a required step is in the way at {self.label(url)}")
        posted, post_headers, post_body = self.post_json(
            f"{self.sts_origin}/authn-api/mfa/{urllib.parse.quote(pending)}/{operation}",
            {},
            opened["csrf"],
        )
        return self.after_act(url, posted, post_headers, post_body)

    def approve_gnap(self, url):
        approval_id = path_of(url).rstrip("/").split("/")[-1]
        opened = self.open_view(url, f"{self.sts_origin}/gnap-api/approve/{urllib.parse.quote(approval_id)}")
        if opened.get("redirect"):
            return opened["redirect"]
        view = opened["view"]
        rights = []
        for token in view.get("tokens") or []:
            for right in token.get("rights") or []:
                if right.get("field"):
                    rights.append(right["field"])
        body = {"action": "allow", "right": rights}
        if view.get("subject"):
            body["subject"] = "yes"
        posted, post_headers, post_body = self.post_json(
            f"{self.sts_origin}/gnap-api/approve/{urllib.parse.quote(approval_id)}",
            body,
            opened["csrf"],
        )
        return self.after_act(url, posted, post_headers, post_body)

    def sign_in(self):
        url = self.demo_origin + PROFILE["login_path"]
        for _hop in range(24):
            nxt = self.act(url)
            if not nxt:
                return
            url = nxt
        raise RuntimeError(f"the sign-in did not finish; last at {self.label(url)}")

    def status(self):
        status, _headers, payload = self.client.request(
            "GET", self.demo_origin + PROFILE["status_path"], headers={"accept": "application/json"}
        )
        parsed = json_body(payload)
        if status != 200 or not isinstance(parsed, dict):
            raise RuntimeError(f"/live-status answered {status}: {payload[:300]!r}")
        return parsed


def mint_admin(client, sts_origin, secret):
    raw = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "scope": "admin:read admin:write",
        "resource": sts_origin + "/admin-api",
    }).encode()
    token = base64.b64encode(f"sts-api-client:{secret}".encode()).decode()
    status, _headers, payload = client.request("POST", sts_origin + "/oauth2/token", body=raw, headers={
        "content-type": "application/x-www-form-urlencoded",
        "authorization": f"Basic {token}",
        "accept": "application/json",
    })
    parsed = json_body(payload) or {}
    if status != 200 or not isinstance(parsed.get("access_token"), str):
        raise RuntimeError(f"the admin token request answered {status}: {json.dumps(parsed)[:300]}")
    return parsed["access_token"]


def admin_json(client, sts_origin, token, method, path, body=None):
    headers = {"accept": "application/json", "authorization": f"Bearer {token}"}
    raw = None
    if body is not None:
        raw = json.dumps(body).encode()
        headers["content-type"] = "application/json"
    status, _headers, payload = client.request(method, sts_origin + path, body=raw, headers=headers)
    parsed = json_body(payload)
    if parsed is None:
        raise RuntimeError(f"{method} {path} answered {status} with non-JSON: {payload[:300]!r}")
    return status, parsed


def session_id_for(client, sts_origin, token, username):
    deadline = time.time() + 20
    while time.time() < deadline:
        _status, parsed = admin_json(client, sts_origin, token, "GET", "/admin-api/caep")
        sessions = parsed.get("sessions") or []
        for row in sessions:
            if str(row.get("username") or "") == username and str(row.get("state") or "") != "revoked":
                found = row.get("sessionId")
                if found:
                    return str(found)
        time.sleep(1)
    raise RuntimeError(f"no CAEP session for {username}: {json.dumps(sessions)[:500]}")


def emit(client, sts_origin, token, session_id, event_type):
    status, parsed = admin_json(client, sts_origin, token, "POST", "/admin-api/caep/emit", {
        "session_id": session_id,
        "type": event_type,
        "initiating_entity": "admin",
    })
    if status != 200 or parsed.get("ok") is False:
        raise RuntimeError(f"emitting {event_type} answered {status}: {json.dumps(parsed)[:500]}")
    message = str(parsed.get("message") or "")
    if "Nothing was sent" in message:
        raise RuntimeError(f"emitting {event_type} reached no stream: {message}")
    print(f"emitted {event_type}: {message or json.dumps(parsed)[:200]}", flush=True)


def wait_for(driver, predicate, what):
    deadline = time.time() + 30
    last = None
    while time.time() < deadline:
        last = driver.status()
        if predicate(last):
            return last
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {what}: {json.dumps(last)[:600]}")


# The embedded PEP (#46). Names are fixed: the iya-sts is always a fresh one.
PEP_NAME = "pep-oidc-demo"
PEP_KEY = "generated/pep-key.pem"  # relative to demo/; .dockerignore keeps it out of the image
PEP_LOCAL_CONFIG = "oidc.pep-local.json"
PEP_ROOT = "pep-demo-orders"
PEP_LOCKED = "pep-demo-orders-locked"
PEP_EVENT = "urn:iya:sts:secevent:event-type:pep-policies-changed"
ACR_ATTRIBUTE = "urn:example:acr"


def orders_policy(namespace, read_effect):
    """ALFA for the demo's application: read on an order is `read_effect`, and
    anything else is denied. `read_effect` permit also needs the subject's acr,
    which only the catalogue row brings, so a Permit shows the claim arrived."""
    condition = "            condition integerGreaterThan(stringBagSize(acr), 0)\n" if read_effect == "permit" else ""
    return (
        f"namespace {namespace} {{\n"
        '    attribute act { category = actionCat\n'
        '        id = "urn:oasis:names:tc:xacml:1.0:action:action-id" type = string }\n'
        '    attribute rtype { category = resourceCat\n'
        '        id = "urn:sts:xacml:authzen:resource-type" type = string }\n'
        f'    attribute acr {{ category = subjectCat id = "{ACR_ATTRIBUTE}" type = string }}\n'
        f"    policy {namespace}Orders {{\n"
        f'        id = "urn:example:{namespace}-orders"\n'
        "        apply firstApplicable\n"
        "        rule readOrder {\n"
        f"            {read_effect}\n"
        '            target clause act == "read"\n'
        '            target clause rtype == "order"\n'
        f"{condition}"
        "        }\n"
        "        rule otherwise {\n"
        "            deny\n"
        "        }\n"
        "    }\n"
        "}\n"
    )


def admin_ok(client, sts_origin, token, path, body, what):
    status, parsed = admin_json(client, sts_origin, token, "POST", path, body)
    if status != 200 or parsed.get("ok") is False:
        raise RuntimeError(f"{what}: POST {path} answered {status}: {json.dumps(parsed)[:500]}")
    print(f"{what}: {status}", flush=True)
    return parsed


def make_pep_key(key_file, work):
    """A P-256 key made here, 0600, and its certificate request. Neither the
    key nor its path is printed; only the request leaves this machine."""
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
        raise RuntimeError("openssl could not make the PEP's key")
    os.chmod(key_file, 0o600)
    csr = work / "pep-key.csr"
    asked = subprocess.run(
        ["openssl", "req", "-new", "-key", str(key_file), "-subj", f"/CN={PEP_NAME}", "-out", str(csr)],
        check=False, capture_output=True, text=True,
    )
    if asked.returncode != 0:
        raise RuntimeError("openssl could not make the PEP's certificate request")
    print("generated the PEP's P-256 key (0600, in demo/generated) and its certificate request", flush=True)
    return csr.read_text(encoding="utf-8")


def provision_pep(client, sts_origin, token, application, key_file, work):
    """docs/remote-pep.md's steps 2 to 5, through /admin-api."""
    admin_ok(client, sts_origin, token, "/admin-api/users/create", {
        "username": PEP_NAME, "invent": False, "credential": "none", "serviceAccount": True,
        "owners": ["admin-write"], "attributes": {"cn": PEP_NAME, "displayName": PEP_NAME},
    }, f"step 2: the service account {PEP_NAME}")
    admin_ok(client, sts_origin, token, "/admin-api/groups/add-member",
             {"group": "remote-peps", "member": PEP_NAME}, "step 2: in remote-peps")
    csr = make_pep_key(key_file, work)
    issued = admin_ok(client, sts_origin, token, "/admin-api/xacml/issue-pep-credential",
                      {"name": PEP_NAME, "csr": csr, "application": application},
                      f"step 3: issue-pep-credential, bound to {application}")
    admin_ok(client, sts_origin, token, "/admin-api/xacml/authzen/set-attribute",
             {"object": "subject", "property": "acr", "attributeId": ACR_ATTRIBUTE},
             "step 4: the catalogue row subject.acr")
    admin_ok(client, sts_origin, token, "/admin-api/xacml/import-alfa",
             {"name": PEP_ROOT, "alfa": orders_policy("pepdemo", "permit")},
             "step 5: the policy permitting read on order")
    admin_ok(client, sts_origin, token, "/admin-api/xacml/set-root", {"name": PEP_ROOT},
             "step 5: made it the realm root")
    return issued.get("application") or application


def flip_policy(client, sts_origin, token):
    """The realm root moves to a policy that denies read too."""
    admin_ok(client, sts_origin, token, "/admin-api/xacml/import-alfa",
             {"name": PEP_LOCKED, "alfa": orders_policy("pepdemolocked", "deny")},
             "the policy denying read on order")
    admin_ok(client, sts_origin, token, "/admin-api/xacml/set-root", {"name": PEP_LOCKED},
             "made it the realm root")


def add_pep_sections(config, mode_files):
    """demo/oidc.json gets a central pep section, and a copy a local one."""
    raw = json.loads(config.read_text(encoding="utf-8"))
    for mode, dest in mode_files.items():
        raw["pep"] = {"name": PEP_NAME, "mode": mode, "assertionKey": "demo/" + PEP_KEY}
        dest.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")


def order(driver, method):
    url = driver.demo_origin + "/orders/42"
    status, _headers, payload = driver.client.request(method, url, body=b"" if method == "POST" else None,
                                                      headers={"accept": "text/html"})
    print(f"{method} {status} demo /orders/42", flush=True)
    return status, payload


def pep_state(driver):
    row = driver.status().get("pep") or {}
    return row


def pep_checks(driver, mode):
    """GET is read (Permit, 200) and POST is write (Deny, 403)."""
    deadline = time.time() + 60
    state = {}
    while time.time() < deadline:
        state = pep_state(driver)
        if state.get("registered") and (mode == "central" or state.get("holdsPolicy")):
            break
        time.sleep(1)
    else:
        raise RuntimeError(f"the {mode} PEP did not get ready: {json.dumps(state)[:600]}")
    read_status, read_body = order(driver, "GET")
    write_status, write_body = order(driver, "POST")
    checks = {
        "mode": state.get("mode"),
        "registered": bool(state.get("registered")),
        "readIs200": read_status == 200,
        "writeIs403": write_status == 403,
    }
    if mode == "local":
        checks["policyCount"] = state.get("policyCount")
    if read_status != 200 or write_status != 403:
        why = (read_body if read_status != 200 else write_body)[:400].decode("utf-8", "replace")
        raise RuntimeError(f"{mode}: GET /orders/42 answered {read_status}, POST {write_status}: {why}; pep {json.dumps(pep_state(driver))[:600]}")
    return checks


def flip_check(driver, client, sts_origin, token):
    """In local mode: the root moves to deny read, and the PEP hears of it."""
    before = pep_state(driver)
    events_before = sum(1 for item in driver.status().get("events") or [] if item.get("type") == PEP_EVENT)
    flipped_at = time.time()
    flip_policy(client, sts_origin, token)
    limit = float(os.environ.get("PEP_FLIP_TIMEOUT") or 30)
    status = None
    while time.time() - flipped_at < limit:
        status, _body = order(driver, "GET")
        if status == 403:
            break
        time.sleep(1)
    after = driver.status()
    state = after.get("pep") or {}
    events = sum(1 for item in after.get("events") or [] if item.get("type") == PEP_EVENT)
    result = {
        "readIs403AfterFlip": status == 403,
        "seconds": round(time.time() - flipped_at, 1),
        "eventReceived": events > events_before,
        "eventsOnStream": events - events_before,
        "syncTokenMoved": bool(state.get("syncToken")) and state.get("syncToken") != before.get("syncToken"),
    }
    # The fallback poll is left at its 300 s default, so a change applied
    # within the bound, with the event received, came through the event.
    result["via"] = "event" if result["eventReceived"] and result["readIs403AfterFlip"] and result["seconds"] < 300 else "poll"
    if status != 403 or result["via"] != "event":
        raise RuntimeError(f"local: after the flip {json.dumps(result)}; pep {json.dumps(state)[:600]}")
    return result


def prepare_sts(sts_port, secret):
    given = os.environ.get("IYA_STS_URL", "").rstrip("/")
    if given:
        print(f"using {given}", flush=True)
        return given, None
    if sts_port in FORBIDDEN_PORTS:
        raise SystemExit(f"refusing to bind port {sts_port}")
    image = os.environ.get("IYA_STS_IMAGE", "")
    source = os.environ.get("IYA_STS_SRC", "")
    cloned = None
    if not image:
        if not source:
            cloned = tempfile.mkdtemp(prefix="iya-sts-main-")
            run(["git", "clone", "--depth", "1", "--branch", "main", STS_REPO, cloned])
            run(["git", "-C", cloned, "submodule", "update", "--init", "--recursive"])
            source = cloned
        image = "iya-sts-live:main"
        docker("build", "-t", image, source)
    name = "iya-sts-live-" + PROFILE["repo"]
    docker_rm(name)
    docker(
        "run", "-d", "--name", name,
        "-p", f"127.0.0.1:{sts_port}:{sts_port}",
        "-e", f"STS_PORT={sts_port}",
        "-e", "STS_PERSISTENCE_MODE=memory",
        "-e", "STS_CLUSTER_MODE=off",
        "-e", "STS_WORKERS_REQUEST_COUNT=0",
        "-e", "STS_WORKERS_SURFACE_COUNT=0",
        "-e", "STS_ADMIN_API_CLIENT_SECRET",
        "-e", "STS_LOG_LEVEL=info",
        image,
    )
    return f"https://127.0.0.1:{sts_port}", name


def configure_demo(config, sts_origin, demo_origin, username, password, secret):
    env = os.environ.copy()
    env["ADMIN_API_CLIENT_SECRET"] = secret
    env["STS_ADMIN_API_CLIENT_SECRET"] = secret
    env[PROFILE["password_env"]] = password
    env["PUBLIC_URL"] = demo_origin
    completed = run(
        [
            *PROFILE["configure"],
            "--config", str(config),
            "--idp", sts_origin,
            "--public-url", demo_origin,
            "--test-user", username,
        ],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
    )
    if completed.stdout:
        print(completed.stdout, flush=True)
    if completed.stderr:
        print(completed.stderr, file=sys.stderr, flush=True)


def start_demo(image, demo_name, demo_port, demo_origin, mounts, env=None):
    """A fresh demo container, with only `mounts` (file by file, read-only)."""
    docker_rm(demo_name)
    args = ["run", "-d", "--name", demo_name, "--network", "host"]
    for source, target in mounts:
        args += ["-v", f"{source}:{target}:ro"]
    args += ["-e", f"PORT={demo_port}", "-e", f"PUBLIC_URL={demo_origin}", "-e", "TLS_CA_REFRESH=0"]
    for name, value in (env or {}).items():
        args += ["-e", f"{name}={value}"]
    docker(*args, image)
    deadline = time.time() + 90
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", demo_port, timeout=3)
            conn.request("GET", "/healthz")
            response = conn.getresponse()
            body = response.read()
            conn.close()
            if response.status == 200 and body == b"ok":
                return
        except OSError:
            pass
        time.sleep(1)
    logs = subprocess.run(["docker", "logs", demo_name], check=False, text=True, capture_output=True)
    if logs.stdout:
        print(logs.stdout, flush=True)
    if logs.stderr:
        print(logs.stderr, file=sys.stderr, flush=True)
    raise RuntimeError("the demo /healthz did not answer ok")


def main():
    pep = "--pep" in sys.argv[1:] or os.environ.get("LIVE_PEP", "") in ("1", "true", "yes")
    sts_port = int(os.environ.get("LIVE_STS_PORT") or 18516)
    demo_port = int(os.environ.get("LIVE_DEMO_PORT") or 18616)
    sts_given = bool(os.environ.get("IYA_STS_URL", "").strip())
    bound = [demo_port] if sts_given else [sts_port, demo_port]
    if any(port in FORBIDDEN_PORTS for port in bound) or len(set(bound)) != len(bound):
        raise SystemExit("LIVE_STS_PORT and LIVE_DEMO_PORT must not bind 3000, 8081, or 18481 through 18495")
    secret = os.environ.get("ADMIN_API_CLIENT_SECRET") or os.environ.get("STS_ADMIN_API_CLIENT_SECRET") or secrets.token_urlsafe(24)
    password = os.environ.get(PROFILE["password_env"]) or secrets.token_urlsafe(18)
    username = PROFILE["test_user"]
    # Secrets reach docker and the install script as -e NAME and through this
    # environment, never on a printed command line.
    os.environ["ADMIN_API_CLIENT_SECRET"] = secret
    os.environ["STS_ADMIN_API_CLIENT_SECRET"] = secret
    os.environ[PROFILE["password_env"]] = password
    sts_origin, sts_name = prepare_sts(sts_port, secret)
    demo_origin = f"http://127.0.0.1:{demo_port}"
    demo_name = PROFILE["repo"] + "-live-demo"
    image = PROFILE["repo"] + "-live:demo"
    work = Path(tempfile.mkdtemp(prefix=PROFILE["repo"] + "-live-"))
    try:
        wait_port(urllib.parse.urlsplit(sts_origin).port or 443, 120)
        wait_ready(sts_origin, 90)
        context = work / "context"
        copy_context(context)
        config = context / PROFILE["config_file"]
        rewrite_config(config, config, sts_origin, demo_origin)
        tls_ca = json.loads(config.read_text(encoding="utf-8")).get("tlsCa")
        ca_file = config.parent / tls_ca
        # The install script first: it writes the client secret and tlsCa's file.
        configure_demo(config, sts_origin, demo_origin, username, password, secret)
        if "BEGIN CERTIFICATE" not in (ca_file.read_text(encoding="utf-8") if ca_file.exists() else ""):
            raise RuntimeError(f"the install script did not write tlsCa's file {tls_ca}")
        pep_key = config.parent / PEP_KEY
        pep_result = {}
        if pep:
            # The PEP is provisioned once the application exists, and before the
            # image: the pep sections go into the image, the key never does.
            admin_client = Client(ca_file)
            token = mint_admin(admin_client, sts_origin, secret)
            written = json.loads(config.read_text(encoding="utf-8"))
            client_id = written.get("clientId") or written.get("client_id")
            pep_result["application"] = provision_pep(admin_client, sts_origin, token, client_id, pep_key, work)
            pep_result["name"] = PEP_NAME
            add_pep_sections(config, {"central": config, "local": config.parent / PEP_LOCAL_CONFIG})
        # THEN the demo image, which carries the chain from build time.
        docker("build", "-t", image, str(context))
        baked = docker("run", "--rm", "--entrypoint", "cat", image, f"/app/demo/{tls_ca}", capture_output=True).stdout
        if baked != ca_file.read_text(encoding="utf-8"):
            raise RuntimeError(f"the demo image's /app/demo/{tls_ca} is not the chain the install script saved")
        chain_count = baked.count("BEGIN CERTIFICATE")
        listed = docker("run", "--rm", "--entrypoint", "ls", image, "-A", "/app/demo/generated", capture_output=True).stdout.split()
        if listed != [Path(tls_ca).name]:
            raise RuntimeError(f"the demo image's /app/demo/generated holds {listed}, not only the trust chain")
        print(f"the demo image carries the {chain_count}-certificate chain at /app/demo/{tls_ca}", flush=True)
        secret_file = config.parent / "generated" / "client-secret"
        mounts = [(secret_file, "/app/demo/generated/client-secret")]
        if pep:
            mounts.append((pep_key, "/app/demo/" + PEP_KEY))
        start_demo(image, demo_name, demo_port, demo_origin, mounts)
        client = Client(ca_file)
        driver = Driver(client, sts_origin, demo_origin, username, password)
        driver.sign_in()
        signed_in = wait_for(
            driver,
            lambda row: row.get("signedIn") is True and "polling" in str(row.get("receiver") or ""),
            "a signed-in demo polling its stream",
        )
        print(f"signed in as {signed_in.get('subject')}; {signed_in.get('receiver')}", flush=True)
        if pep:
            central = pep_checks(driver, "central")
        token = mint_admin(client, sts_origin, secret)
        session_id = session_id_for(client, sts_origin, token, username)
        emit(client, sts_origin, token, session_id, "credential-change")
        wait_for(
            driver,
            lambda row: row.get("signedIn") is True and any(
                item.get("type") == CREDENTIAL_CHANGE for item in row.get("events") or []
            ),
            "credential-change while still signed in",
        )
        emit(client, sts_origin, token, session_id, "session-revoked")
        finished = wait_for(
            driver,
            lambda row: row.get("signedIn") is False and any(
                item.get("type") == SESSION_REVOKED for item in row.get("events") or []
            ),
            "session-revoked to end the local session",
        )
        result = {
            "ok": True,
            "subject": signed_in.get("subject"),
            "tlsCaInImage": chain_count,
            "events": finished.get("events"),
        }
        if pep:
            pep_result["central"] = central
            # THEN local: the same image and iya-sts, the copy with mode local.
            start_demo(image, demo_name, demo_port, demo_origin, mounts,
                       env={"OIDC_CONFIG": "/app/demo/" + PEP_LOCAL_CONFIG})
            local_driver = Driver(Client(ca_file), sts_origin, demo_origin, username, password)
            local_driver.sign_in()
            wait_for(local_driver, lambda row: row.get("signedIn") is True and "polling" in str(row.get("receiver") or ""),
                     "a signed-in local-mode demo polling its stream")
            local = pep_checks(local_driver, "local")
            token = mint_admin(client, sts_origin, secret)
            local["policyChange"] = flip_check(local_driver, client, sts_origin, token)
            pep_result["local"] = local
            result["pep"] = pep_result
        print(json.dumps(result, indent=2))
    finally:
        if os.environ.get("LIVE_KEEP", "") == "1":
            # For a failure's post-mortem: both containers stay. The next run
            # removes them before it starts its own.
            print(f"LIVE_KEEP=1: left {demo_name} and {sts_name or 'the given iya-sts'} running", flush=True)
        else:
            docker_rm(demo_name)
            if sts_name:
                docker_rm(sts_name)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)
