#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The AuthZEN differential (#46): central and local must always agree.

`python3 scripts/live_iya_sts.py --authzen` (or this file directly). Against a
fresh iya-sts (IYA_STS_IMAGE, or main built as live_iya_sts.py builds it) it
provisions what src/tests/authzen_cases.json describes, through /admin-api:

* each application of the table (`authzen-docs`, decided by the realm root,
  and `authzen-ledger`, which enforces fine-grained authorization);
* the table's directory users, for the PIP;
* TWO embedded PEPs per application, one `central` and one `local`, each a
  service account in remote-peps with its own P-256 key, made here with the
  host's openssl (0600, never printed), certified and bound with
  issue-pep-credential;
* the table's catalogue rows (xacml/authzen/set-attribute) and policies
  (import-alfa; a PolicyIdReference is added with the editor, because this
  ALFA dialect has none), the root, the ledger's own policy, and fga-enable.

THEN it runs the ignored Rust test `authzen_test::live_central_equals_local`
in rust:1-bookworm on the host network (`-v iya-pep-cargo:/cargo`, never
Cargo on the host). That test builds a RelyingParty per PEP, waits for each
local PEP to hold its policy, runs EVERY case through both modes, and fails
once, listing each case where central != local or either != the table.

The Rust test prints one line `AUTHZEN-RESULT <json>`; this script prints that
JSON last and exits non-zero when it has mismatches. AUTHZEN_XACML_OUT=<file>
also saves the documents iya-sts stored for the table's policies (the table's
`xacml`, which the offline run serves). LIVE_STS_PORT defaults to 18526 here;
3000, 8081 and 18481 through 18495 are refused. LIVE_KEEP=1 keeps iya-sts.
No secret, key or path derived from one is printed.
"""

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

import live_iya_sts as live
import trust_chain

ROOT = live.ROOT
TABLE = ROOT / "src" / "tests" / "authzen_cases.json"
CONTAINER = "iya-sts-live-" + live.PROFILE["repo"] + "-authzen"
TARGET_VOLUME = live.PROFILE["repo"] + "-authzen-target"
MODES = ("central", "local")


def pep_name(app, mode):
    return f"pep-az-{app}-{mode}"


def admin(client, origin, token, path, body, what, ok_if=None):
    status, parsed = live.admin_json(client, origin, token, "POST", path, body)
    if status != 200 or parsed.get("ok") is False:
        text = json.dumps(parsed)
        if ok_if and ok_if in text:
            print(f"{what}: already so", flush=True)
            return parsed
        raise RuntimeError(f"{what}: POST {path} answered {status}: {text[:600]}")
    print(f"{what}: {status}", flush=True)
    return parsed


def make_key(directory, name):
    """A P-256 key (0600) and its certificate request; only the request leaves."""
    key = directory / f"{name}.pem"
    old = os.umask(0o077)
    try:
        made = subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key)],
                              check=False, capture_output=True, text=True)
    finally:
        os.umask(old)
    if made.returncode != 0:
        raise RuntimeError(f"openssl could not make {name}'s key")
    os.chmod(key, 0o600)
    asked = subprocess.run(["openssl", "req", "-new", "-key", str(key), "-subj", f"/CN={name}"],
                           check=False, capture_output=True, text=True)
    if asked.returncode != 0:
        raise RuntimeError(f"openssl could not make {name}'s certificate request")
    return key, asked.stdout


def fga_policy(client, origin, token, application):
    """The entry name and PolicyId of an application's own policy."""
    status, parsed = live.admin_json(client, origin, token, "GET", "/admin-api/applications?application=" + urllib.parse.quote(application))
    fga = ((parsed.get("page") or {}).get("fga") or {}) if status == 200 else {}
    policy = fga.get("policy") or {}
    return policy.get("name") or "", policy.get("policyId") or ""


def provision(client, origin, token, table, keys):
    plan = {"apps": {}}
    for key, app in table["applications"].items():
        admin(client, origin, token, "/admin-api/applications/create",
              {"identifier": app["identifier"], "name": "AuthZEN " + key, "protocols": ["oauth2"]},
              f"the application {app['identifier']}")
    for user in table["users"]:
        admin(client, origin, token, "/admin-api/users/create",
              {"username": user["username"], "invent": False, "credential": "none", "attributes": user["attributes"]},
              f"the directory user {user['username']}")
    for key, app in table["applications"].items():
        entry = {"application": app["identifier"]}
        for mode in MODES:
            name = pep_name(key, mode)
            admin(client, origin, token, "/admin-api/users/create", {
                "username": name, "invent": False, "credential": "none", "serviceAccount": True,
                "owners": ["admin-write"], "attributes": {"cn": name, "displayName": name},
            }, f"the service account {name}")
            admin(client, origin, token, "/admin-api/groups/add-member", {"group": "remote-peps", "member": name}, f"{name} in remote-peps")
            key_file, csr = make_key(keys, name)
            admin(client, origin, token, "/admin-api/xacml/issue-pep-credential",
                  {"name": name, "csr": csr, "application": app["identifier"]}, f"issue-pep-credential {name} -> {app['identifier']}")
            entry[mode] = {"name": name, "key": "/plan/keys/" + key_file.name}
        plan["apps"][key] = entry
    for row in table["catalogue"]:
        admin(client, origin, token, "/admin-api/xacml/authzen/set-attribute", row, f"catalogue {row['object']}.{row['property']}")

    names = {}
    for policy in table["policies"]:
        name = policy["name"]
        alfa = "\n".join(policy["alfa"]) + "\n"
        if policy.get("owned"):
            identifier = table["applications"][policy["app"]]["identifier"]
            name, policy_id = fga_policy(client, origin, token, identifier)
            if not name:
                admin(client, origin, token, "/admin-api/applications/fga-create-policy", {"application": identifier}, f"{identifier}'s own policy")
                name, policy_id = fga_policy(client, origin, token, identifier)
            if not name or not policy_id:
                raise RuntimeError(f"{identifier} has no policy of its own to write")
            alfa = alfa.replace("@FGA_POLICY_ID@", policy_id)
        admin(client, origin, token, "/admin-api/xacml/import-alfa", {"name": name, "alfa": alfa}, f"the policy {name}")
        for ref in policy.get("references") or []:
            admin(client, origin, token, "/admin-api/xacml/add-policy-reference", {"policy": name, "path": "", "ref": ref},
                  f"{name} references {ref}")
        if policy.get("root") and not policy.get("owned"):
            admin(client, origin, token, "/admin-api/xacml/set-root", {"name": name}, f"{name} is the realm root")
        names[policy["name"]] = name
    for key, app in table["applications"].items():
        if app.get("fga"):
            admin(client, origin, token, "/admin-api/applications/fga-enable", {"application": app["identifier"]},
                  f"{app['identifier']} enforces fine-grained authorization")
    return plan, names


def stored_documents(client, origin, token, names):
    """The XACML iya-sts stored for each of the table's policies, by table name
    (the editor's view of a policy carries its document)."""
    out = {}
    for table_name, stored in names.items():
        status, parsed = live.admin_json(client, origin, token, "GET", "/admin-api/xacml/editor?policy=" + urllib.parse.quote(stored))
        document = parsed.get("document") if status == 200 and (parsed.get("policy") or {}).get("name") == stored else None
        out[table_name] = document if isinstance(document, str) else None
    return out


def run_rust(work, origin):
    """The ignored Rust test, on the host network, against `plan.json`."""
    command = [
        "docker", "run", "--rm", "--network", "host",
        "-v", f"{ROOT}:/src:ro", "-v", f"{work}:/plan:ro",
        "-v", "iya-pep-cargo:/cargo", "-v", f"{TARGET_VOLUME}:/target",
        "-e", "CARGO_HOME=/cargo", "-e", "CARGO_TARGET_DIR=/target", "-e", "AUTHZEN_LIVE_PLAN=/plan/plan.json",
        "-w", "/src", "rust:1-bookworm",
        "cargo", "test", "--locked", "--features", "local", "--lib", "authzen_test::live_central_equals_local",
        "--", "--ignored", "--nocapture", "--test-threads=1",
    ]
    print("+ " + " ".join(command), flush=True)
    completed = subprocess.run(command, check=False, text=True, capture_output=True)
    out = completed.stdout + "\n" + completed.stderr
    print(out[-12000:], flush=True)
    found = re.findall(r"AUTHZEN-RESULT (\{.*\})$", out, re.M)
    if not found:
        raise RuntimeError(f"the Rust test printed no result (exit {completed.returncode})")
    return json.loads(found[-1]), completed.returncode


def main():
    sts_port = int(os.environ.get("LIVE_STS_PORT") or 18526)
    if not os.environ.get("IYA_STS_URL") and sts_port in live.FORBIDDEN_PORTS:
        raise SystemExit("LIVE_STS_PORT must not be 3000, 8081, or 18481 through 18495")
    secret = os.environ.get("ADMIN_API_CLIENT_SECRET") or os.environ.get("STS_ADMIN_API_CLIENT_SECRET") or secrets.token_urlsafe(24)
    os.environ["ADMIN_API_CLIENT_SECRET"] = secret
    os.environ["STS_ADMIN_API_CLIENT_SECRET"] = secret
    table = json.loads(TABLE.read_text(encoding="utf-8"))
    origin, started = live.prepare_sts(sts_port, secret, CONTAINER)
    work = Path(tempfile.mkdtemp(prefix=live.PROFILE["repo"] + "-authzen-"))
    try:
        live.wait_port(urllib.parse.urlsplit(origin).port or 443, 120)
        live.wait_ready(origin, 90)
        ca_file = work / "idp-ca.pem"
        trust_chain.save_trust_chain(origin, str(ca_file))
        client = live.Client(ca_file)
        token = live.mint_admin(client, origin, secret)
        keys = work / "keys"
        keys.mkdir(mode=0o700)
        plan, names = provision(client, origin, token, table, keys)
        documents = stored_documents(client, origin, token, names)
        out = os.environ.get("AUTHZEN_XACML_OUT")
        if out:
            Path(out).write_text(json.dumps(documents, indent=2) + "\n", encoding="utf-8")
            print(f"saved the stored XACML of {sum(1 for d in documents.values() if d)} policies", flush=True)
        # The table's `xacml` is what the offline run serves; say when iya-sts
        # now stores something else for the same ALFA.
        held = {p["name"]: "\n".join(p.get("xacml") or []) for p in table["policies"]}
        drift = [name for name, doc in documents.items() if doc is None or "".join(held.get(name, "").split()) != "".join(doc.split())]
        plan.update({"metadataUrl": origin + "/.well-known/openid-configuration", "tlsCa": "/plan/idp-ca.pem",
                     "supportedObligations": table.get("supportedObligations") or []})
        (work / "plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        os.chmod(work, 0o755)
        result, code = run_rust(work, origin)
        result["xacmlDriftFromTable"] = drift
        print(json.dumps(result, indent=2))
        if code != 0 or result.get("mismatches"):
            sys.exit(1)
    finally:
        if os.environ.get("LIVE_KEEP", "") == "1":
            print(f"LIVE_KEEP=1: left {started or 'the given iya-sts'} running", flush=True)
        elif started:
            live.docker_rm(started)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)
