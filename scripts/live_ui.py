#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The demo's two PEP-protected pages in a real browser (#46).

`python3 scripts/live_ui.py` (or `live_iya_sts.py --ui`, or LIVE_UI=1).
It provisions exactly as live_iya_sts.py does (its `provisioned()`): a FRESH
iya-sts container (IYA_STS_IMAGE, here `iya-sts-live-oidc-caep-risc-rust-ui`
on LIVE_STS_PORT, default 18536), the install script run as a user runs it
with `--pep local`, the install script's test user (attr1=abc123) and a
second user with attr1=not-abc123, the demo image built from a scratch copy
of this checkout, and the demo (`oidc-caep-risc-rust-live-ui-demo`, on
LIVE_DEMO_PORT, default 18636). 3000, 8081 and 18481 through 18495 are
refused.

THEN a headless Chromium in Playwright's image (UI_PLAYWRIGHT_IMAGE, default
mcr.microsoft.com/playwright/python:v1.49.0-noble, --network host; the
playwright package is installed inside that throwaway container, nothing on
the host) runs scripts/ui_browser.py: Sign in, iya-sts's sign-in page, the top
bar's links and the pages typed in, a POST /orders/42 with the browser's
cookies, Sign out from the user menu, then the same as the second user. The
allowed user must get 200 on GET /attribute-protected and GET /orders/42; the
denied user 403 and 200; POST /orders/42 is 403 for both and a signed-out
GET 401. Chromium trusts iya-sts's listener by its key's SPKI hash only
(--ignore-certificate-errors-spki-list, computed here from the chain the
install script saved).

Screenshots go to LIVE_UI_OUT (default a new directory under the system temp
directory, printed). The last thing printed is the JSON summary; the exit
status is non-zero on any mismatch. The passwords reach the browser container
as -e NAME and are never printed. LIVE_KEEP=1 leaves iya-sts and the demo
running. Only the containers this run started are removed, by name.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import live_iya_sts as live

PLAYWRIGHT_IMAGE = os.environ.get("UI_PLAYWRIGHT_IMAGE") or "mcr.microsoft.com/playwright/python:v1.49.0-noble"
PLAYWRIGHT_VERSION = "1.49.0"
STS_CONTAINER = "iya-sts-live-" + live.PROFILE["repo"] + "-ui"
DEMO_CONTAINER = live.PROFILE["repo"] + "-live-ui-demo"
BROWSER_CONTAINER = live.PROFILE["repo"] + "-live-ui-browser"
IMAGE = live.PROFILE["repo"] + "-live:ui"


def leaf_spki(chain_file):
    """base64(sha256(SubjectPublicKeyInfo)) of the chain's first certificate,
    the listener's own, with the host's openssl."""
    pem = Path(chain_file).read_text(encoding="utf-8")
    leaf = pem[:pem.index("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")] + "\n"
    key = subprocess.run(["openssl", "x509", "-pubkey", "-noout"], input=leaf.encode(), capture_output=True, check=True).stdout
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"], input=key, capture_output=True, check=True).stdout
    digest = subprocess.run(["openssl", "dgst", "-sha256", "-binary"], input=der, capture_output=True, check=True).stdout
    return subprocess.run(["base64"], input=digest, capture_output=True, check=True).stdout.decode().strip()


def run_browser(env, out):
    names = {
        "UI_DEMO_ORIGIN": env["demoOrigin"], "UI_STS_ORIGIN": env["stsOrigin"], "UI_OUT": "/out",
        "UI_STS_SPKI": leaf_spki(env["caFile"]),
        "UI_ALLOWED_USER": live.PROFILE["test_user"], "UI_DENIED_USER": live.DENIED_USER,
    }
    child = os.environ.copy()
    child.update(names)
    # The passwords go only into the browser container's environment.
    _secret, allowed_password, denied_password = live.credentials()
    child["UI_ALLOWED_PASSWORD"] = allowed_password
    child["UI_DENIED_PASSWORD"] = denied_password
    owner = f"{os.getuid()}:{os.getgid()}"
    command = ["docker", "run", "--rm", "--name", BROWSER_CONTAINER, "--network", "host",
               "-v", f"{live.ROOT / 'scripts'}:/ui:ro", "-v", f"{out}:/out"]
    for name in [*names, "UI_ALLOWED_PASSWORD", "UI_DENIED_PASSWORD"]:
        command += ["-e", name]
    command += [PLAYWRIGHT_IMAGE, "bash", "-c",
                f"python3 -m pip install -q --disable-pip-version-check --break-system-packages playwright=={PLAYWRIGHT_VERSION}"
                f" && python3 /ui/ui_browser.py; rc=$?; chown -R {owner} /out; exit $rc"]
    live.docker_rm(BROWSER_CONTAINER)
    print("+ " + " ".join(command), flush=True)
    completed = subprocess.run(command, check=False, text=True, capture_output=True, env=child)
    print(completed.stdout[-20000:], flush=True)
    if completed.stderr.strip():
        print(completed.stderr[-4000:], file=sys.stderr, flush=True)
    found = re.findall(r"^UI-RESULT (\{.*\})$", completed.stdout, re.M)
    if not found:
        raise RuntimeError(f"the browser printed no result (exit {completed.returncode})")
    return json.loads(found[-1]), completed.returncode


def main():
    out = Path(os.environ.get("LIVE_UI_OUT") or tempfile.mkdtemp(prefix=live.PROFILE["repo"] + "-ui-" + time.strftime("%Y%m%d-%H%M%S-")))
    out.mkdir(parents=True, exist_ok=True)
    print(f"screenshots go to {out}", flush=True)
    try:
        with live.provisioned(pep="local", sts_container=STS_CONTAINER, demo_name=DEMO_CONTAINER, image=IMAGE,
                              default_ports=(18536, 18636)) as env:
            if (env["pep"] or {}).get("mode") != "local":
                raise RuntimeError(f"the install script did not write a local pep section: {json.dumps(env['pep'])}")
            browser, code = run_browser(env, out)
    finally:
        live.docker_rm(BROWSER_CONTAINER)
    # An explicit summary of named fields, user names from constants: no
    # credential reaches what is printed.
    steps = [row for row in browser.get("steps") or [] if isinstance(row, dict)]
    failed = [row for row in browser.get("failed") or [] if isinstance(row, dict)]
    result = {
        "ok": browser.get("ok") is True and code == 0,
        "pepMode": "local",
        "users": {"allowed": {"user": live.PROFILE["test_user"], live.TEST_ATTRIBUTE: live.TEST_ATTRIBUTE_VALUE},
                  "denied": {"user": live.DENIED_USER, live.TEST_ATTRIBUTE: live.DENIED_VALUE}},
        "screenshotsDir": str(out),
        "checks": int(browser.get("checks") or 0),
        "failed": [{"check": str(row.get("check")), "got": row.get("got") if isinstance(row.get("got"), (int, bool)) else str(row.get("got")),
                    "want": row.get("want") if isinstance(row.get("want"), (int, bool)) else str(row.get("want"))} for row in failed],
        "screenshots": [str(name) for name in browser.get("screenshots") or []],
        "steps": [{"check": str(row.get("check")), "got": row.get("got") if isinstance(row.get("got"), (int, bool)) else str(row.get("got"))} for row in steps],
    }
    print(json.dumps(result, indent=2))
    if not result["ok"]:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)
