#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The browser half of scripts/live_ui.py: run INSIDE Playwright's image
(mcr.microsoft.com/playwright/python), never on the host.

A headless Chromium goes through the demo's real pages as a person does:
the demo's Sign in button, iya-sts's sign-in page (username, password, Sign
in), back to the demo, the top bar's Attribute-protected and Order 42 links
and the same pages typed in, then Sign out from the user menu and the same
again as the second user. Every page's HTTP status is the status of the
document response the browser received (Playwright's response.status), and
its visible <h1> is read from the rendered page. A POST /orders/42 goes
through page.request, which carries the browser's own cookies.

Everything comes from the environment (UI_DEMO_ORIGIN, UI_STS_ORIGIN,
UI_STS_SPKI, UI_OUT, UI_ALLOWED_USER, UI_DENIED_USER and the two passwords,
UI_ALLOWED_PASSWORD and UI_DENIED_PASSWORD, which are typed into the page and
never printed). Screenshots go to UI_OUT. The last line printed is
`UI-RESULT <json>`.
"""

import json
import os
import sys
import time
import urllib.parse

from playwright.sync_api import sync_playwright

DEMO = os.environ["UI_DEMO_ORIGIN"].rstrip("/")
STS = os.environ["UI_STS_ORIGIN"].rstrip("/")
OUT = os.environ.get("UI_OUT", "/out")
STEP_TIMEOUT = 30_000

checks = []
shots = []


def check(name, got, want):
    checks.append({"check": name, "got": got, "want": want, "ok": got == want})
    print(f"{'ok  ' if got == want else 'FAIL'} {name}: {got!r} (want {want!r})", flush=True)


def shot(page, name):
    path = os.path.join(OUT, f"{len(shots) + 1:02d}-{name}.png")
    page.screenshot(path=path, full_page=True)
    shots.append(os.path.basename(path))


def origin(url):
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def where(url):
    """A label for a URL, never its query (it holds sign-in handles)."""
    side = "demo" if origin(url) == DEMO else "iya-sts" if origin(url) == STS else "elsewhere"
    return f"{side} {urllib.parse.urlsplit(url).path}"


def heading(page):
    h1 = page.locator("main h1").first
    return h1.inner_text().strip() if h1.count() else ""


def through_iya_sts(page, user, password, label):
    """From iya-sts's first page back to the demo: the sign-in form (or the
    account chooser), and any consent or optional step on the way."""
    deadline = time.time() + 90
    typed = False
    while time.time() < deadline:
        page.wait_for_load_state("domcontentloaded")
        if origin(page.url) == DEMO:
            return
        path = urllib.parse.urlsplit(page.url).path
        username = page.locator("#username")
        if not typed and username.count() and username.is_visible():
            shot(page, f"{label}-iya-sts-sign-in")
            if username.get_attribute("readonly") is None:
                username.fill(user)
            page.locator("#password").fill(password)
            with page.expect_navigation(timeout=STEP_TIMEOUT):
                page.locator("#kc-login").click()
            typed = True
            continue
        for selector in ("#consent-allow", "#post-login-skip", "button[value=skip]"):
            button = page.locator(selector)
            if button.count() and button.first.is_visible():
                with page.expect_navigation(timeout=STEP_TIMEOUT):
                    button.first.click()
                break
        else:
            # A scripted page still drawing itself, or the account chooser:
            # "another account" opens the sign-in form for a new person.
            other = page.get_by_role("link", name="another account")
            if not typed and other.count() and other.first.is_visible():
                other.first.click()
            time.sleep(0.5)
            continue
        print(f"step at {where(page.url)} ({path})", flush=True)
    raise RuntimeError(f"the sign-in did not return to the demo; last at {where(page.url)}")


def sign_in(page, user, password, label, previous=None):
    """The demo's Sign in button. Signing out of the demo ends only the
    demo's session: iya-sts still knows the browser, so with `previous`
    signed in there the button signs that person back in without a page.
    The second person then does what the demo offers for it: the user menu's
    Sign in with another account (prompt=login), which asks iya-sts who it is."""
    response = page.goto(DEMO + "/")
    check(f"{label}: GET / before sign-in", response.status, 200)
    check(f"{label}: the signed-out page", heading(page), "Sign in with OpenID Connect")
    shot(page, f"{label}-signed-out")
    page.get_by_role("link", name="Sign in with OpenID Connect").click()
    page.wait_for_url(lambda url: origin(url) == STS or origin(url) == DEMO, timeout=STEP_TIMEOUT)
    through_iya_sts(page, user, password, label)
    page.wait_for_load_state("load")
    if previous and heading(page) == f"Signed in as {previous}":
        print(f"{label}: iya-sts signed {previous} back in (its session outlives the demo's); using Sign in with another account", flush=True)
        shot(page, f"{label}-iya-sts-session-kept")
        page.locator(".acct-menu > summary").click()
        page.locator(".acct-menu").get_by_role("menuitem", name="Sign in with another account").click()
        page.wait_for_url(lambda url: origin(url) == STS, timeout=STEP_TIMEOUT)
        through_iya_sts(page, user, password, label)
        page.wait_for_load_state("load")
    check(f"{label}: signed in as", heading(page), f"Signed in as {user}")
    shot(page, f"{label}-signed-in")


def by_link(page, label, link, path, status, title):
    """The top bar's link: the document response's status and the heading."""
    with page.expect_response(lambda r: r.url == DEMO + path and r.request.resource_type == "document") as answered:
        page.locator("header.topbar nav.site-nav").get_by_role("link", name=link).click()
    page.wait_for_load_state("load")
    check(f"{label}: {link} link -> GET {path} status", answered.value.status, status)
    check(f"{label}: {link} link -> heading", heading(page), title)
    shot(page, f"{label}-link-{path.strip('/').replace('/', '-')}")


def by_url(page, label, path, status, title):
    response = page.goto(DEMO + path)
    check(f"{label}: GET {path} status", response.status, status)
    check(f"{label}: GET {path} heading", heading(page), title)
    shot(page, f"{label}-get-{path.strip('/').replace('/', '-')}")


def post_order(page, label, status):
    """POST /orders/42 with the browser's cookies. page.request shares the
    context's cookie jar, but neither it nor context.cookies(url) hands a
    Secure cookie to loopback http the way Chromium itself does, so the
    jar's cookies for the demo's host are sent as the header the browser
    sends."""
    host = urllib.parse.urlsplit(DEMO).hostname
    jar = "; ".join(f"{c['name']}={c['value']}" for c in page.context.cookies()
                    if c["domain"].lstrip(".") == host and "/orders/42".startswith(c["path"]))
    if "oidc_session=" not in jar:
        raise RuntimeError(f"{label}: the browser holds no demo session cookie")
    answered = page.request.post(DEMO + "/orders/42", headers={"accept": "text/html", "cookie": jar})
    body = answered.text()
    start = body.find("<h1>")
    title = body[start + 4:body.find("</h1>", start)] if start >= 0 else ""
    check(f"{label}: POST /orders/42 status", answered.status, status)
    check(f"{label}: POST /orders/42 heading", title, "Not allowed")


def sign_out(page, label):
    page.goto(DEMO + "/")
    page.locator(".acct-menu > summary").click()
    shot(page, f"{label}-user-menu")
    with page.expect_navigation(timeout=STEP_TIMEOUT):
        page.locator(".acct-menu form[action='/logout'] button").click()
    page.wait_for_load_state("load")
    check(f"{label}: after Sign out", heading(page), "Sign in with OpenID Connect")
    response = page.goto(DEMO + "/attribute-protected")
    check(f"{label}: GET /attribute-protected signed out", response.status, 401)
    shot(page, f"{label}-signed-out-401")


def main():
    allowed, denied = os.environ["UI_ALLOWED_USER"], os.environ["UI_DENIED_USER"]
    args = []
    if os.environ.get("UI_STS_SPKI"):
        # Trust iya-sts's own listener key, and nothing else that is not trusted already.
        args.append("--ignore-certificate-errors-spki-list=" + os.environ["UI_STS_SPKI"])
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=args)
        context = browser.new_context(viewport={"width": 1280, "height": 900})
        context.set_default_timeout(STEP_TIMEOUT)
        page = context.new_page()
        try:
            sign_in(page, allowed, os.environ["UI_ALLOWED_PASSWORD"], "allowed")
            by_link(page, "allowed", "Attribute-protected", "/attribute-protected", 200, "Allowed")
            by_link(page, "allowed", "Order 42", "/orders/42", 200, "Order 42")
            by_url(page, "allowed", "/attribute-protected", 200, "Allowed")
            by_url(page, "allowed", "/orders/42", 200, "Order 42")
            post_order(page, "allowed", 403)
            sign_out(page, "allowed")

            sign_in(page, denied, os.environ["UI_DENIED_PASSWORD"], "denied", previous=allowed)
            by_link(page, "denied", "Attribute-protected", "/attribute-protected", 403, "Not allowed")
            by_link(page, "denied", "Order 42", "/orders/42", 200, "Order 42")
            by_url(page, "denied", "/attribute-protected", 403, "Not allowed")
            by_url(page, "denied", "/orders/42", 200, "Order 42")
            post_order(page, "denied", 403)
            sign_out(page, "denied")
        except Exception as err:  # noqa: BLE001 - reported, and the run fails
            checks.append({"check": "the run finished", "got": str(err)[:500], "want": "no error", "ok": False})
            try:
                shot(page, "failure")
            except Exception:  # noqa: BLE001
                pass
        finally:
            browser.close()
    failed = [c for c in checks if not c["ok"]]
    result = {"ok": not failed, "checks": len(checks), "failed": failed, "screenshots": shots,
              "steps": [{"check": c["check"], "got": c["got"]} for c in checks]}
    print("UI-RESULT " + json.dumps(result), flush=True)
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
