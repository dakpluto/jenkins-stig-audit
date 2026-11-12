"""Optional rendered GitLab logout exercise using Playwright and a test account.

Install Playwright/browser separately. No credentials, cookies, screenshots or traces
are saved. Unsupported flows are inconclusive; no MFA/SSO bypass is attempted.
"""
import argparse
from datetime import datetime, timezone
import json
import os
import re
import sys
from urllib.parse import urlsplit


def identity(response):
    try:
        value = response.json()
        return value["id"] if response.status == 200 and isinstance(value, dict) and type(value.get("id")) is int and value["id"] > 0 else None
    except Exception:
        return None


def denied(response):
    try:
        value = response.json()
        if response.status == 401 and "unauthorized" in str(value.get("message", "")).lower():
            return True
        if identity(response) is not None:
            return False
    except Exception:
        pass
    return None


def origin(url):
    value = urlsplit(url)
    return value.scheme, value.hostname, value.port or 443


def exercise(page, replay, base, username, password, reference, menu_selector, logout_selector, message_text):
    observed = dict(tested_at=datetime.now(timezone.utc).isoformat(), test_reference=reference)
    page.goto(base + "/users/sign_in", wait_until="domcontentloaded")
    page.locator("#user_login").fill(username)
    page.locator("#user_password").fill(password)
    page.locator("#new_user [type=submit]").click()
    page.wait_for_load_state("domcontentloaded")
    # Login may finish asynchronously. Poll a bounded number of times without
    # bypassing any additional authentication step or exporting response bodies.
    account = None
    for _ in range(20):
        account = identity(page.request.get(base + "/api/v4/user", max_redirects=0))
        if account is not None:
            break
        page.wait_for_timeout(250)
    if account is None:
        return observed
    observed["authenticated_before"] = True
    page.goto(base + "/-/profile", wait_until="domcontentloaded")
    cookies = page.context.cookies([base])
    cookie_header = "; ".join(item["name"] + "=" + item["value"] for item in cookies)
    if not any(item["name"] == "_gitlab_session" for item in cookies):
        return observed
    if identity(replay.get(base + "/api/v4/user", headers={"Cookie": cookie_header}, max_redirects=0)) != account:
        return observed
    control = page.locator(logout_selector)
    if not control.count() or not control.first.is_visible():
        menu = page.locator(menu_selector)
        if menu.count() and menu.first.is_visible():
            menu.first.click()
    control = page.locator(logout_selector)
    if not control.count() or not control.first.is_visible():
        # A selector miss is not proof the product has no logout control.
        return observed
    observed["visible_usable_control"] = control.first.is_enabled()
    if not observed["visible_usable_control"]:
        return observed
    control.first.click()
    page.wait_for_load_state("domcontentloaded")
    completed = None
    for _ in range(20):
        completed = denied(page.request.get(base + "/api/v4/user", max_redirects=0))
        if completed is not False:
            break
        page.wait_for_timeout(250)
    # A request racing asynchronous logout is not proof that logout is broken.
    observed["user_initiated_logout_completed"] = True if completed is True else None
    if observed["user_initiated_logout_completed"] is not True:
        return observed
    observed["old_session_rejected"] = denied(replay.get(base + "/api/v4/user", headers={"Cookie": cookie_header}, max_redirects=0))
    # Explicit expected localized text must be supplied to conclude absence. A
    # default English heuristic may discover a confirmation, but cannot prove absence.
    matcher = re.compile(re.escape(message_text), re.I) if message_text else re.compile(
        r"you (?:have been|are now) signed out|signed out successfully|you have successfully signed out", re.I)
    messages = page.get_by_text(matcher)
    try:
        messages.first.wait_for(state="visible", timeout=3000)
    except Exception:
        pass
    visible = any(messages.nth(index).is_visible() for index in range(min(messages.count(), 30)))
    observed["explicit_message_visible"] = visible if visible or message_text else None
    return observed


def run(args, username, password):
    base = args.url.rstrip("/")
    parsed = urlsplit(base)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("a credential-free HTTPS base URL is required")
    from playwright.sync_api import sync_playwright
    observed, errors = {}, []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context()  # certificate verification remains enabled
        context.set_default_timeout(15000)
        replay = playwright.request.new_context(timeout=15000)
        allowed_origin = origin(base)
        context.route("**/*", lambda route: route.continue_() if origin(route.request.url) == allowed_origin else route.abort())
        page = context.new_page()
        try:
            observed = exercise(page, replay, base, username, password, args.reference, args.menu_selector,
                                args.logout_selector, args.message_text)
        except Exception as exc:
            errors.append("Rendered logout probe incomplete: " + type(exc).__name__)
        finally:
            # Even unsupported UI flows get a same-origin logout attempt. This
            # is cleanup only and does not count as a successful user UI exercise.
            try:
                if identity(context.request.get(base + "/api/v4/user", max_redirects=0)) is not None:
                    page.goto(base + "/-/profile", wait_until="domcontentloaded")
                    token = page.locator('meta[name="csrf-token"]').get_attribute("content")
                    context.request.post(base + "/users/sign_out", form={"_method": "delete", "authenticity_token": token}, max_redirects=0)
                    if denied(context.request.get(base + "/api/v4/user", max_redirects=0)) is not True:
                        errors.append("Test session cleanup incomplete; revoke dedicated-account test sessions")
            except Exception:
                errors.append("Test session cleanup incomplete; revoke dedicated-account test sessions")
            replay.dispose()
            context.close()
            browser.close()
    return dict(observed_at=datetime.now(timezone.utc).isoformat(), reference=args.reference,
                management_controls=dict(logout=dict(interfaces={args.interface: observed})), browser_probe_errors=errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--interface", default="gitlab-web")
    parser.add_argument("--menu-selector", default='[data-testid="user-menu-toggle"]')
    parser.add_argument("--logout-selector", default='a[href*="/users/sign_out"], [data-testid="sign-out-link"]')
    parser.add_argument("--message-text", help="Expected explicit logout confirmation in the interface language")
    args = parser.parse_args()
    username, password = os.environ.get("GITLAB_SESSION_TEST_USER"), os.environ.get("GITLAB_SESSION_TEST_PASSWORD")
    if not username or not password:
        parser.error("set GITLAB_SESSION_TEST_USER and GITLAB_SESSION_TEST_PASSWORD for a dedicated account")
    try:
        result = run(args, username, password)
    except Exception as exc:
        result = {"browser_probe_errors": ["Probe setup failed: " + type(exc).__name__]}
    print(json.dumps(result, indent=2))
    return 1 if result.get("browser_probe_errors") else 0


if __name__ == "__main__":
    sys.exit(main())
