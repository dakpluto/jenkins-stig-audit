"""Opt-in GitLab local-password session probes; credentials/cookies stay in memory.

Run explicitly with a dedicated test account. Emits evidence only, never a STIG pass.
Unsupported SSO/MFA/CAPTCHA flows remain inconclusive and are not bypassed.
"""
import argparse
import copy
from datetime import datetime, timezone
import http.cookiejar
from html.parser import HTMLParser
import json
import os
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Tokens(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.csrf = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta" and attrs.get("name") == "csrf-token":
            self.csrf = attrs.get("content")
        elif tag == "input" and attrs.get("name") == "authenticity_token" and not self.csrf:
            self.csrf = attrs.get("value")


class Client:
    def __init__(self, url, context, jar=None):
        self.url = url.rstrip("/")
        self.jar = jar if jar is not None else http.cookiejar.CookieJar()
        # Disable environment proxies to avoid unexpectedly forwarding credentials.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(self.jar))

    def request(self, path, data=None, method=None):
        payload = urllib.parse.urlencode(data).encode() if data is not None else None
        request = urllib.request.Request(self.url + path, data=payload, method=method)
        request.add_header("Accept", "application/json" if path.startswith("/api/") else "text/html")
        try:
            response = self.opener.open(request, timeout=30)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            return response.code, response.read(524288).decode("utf-8", "replace")

    def session(self):
        matches = [cookie for cookie in self.jar if cookie.name == "_gitlab_session"]
        if len(matches) != 1:
            raise ValueError("session cookie unavailable or ambiguous")
        return matches[0]

    def identity(self):
        status, body = self.request("/api/v4/user")
        try:
            user = json.loads(body)
        except ValueError:
            return None
        return user["id"] if status == 200 and isinstance(user, dict) and type(user.get("id")) is int and user["id"] > 0 else None

    def denied(self):
        status, body = self.request("/api/v4/user")
        try:
            message = json.loads(body).get("message", "")
        except (ValueError, AttributeError):
            return None
        if status == 401 and "unauthorized" in str(message).lower():
            return True
        if status == 200 and self.identity() is not None:
            return False
        return None

    def login(self, username, password):
        status, body = self.request("/users/sign_in")
        token = Tokens()
        token.feed(body)
        if status != 200 or not token.csrf:
            raise ValueError("supported local login form unavailable")
        self.request("/users/sign_in", {"authenticity_token": token.csrf,
            "user[login]": username, "user[password]": password, "user[remember_me]": "0"})
        identity = self.identity()
        if identity is None:
            raise ValueError("local authentication incomplete")
        return identity

    def logout(self):
        status, body = self.request("/-/profile")
        token = Tokens()
        token.feed(body)
        if status != 200 or not token.csrf:
            return False
        status, _ = self.request("/users/sign_out", {"authenticity_token": token.csrf, "_method": "delete"})
        return status in (200, 204, 302, 303) and self.denied() is True


def probe(url, username, password, reference, ca_file=None):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("a credential-free HTTPS GitLab base URL is required")
    context = ssl.create_default_context(cafile=ca_file)
    clients = []
    tested_at = datetime.now(timezone.utc).isoformat()
    generation, termination, errors = {}, {}, []
    cleanup_failures = 0

    def replay(cookie):
        jar = http.cookiejar.CookieJar()
        jar.set_cookie(copy.copy(cookie))
        return Client(url, context, jar)

    try:
        first, second = Client(url, context), Client(url, context)
        clients.extend([first, second])
        # Capture a server cookie template before replacing it with an invented identifier.
        first.request("/users/sign_in")
        fabricated = copy.copy(first.session())
        fabricated.value = secrets.token_hex(32)
        first.jar.set_cookie(copy.copy(fabricated))
        identity = first.login(username, password)
        if second.login(username, password) != identity:
            raise ValueError("independent test sessions have inconsistent identities")
        original = copy.copy(first.session())
        other = copy.copy(second.session())
        generation["distinct_cookie_values"] = original.value != other.value
        # This is an observation of opaque cookies, not underlying ID uniqueness.
        generation["fabricated_rejected"] = replay(fabricated).denied()
        generation["fixation_rejected"] = generation["fabricated_rejected"]
        tampered = copy.copy(original)
        tampered.value = ("A" if original.value[:1] != "A" else "B") + original.value[1:]
        generation["tampered_rejected"] = replay(tampered).denied()
        before = replay(original).identity() == identity
        logged_out = first.logout()
        rejected = replay(original).denied() if logged_out else None
        termination = dict(authenticated_before=before, termination_completed=logged_out,
                           old_session_rejected=rejected, tested_at=tested_at, test_reference=reference)
    except Exception as exc:
        # Exception messages can embed URLs or request data. Export only the class.
        errors.append("Session probe incomplete: " + type(exc).__name__)
    finally:
        for client in clients:
            try:
                if client.identity() is not None and not client.logout():
                    cleanup_failures += 1
            except Exception:
                cleanup_failures += 1
    generation.update(tested_at=tested_at, test_reference=reference)
    if cleanup_failures:
        errors.append("Test session cleanup incomplete; revoke the dedicated account's test sessions")
    return dict(observed_at=datetime.now(timezone.utc).isoformat(), reference=reference,
                auth_controls=dict(sessions=dict(termination=dict(logout=termination),
                                                  generation=dict(gitlab_web=generation))),
                session_probe_errors=errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--ca-file")
    args = parser.parse_args()
    username = os.environ.get("GITLAB_SESSION_TEST_USER")
    password = os.environ.get("GITLAB_SESSION_TEST_PASSWORD")
    if not username or not password:
        parser.error("set GITLAB_SESSION_TEST_USER and GITLAB_SESSION_TEST_PASSWORD for a dedicated test account")
    try:
        result = probe(args.url, username, password, args.reference, args.ca_file)
    except Exception as exc:
        print(json.dumps({"session_probe_errors": ["Probe setup failed: " + type(exc).__name__]}))
        return 1
    print(json.dumps(result, indent=2))
    return 1 if result["session_probe_errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
