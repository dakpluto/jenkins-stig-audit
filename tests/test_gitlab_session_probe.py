import copy
import http.cookiejar
import importlib.util
import json
import os
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("session_probe", os.path.join(os.path.dirname(__file__), "..", "scripts", "gitlab_session_probe.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def cookie(value):
    return http.cookiejar.Cookie(0, "_gitlab_session", value, None, False, "gitlab.example.mil", False,
                                 False, "/", True, True, None, True, None, None, {})


class FakeClient:
    active = set()
    sequence = 0
    adopt = False
    fail_second = False

    def __init__(self, url, context, jar=None):
        self.jar = jar if jar is not None else http.cookiejar.CookieJar()

    def request(self, *args, **kwargs):
        if not list(self.jar):
            self.jar.set_cookie(cookie("anonymous"))
        return 200, ""

    def session(self):
        return next(iter(self.jar))

    def login(self, username, password):
        type(self).sequence += 1
        if self.fail_second and self.sequence == 2:
            raise ValueError("credential-like-text-must-not-export")
        value = self.session().value if self.adopt and list(self.jar) else "authenticated-" + str(self.sequence)
        self.jar.set_cookie(cookie(value))
        self.active.add(value)
        return 42

    def identity(self):
        return 42 if list(self.jar) and self.session().value in self.active else None

    def denied(self):
        return self.identity() is None

    def logout(self):
        if list(self.jar):
            self.active.discard(self.session().value)
        return True


class SessionProbeTests(unittest.TestCase):
    def setUp(self):
        FakeClient.active = set()
        FakeClient.sequence = 0
        FakeClient.adopt = False
        FakeClient.fail_second = False

    def run_probe(self):
        with patch.object(probe, "Client", FakeClient):
            return probe.probe("https://gitlab.example.mil", "test-person", "secret-password", "run:42")

    def test_success_and_cleanup(self):
        result = self.run_probe()
        sessions = result["auth_controls"]["sessions"]
        self.assertTrue(sessions["termination"]["logout"]["old_session_rejected"])
        self.assertTrue(sessions["generation"]["gitlab_web"]["fabricated_rejected"])
        self.assertTrue(sessions["generation"]["gitlab_web"]["tampered_rejected"])
        self.assertNotIn("underlying_ids_unique", sessions["generation"]["gitlab_web"])
        self.assertNotIn("implementation_verified", sessions["generation"]["gitlab_web"])
        self.assertFalse(FakeClient.active)
        output = json.dumps(result)
        for secret in ("secret-password", "test-person", "authenticated-1", "authenticated-2"):
            self.assertNotIn(secret, output)

    def test_fixation_detected(self):
        FakeClient.adopt = True
        result = self.run_probe()
        self.assertFalse(result["auth_controls"]["sessions"]["generation"]["gitlab_web"]["fixation_rejected"])

    def test_unsupported_login_inconclusive_and_cleanup(self):
        FakeClient.fail_second = True
        result = self.run_probe()
        self.assertTrue(result["session_probe_errors"])
        self.assertNotIn("old_session_rejected", result["auth_controls"]["sessions"]["termination"]["logout"])
        self.assertFalse(FakeClient.active)
        self.assertNotIn("credential-like-text", json.dumps(result))

    def test_no_unsafe_base_urls(self):
        for url in ("http://gitlab.example.mil", "https://user:password@gitlab.example.mil", "https://gitlab.example.mil/?token=secret", "https://gitlab.example.mil/#secret"):
            with self.assertRaises(ValueError):
                probe.probe(url, "test", "secret", "run:42")

    def test_unexpected_responses_are_inconclusive(self):
        client = probe.Client("https://gitlab.example.mil", probe.ssl.create_default_context())
        with patch.object(client, "request", return_value=(403, '<h1>proxy denied</h1>')):
            self.assertIsNone(client.denied())
        with patch.object(client, "request", return_value=(200, '{"message":"login page"}')):
            self.assertIsNone(client.denied())
        with patch.object(client, "request", return_value=(401, '{"message":"401 Unauthorized"}')):
            self.assertTrue(client.denied())

    def test_token_parser_handles_meta_and_form(self):
        for markup in ('<meta name="csrf-token" content="test-only">', '<input name="authenticity_token" value="test-only">'):
            parser = probe.Tokens()
            parser.feed(markup)
            self.assertEqual(parser.csrf, "test-only")

    def test_redirects_never_forward_credentials(self):
        self.assertIsNone(probe.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://unrelated.example"))

    def test_logout_uses_current_csrf_and_requires_endpoint_success(self):
        client = probe.Client("https://gitlab.example.mil", probe.ssl.create_default_context())
        responses = [(200, '<meta name="csrf-token" content="test-csrf">'), (302, ""), (401, '{"message":"401 Unauthorized"}')]
        with patch.object(client, "request", side_effect=responses) as request:
            self.assertTrue(client.logout())
            self.assertEqual(request.call_args_list[1].args, ("/users/sign_out", {"authenticity_token": "test-csrf", "_method": "delete"}))
        with patch.object(client, "request", side_effect=[responses[0], (500, "error")]):
            self.assertFalse(client.logout())
