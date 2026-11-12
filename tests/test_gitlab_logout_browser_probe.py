import importlib.util
import json
import os
import types
import unittest
from unittest.mock import MagicMock

spec = importlib.util.spec_from_file_location("logout_browser_probe", os.path.join(os.path.dirname(__file__), "..", "scripts", "gitlab_logout_browser_probe.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def response(status, value):
    return types.SimpleNamespace(status=status, json=lambda: value)


class LogoutBrowserProbeTests(unittest.TestCase):
    def setUp(self):
        self.page, self.replay = MagicMock(), MagicMock()
        self.account = response(200, {"id": 42})
        self.unauthorized = response(401, {"message": "401 Unauthorized"})
        self.page.request.get.side_effect = [self.account, self.unauthorized]
        self.replay.get.side_effect = [self.account, self.unauthorized]
        self.page.context.cookies.return_value = [{"name": "_gitlab_session", "value": "TEST-COOKIE-DO-NOT-EXPORT"}]
        self.control, self.menu = MagicMock(), MagicMock()
        self.control.count.return_value = 1
        self.control.first.is_visible.return_value = True
        self.control.first.is_enabled.return_value = True
        self.menu.count.return_value = 0
        self.messages = MagicMock()
        self.messages.count.return_value = 1
        self.messages.nth.return_value.is_visible.return_value = True
        self.page.get_by_text.return_value = self.messages
        self.page.locator.side_effect = lambda selector: self.control if selector == "logout" else self.menu if selector == "menu" else MagicMock()

    def exercise(self, text=None):
        return probe.exercise(self.page, self.replay, "https://gitlab.example.mil", "TEST-USER", "TEST-PASSWORD", "exercise:42", "menu", "logout", text)

    def test_complete_rendered_logout_without_exporting_secrets(self):
        result = self.exercise()
        for key in ("authenticated_before", "visible_usable_control", "user_initiated_logout_completed", "old_session_rejected", "explicit_message_visible"):
            self.assertTrue(result[key])
        for value in ("TEST-USER", "TEST-PASSWORD", "TEST-COOKIE-DO-NOT-EXPORT"):
            self.assertNotIn(value, json.dumps(result))
        self.control.first.click.assert_called_once()

    def test_selector_miss_is_inconclusive(self):
        self.control.count.return_value = 0
        result = self.exercise()
        self.assertNotIn("visible_usable_control", result)
        self.assertNotIn("explicit_message_visible", result)

    def test_unknown_message_is_inconclusive(self):
        self.messages.count.return_value = 0
        self.assertIsNone(self.exercise()["explicit_message_visible"])

    def test_approved_expected_message_absence_is_observed(self):
        self.messages.count.return_value = 0
        self.assertFalse(self.exercise("Signed out successfully")["explicit_message_visible"])

    def test_old_session_still_authenticates(self):
        self.replay.get.side_effect = [self.account, self.account]
        self.assertFalse(self.exercise()["old_session_rejected"])

    def test_unknown_unauthenticated_response_is_inconclusive(self):
        self.page.request.get.side_effect = [self.account, response(403, {"message": "proxy denied"})]
        result = self.exercise()
        self.assertIsNone(result["user_initiated_logout_completed"])
        self.assertNotIn("explicit_message_visible", result)

    def test_response_helpers_and_origin(self):
        self.assertIsNone(probe.identity(response(200, {"id": True})))
        self.assertIsNone(probe.denied(response(302, {})))
        self.assertTrue(probe.denied(self.unauthorized))
        self.assertEqual(probe.origin("https://gitlab.example.mil/a"), probe.origin("https://gitlab.example.mil:443/b"))
        self.assertNotEqual(probe.origin("https://gitlab.example.mil"), probe.origin("https://idp.example.mil"))

    def test_unsafe_urls_rejected_before_loading_playwright(self):
        for url in ("http://gitlab.example.mil", "https://user:password@gitlab.example.mil", "https://gitlab.example.mil/?secret=1"):
            with self.assertRaises(ValueError):
                probe.run(types.SimpleNamespace(url=url), "user", "secret")
