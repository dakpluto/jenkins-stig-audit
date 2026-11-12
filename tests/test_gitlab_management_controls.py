import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "roles", "gitlab_stig_audit", "filter_plugins"))
import gitlab_stig as gs
from gitlab_management_controls import evaluate_management_controls


class ManagementControlsTests(unittest.TestCase):
    def setUp(self):
        self.policy = dict(management_interfaces=["gitlab-web"], security_attributes=dict(classification=["CUI"]),
                           processing_workflows=["repository-read"], transmission_paths=["repository-download"],
                           remote_management_paths=["admin-web"], privileged_functions=["change-security-settings"],
                           privileged_role_operations=dict(administrator=["change-security-settings"]))
        def facts(*keys):
            return dict.fromkeys(keys, True)
        def tested(item):
            return dict(item, tested_at="2026-11-12T11:00:00Z", test_reference="exercise:42")
        logout = tested(facts("authenticated_before", "visible_usable_control", "user_initiated_logout_completed", "old_session_rejected", "explicit_message_visible"))
        attrs = tested(facts("binding_verified", "lifecycle_coverage_verified", "unauthorized_change_prevented"))
        attrs.update(observed_attributes=dict(classification=["CUI"]), configuration_reference="attributes:42")
        remote = tested(facts("method_approved", "authentication_enforced", "authorization_enforced", "network_restrictions_verified", "bypass_prevented"))
        remote["configuration_reference"] = "remote:42"
        disconnect = tested(facts("implemented", "authorized_operators_verified", "immediate_effect_verified", "scope_coverage_verified",
                                   "exercise_completed", "existing_connections_terminated", "new_access_blocked"))
        disconnect.update(mode="both", configuration_reference="disconnect:42", procedure_reference="procedure:42")
        authorization = tested(facts("server_authorization_verified", "safeguard_bypass_prevented", "authorized_control_succeeded", "nonprivileged_rejected"))
        authorization["tested_nonprivileged_roles"] = ["developer", "guest"]
        record = dict(time="2026-11-12T11:00:00Z", actor="alice", target="security-settings", source="record:42",
                      operation="change-security-settings", role="administrator", individual_attribution_verified=True, impersonated=False)
        self.management = dict(
            logout=dict(inventory_complete=True, interfaces={"gitlab-web": logout}),
            processing_attributes=dict(inventory_complete=True, policy_reference="ISSM:42", paths={"repository-read": copy.deepcopy(attrs)}),
            transmission_attributes=dict(inventory_complete=True, policy_reference="ISSM:42", paths={"repository-download": copy.deepcopy(attrs)}),
            remote_access=dict(inventory_complete=True, approval_reference="policy:42", paths={"admin-web": remote}),
            remote_disconnect=dict(inventory_complete=True, paths={"admin-web": disconnect}),
            privileged_authorization=dict(inventory_complete=True, gitlab_version="17.3.4", implementation_reference="source:42", effective_roles_reviewed=True,
                                          functions={"change-security-settings": authorization}),
            privileged_logging=dict(inventory_complete=True, version_license_coverage_verified=True, gitlab_version="17.3.4", coverage_reference="coverage:42",
                roles=dict(administrator=dict(delegation_impersonation_reviewed=True,
                    operations={"change-security-settings": dict(coverage_verified=True, records=[record])}))))
        self.doc = dict(observed_at="2026-11-12T12:00:00Z", reference="assessment:42", management_controls=self.management)
        self.ev = dict(collected_at="2026-11-12T12:01:00Z", version="17.3.4", audit_control_evidence=self.doc)

    def checks(self):
        result = gs.sc.Results(gs.CHECK_META)
        evaluate_management_controls(result, self.ev, self.policy)
        return {r["id"]: r for r in result.items}

    def test_complete(self):
        self.assertEqual({r["status"] for r in self.checks().values()}, {gs.NF})

    def test_missing_scope_and_evidence(self):
        self.ev, self.policy = {}, {}
        self.assertEqual({r["status"] for r in self.checks().values()}, {gs.NR})

    def test_stale_future_and_unreferenced(self):
        for key, value in (("reference", ""), ("observed_at", "2026-01-01T00:00:00Z"), ("observed_at", "2026-11-13T00:00:00Z")):
            self.ev["audit_control_evidence"] = dict(self.doc, **{key: value})
            self.assertEqual({r["status"] for r in self.checks().values()}, {gs.NR})

    def test_logout_message_and_replay_are_separate(self):
        item = self.management["logout"]["interfaces"]["gitlab-web"]
        item["explicit_message_visible"] = False
        self.assertEqual(self.checks()["GLAB-056"]["status"], gs.NF)
        self.assertEqual(self.checks()["GLAB-057"]["status"], gs.OPEN)
        item["explicit_message_visible"], item["old_session_rejected"] = True, False
        self.assertEqual(self.checks()["GLAB-057"]["status"], gs.OPEN)
        item["authenticated_before"] = False
        self.assertEqual(self.checks()["GLAB-057"]["status"], gs.NR)

    def test_missing_rendered_control_is_inconclusive(self):
        self.management["logout"]["interfaces"]["gitlab-web"].pop("visible_usable_control")
        self.assertEqual(self.checks()["GLAB-056"]["status"], gs.NR)

    def test_attributes_need_policy_binding_and_approved_values(self):
        item = self.management["processing_attributes"]["paths"]["repository-read"]
        item["observed_attributes"]["classification"] = ["UNKNOWN"]
        self.assertEqual(self.checks()["GLAB-058"]["status"], gs.OPEN)
        self.assertEqual(self.checks()["GLAB-059"]["status"], gs.NF)
        item["observed_attributes"].clear()
        self.assertEqual(self.checks()["GLAB-058"]["status"], gs.NR)
        self.policy["security_attributes"] = {}
        self.assertEqual(self.checks()["GLAB-059"]["status"], gs.NR)

    def test_remote_access_bypass_is_finding(self):
        self.management["remote_access"]["paths"]["admin-web"]["bypass_prevented"] = False
        self.assertEqual(self.checks()["GLAB-060"]["status"], gs.OPEN)

    def test_disable_is_distinct_from_disconnect(self):
        item = self.management["remote_disconnect"]["paths"]["admin-web"]
        item["existing_connections_terminated"] = False
        self.assertEqual(self.checks()["GLAB-061"]["status"], gs.OPEN)
        item["mode"] = "disable"
        self.assertEqual(self.checks()["GLAB-061"]["status"], gs.NF)
        item["exercise_completed"] = False
        self.assertEqual(self.checks()["GLAB-061"]["status"], gs.NR)

    def test_negative_authorization_requires_positive_control(self):
        item = self.management["privileged_authorization"]["functions"]["change-security-settings"]
        item["nonprivileged_rejected"] = False
        self.assertEqual(self.checks()["GLAB-062"]["status"], gs.OPEN)
        item["authorized_control_succeeded"] = False
        self.assertEqual(self.checks()["GLAB-062"]["status"], gs.NR)

    def test_privileged_logging_record_role_operation_and_impersonation(self):
        item = self.management["privileged_logging"]["roles"]["administrator"]["operations"]["change-security-settings"]
        record = item["records"][0]
        record["role"] = "developer"
        self.assertEqual(self.checks()["GLAB-063"]["status"], gs.NR)
        record["role"], record["impersonated"] = "administrator", True
        self.assertEqual(self.checks()["GLAB-063"]["status"], gs.NR)
        record["impersonating_admin"] = "bob"
        self.assertEqual(self.checks()["GLAB-063"]["status"], gs.NF)
        item["coverage_verified"] = False
        self.assertEqual(self.checks()["GLAB-063"]["status"], gs.OPEN)

    def test_new_role_and_version_require_coverage(self):
        self.policy["privileged_role_operations"]["group-owner"] = ["change-visibility"]
        self.assertEqual(self.checks()["GLAB-063"]["status"], gs.NR)
        self.ev["version"] = "18.0.0"
        self.assertEqual(self.checks()["GLAB-062"]["status"], gs.NR)

    def test_malformed_sections_and_nonboolean_flags(self):
        for key in self.management:
            saved = self.management[key]
            self.management[key] = "bad"
            self.assertIn(gs.NR, {r["status"] for r in self.checks().values()})
            self.management[key] = saved
        self.management["remote_access"]["paths"]["admin-web"]["method_approved"] = "true"
        self.assertEqual(self.checks()["GLAB-060"]["status"], gs.NR)

    def test_all_eight_checklist_bindings(self):
        results = gs.gitlab_stig_evaluate(self.ev, dict(audit_controls=self.policy))
        with open(os.path.join(os.path.dirname(__file__), "..", "roles", "stig_common", "files", "app_server_srg_index.json")) as stream:
            index = json.load(stream)
        bindings = gs.sc.stig_bind(results, index)
        for number in range(56, 64):
            self.assertEqual(bindings["bound"]["V-%d" % (204778 + number - 56)], ["GLAB-%03d" % number])
