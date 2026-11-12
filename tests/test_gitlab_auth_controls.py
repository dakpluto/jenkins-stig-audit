import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "roles", "gitlab_stig_audit", "filter_plugins"))
import gitlab_stig as gs
from gitlab_auth_controls import evaluate_auth_controls, AuthInputs


class AuthenticationControlsTests(unittest.TestCase):
    def setUp(self):
        self.policy = dict(group_auth_paths=["broker"], soap_endpoints=["gateway"],
                           pki_auth_paths=["cac-idp"], authentication_interfaces=["gitlab-web"],
                           peer_connections=["proxy-gitlab"], session_termination_methods=["logout", "expiry"],
                           session_generation_paths=["gitlab_web"])
        def facts(*keys):
            return dict.fromkeys(keys, True)
        group = facts("individual_auth_required", "bypass_prevented", "traceability_verified")
        group["records"] = [dict(individual="alice", group_account="shared-admin", source="broker:42",
                                  individual_authenticated_at="2026-11-12T11:00:00Z", group_used_at="2026-11-12T11:01:00Z")]
        soap = facts("ws_security_configured", "authentication_enforced", "unauthenticated_rejected", "invalid_credentials_rejected")
        soap.update(configuration_reference="soap:config", test_reference="soap:test")
        pki = facts("certificate_validated", "mapping_configured", "intended_account_verified", "unmapped_identity_rejected")
        pki.update(certificate_identity_reference="certificate:subject", account_reference="user:42",
                   configuration_reference="mapping:42", test_reference="mapping:test")
        masking = facts("rendered_or_terminal_verified", "all_secret_inputs_obscured")
        masking["test_reference"] = "browser:42"
        peer = facts("both_peers_authenticated", "peer_identity_verified", "missing_credentials_rejected", "untrusted_credentials_rejected", "bypass_prevented")
        peer.update(configuration_reference="mtls:config", test_reference="mtls:test")
        termination = facts("authenticated_before", "termination_completed", "old_session_rejected")
        termination.update(tested_at="2026-11-12T11:00:00Z", test_reference="session:test")
        generation = facts("implementation_verified", "underlying_ids_unique", "independent_sessions_verified",
                           "fabricated_rejected", "tampered_rejected", "fixation_rejected", "rng_path_traced",
                           "validated_module_verified", "approved_runtime_verified")
        generation.update(implementation_reference="source:17.3.4", gitlab_version="17.3.4", tested_at="2026-11-12T11:00:00Z",
                          test_reference="session:test", rng_backend="openssl", rng_reference="rng:source",
                          module_validation_reference="CMVP:example", runtime_reference="runtime:report")
        self.auth = dict(
            group_auth=dict(inventory_complete=True, paths=dict(broker=group)),
            soap=dict(inventory_complete=True, endpoints=dict(gateway=soap)),
            pki_mapping=dict(inventory_complete=True, paths={"cac-idp": pki}),
            input_masking=dict(inventory_complete=True, interfaces={"gitlab-web": masking}),
            peer_auth=dict(inventory_complete=True, connections={"proxy-gitlab": peer}),
            sessions=dict(termination_inventory_complete=True, generation_inventory_complete=True,
                          termination=dict(logout=copy.deepcopy(termination), expiry=copy.deepcopy(termination)),
                          generation=dict(gitlab_web=generation)))
        self.doc = dict(observed_at="2026-11-12T12:00:00Z", reference="assessment:42", auth_controls=self.auth)
        self.ev = dict(collected_at="2026-11-12T12:01:00Z", version="17.3.4", audit_control_evidence=self.doc,
                       rails=dict(session_crypto=dict(openssl_fips_mode=True, openssl_version="example")))

    def checks(self):
        result = gs.sc.Results(gs.CHECK_META)
        evaluate_auth_controls(result, self.ev, self.policy)
        return {r["id"]: r for r in result.items}

    def test_complete_evidence(self):
        self.assertEqual({r["status"] for r in self.checks().values()}, {gs.NF})

    def test_missing_evidence(self):
        self.ev, self.policy = {}, {}
        self.assertEqual({r["status"] for r in self.checks().values()}, {gs.NR})

    def test_stale_future_unreferenced(self):
        for key, value in [("observed_at", "2026-01-01T00:00:00Z"), ("observed_at", "2026-11-13T00:00:00Z"), ("reference", "")]:
            self.ev["audit_control_evidence"] = dict(self.doc, **{key: value})
            self.assertEqual({r["status"] for r in self.checks().values()}, {gs.NR})

    def test_reviewed_absence(self):
        for section, policy, cid, expected in (("soap", "soap_endpoints", "GLAB-042", gs.NA),
                ("pki_mapping", "pki_auth_paths", "GLAB-043", gs.NA),
                ("peer_auth", "peer_connections", "GLAB-045", gs.NA),
                ("group_auth", "group_auth_paths", "GLAB-041", gs.NF)):
            self.policy[policy] = []
            self.auth[section] = dict(inventory_complete=True, none_present=True)
            self.assertEqual(self.checks()[cid]["status"], gs.NR)
            self.auth[section]["scope_reference"] = "architecture:42"
            self.assertEqual(self.checks()[cid]["status"], expected)

    def test_bad_mapping_and_peer_bypass(self):
        self.auth["pki_mapping"]["paths"]["cac-idp"]["intended_account_verified"] = False
        self.auth["peer_auth"]["connections"]["proxy-gitlab"]["bypass_prevented"] = False
        self.assertEqual(self.checks()["GLAB-043"]["status"], gs.OPEN)
        self.assertEqual(self.checks()["GLAB-045"]["status"], gs.OPEN)

    def test_group_sequence_and_shared_identity(self):
        record = self.auth["group_auth"]["paths"]["broker"]["records"][0]
        record["individual_authenticated_at"] = "2026-11-12T11:02:00Z"
        self.assertEqual(self.checks()["GLAB-041"]["status"], gs.OPEN)
        record["individual_authenticated_at"] = "2026-11-12T11:00:00Z"
        record["individual"] = "shared-admin"
        self.assertEqual(self.checks()["GLAB-041"]["status"], gs.NR)

    def test_static_html_does_not_pass_masking(self):
        self.auth.pop("input_masking")
        self.ev["http"] = dict(sign_in=dict(status=200, content='<input name="user[password]" type="password" value="secret-do-not-export">'))
        result = self.checks()["GLAB-044"]
        self.assertEqual(result["status"], gs.NR)
        self.assertIn("password", result["evidence"])
        self.assertNotIn("secret-do-not-export", json.dumps(result))

    def test_rendered_input_exposure_is_finding(self):
        self.auth["input_masking"]["interfaces"]["gitlab-web"]["all_secret_inputs_obscured"] = False
        self.assertEqual(self.checks()["GLAB-044"]["status"], gs.OPEN)

    def test_logout_requires_real_authenticated_precondition(self):
        item = self.auth["sessions"]["termination"]["logout"]
        item["old_session_rejected"] = False
        self.assertEqual(self.checks()["GLAB-046"]["status"], gs.OPEN)
        item["authenticated_before"] = False
        self.assertEqual(self.checks()["GLAB-046"]["status"], gs.NR)
        item["authenticated_before"], item["termination_completed"] = True, False
        self.assertEqual(self.checks()["GLAB-046"]["status"], gs.NR)

    def test_all_termination_methods_required(self):
        self.auth["sessions"]["termination"].pop("expiry")
        self.assertEqual(self.checks()["GLAB-046"]["status"], gs.NR)
        self.policy["session_termination_methods"] = ["expiry"]
        self.assertEqual(self.checks()["GLAB-046"]["status"], gs.NR)

    def test_cookie_variation_is_not_underlying_id_uniqueness(self):
        item = self.auth["sessions"]["generation"]["gitlab_web"]
        item.pop("underlying_ids_unique")
        item["distinct_cookie_values"] = True
        self.assertEqual(self.checks()["GLAB-047"]["status"], gs.NR)

    def test_fixation_and_fips_failures(self):
        self.auth["sessions"]["generation"]["gitlab_web"]["fixation_rejected"] = False
        self.ev["rails"]["session_crypto"]["openssl_fips_mode"] = False
        self.assertEqual(self.checks()["GLAB-048"]["status"], gs.OPEN)
        self.assertEqual(self.checks()["GLAB-049"]["status"], gs.OPEN)

    def test_missing_runtime_or_wrong_version(self):
        self.ev["rails"] = {}
        self.assertEqual(self.checks()["GLAB-049"]["status"], gs.NR)
        self.ev["version"] = "18.0.0"
        for cid in ("GLAB-047", "GLAB-048", "GLAB-049"):
            self.assertEqual(self.checks()[cid]["status"], gs.NR)

    def test_malformed_sections_and_non_boolean_facts(self):
        for key in self.auth:
            saved = self.auth[key]
            self.auth[key] = ["invalid"]
            self.assertIn(gs.NR, {r["status"] for r in self.checks().values()})
            self.auth[key] = saved
        self.auth["soap"]["endpoints"]["gateway"]["ws_security_configured"] = "true"
        self.assertEqual(self.checks()["GLAB-042"]["status"], gs.NR)

    def test_distinct_checklist_bindings(self):
        results = gs.gitlab_stig_evaluate(self.ev, dict(audit_controls=self.policy))
        with open(os.path.join(os.path.dirname(__file__), "..", "roles", "stig_common", "files", "app_server_srg_index.json")) as stream:
            index = json.load(stream)
        bindings = gs.sc.stig_bind(results, index)
        self.assertEqual(bindings["bound"]["V-204764"], ["GLAB-047"])
        self.assertEqual(bindings["bound"]["V-204765"], ["GLAB-048"])
        self.assertEqual(bindings["bound"]["V-204766"], ["GLAB-049"])

    def test_parser_reports_only_secret_input_types(self):
        parser = AuthInputs()
        parser.feed('<input type="hidden" name="authenticity_token" value="hidden"><input name="user[otp_attempt]" type="text"><input name="username"><input name="password" type="password">')
        self.assertEqual([field["type"] for field in parser.fields], ["text", "password"])

    def test_enabled_smartcard_blocks_pki_absence_claim(self):
        self.policy["pki_auth_paths"] = []
        self.auth["pki_mapping"] = dict(inventory_complete=True, none_present=True, scope_reference="inventory:42")
        self.ev["gitlab_yml"] = dict(smartcard=dict(enabled=True))
        self.assertEqual(self.checks()["GLAB-043"]["status"], gs.NR)
