import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "roles", "gitlab_stig_audit", "filter_plugins"))
import gitlab_stig as gs
from gitlab_data_controls import evaluate_data_controls


class DataControlsTests(unittest.TestCase):
    def setUp(self):
        self.policy = dict(storage_locations=["repositories"], offline_copies=["backup-media"],
                           management_inputs=["admin/session_timeout"], error_conditions=["authorization_failure"],
                           error_outputs=["rails-errors"], required_log_tools=["/opt/gitlab/embedded/bin/svlogd"])
        self.tool = self.policy["required_log_tools"][0]
        def facts(*keys):
            return dict.fromkeys(keys, True)
        rest = facts("confidentiality_verified", "integrity_verified", "effective_access_verified")
        rest.update(storage_reference="storage:42", configuration_reference="config:42", verification_reference="test:42")
        offline = facts("encryption_verified", "cryptographic_integrity_verified", "key_protection_verified", "coverage_verified")
        offline.update(mechanism_reference="offline:42", verification_reference="verify:42", key_management_reference="kms:42")
        inputs = facts("server_validation_verified", "type_format_verified", "bounds_verified", "unexpected_parameters_verified", "invalid_input_rejected")
        inputs.update(tested_at="2026-11-12T11:00:00Z", test_reference="validation:42")
        error = dict(recognition_verified=True, configuration_reference="errors:42",
                     records=[dict(time="2026-11-12T11:00:00Z", source="record:42")])
        output = facts("sanitization_verified", "corrective_information_verified", "sensitive_disclosure_prevented")
        output.update(tested_at="2026-11-12T11:00:00Z", test_reference="sanitization:42")
        self.data = dict(
            at_rest=dict(inventory_complete=True, locations=dict(repositories=rest)),
            offline=dict(inventory_complete=True, copies={"backup-media": offline}),
            input_validation=dict(inventory_complete=True, gitlab_version="17.3.4", implementation_reference="source:42", inputs={"admin/session_timeout": inputs}),
            error_identification=dict(inventory_complete=True, conditions=dict(authorization_failure=error)),
            error_sanitization=dict(inventory_complete=True, gitlab_version="17.3.4", implementation_reference="source:42", outputs={"rails-errors": output}),
            tool_integrity=dict(inventory_complete=True, baseline_authenticated=True, baseline_independently_protected=True,
                                baseline_approved=True, baseline_reference="signed-manifest:42", paths={self.tool: dict(sha256="a" * 64)}))
        self.doc = dict(observed_at="2026-11-12T12:00:00Z", reference="assessment:42", data_controls=self.data)
        self.ev = dict(collected_at="2026-11-12T12:01:00Z", version="17.3.4", audit_control_evidence=self.doc,
                       log_tools=dict(paths={self.tool: dict(exists=True, sha256="a" * 64)}))

    def checks(self):
        result = gs.sc.Results(gs.CHECK_META)
        evaluate_data_controls(result, self.ev, self.policy)
        return {r["id"]: r for r in result.items}

    def test_complete(self):
        self.assertEqual({r["status"] for r in self.checks().values()}, {gs.NF})

    def test_missing_evidence_and_policy(self):
        self.ev, self.policy = {}, {}
        self.assertEqual({r["status"] for r in self.checks().values()}, {gs.NR})

    def test_stale_future_unreferenced(self):
        for key, value in (("observed_at", "2026-01-01T00:00:00Z"), ("observed_at", "2026-11-13T00:00:00Z"), ("reference", "")):
            self.ev["audit_control_evidence"] = dict(self.doc, **{key: value})
            self.assertEqual({r["status"] for r in self.checks().values()}, {gs.NR})

    def test_confidentiality_does_not_imply_integrity(self):
        self.data["at_rest"]["locations"]["repositories"]["integrity_verified"] = False
        self.data["offline"]["copies"]["backup-media"].pop("cryptographic_integrity_verified")
        self.assertEqual(self.checks()["GLAB-050"]["status"], gs.OPEN)
        self.assertEqual(self.checks()["GLAB-051"]["status"], gs.NR)

    def test_offline_absence_requires_complete_scope(self):
        self.policy["offline_copies"] = []
        self.data["offline"] = dict(inventory_complete=True, none_present=True)
        self.assertEqual(self.checks()["GLAB-051"]["status"], gs.NR)
        self.data["offline"]["scope_reference"] = "inventory:42"
        self.assertEqual(self.checks()["GLAB-051"]["status"], gs.NA)

    def test_validation_exceptions_require_explicit_approval(self):
        item = self.data["input_validation"]["inputs"]["admin/session_timeout"]
        item.clear()
        item["exception"] = True
        self.assertEqual(self.checks()["GLAB-052"]["status"], gs.NR)
        item.update(organization_approval_reference="ISSM:42", exception_scope_reference="input:42")
        self.assertEqual(self.checks()["GLAB-052"]["status"], gs.NF)

    def test_invalid_input_acceptance_is_finding(self):
        self.data["input_validation"]["inputs"]["admin/session_timeout"]["invalid_input_rejected"] = False
        self.assertEqual(self.checks()["GLAB-052"]["status"], gs.OPEN)

    def test_version_mismatch_requires_review(self):
        self.ev["version"] = "18.0.0"
        for cid in ("GLAB-052", "GLAB-054"):
            self.assertEqual(self.checks()[cid]["status"], gs.NR)

    def test_error_record_absence_inconclusive_and_local_sample_supported(self):
        self.data["error_identification"]["conditions"]["authorization_failure"]["records"] = []
        self.assertEqual(self.checks()["GLAB-053"]["status"], gs.NR)
        self.ev["error_inspection"] = dict(events=[dict(condition="authorization_failure", time="2026-11-12T11:00:00Z", source="production_json.log")])
        self.assertEqual(self.checks()["GLAB-053"]["status"], gs.NF)
        self.data["error_identification"]["conditions"]["authorization_failure"]["recognition_verified"] = False
        self.assertEqual(self.checks()["GLAB-053"]["status"], gs.OPEN)

    def test_suspected_secret_requires_review_but_canary_is_finding(self):
        self.ev["error_inspection"] = dict(sources=dict(errors=dict(sampled_lines=10, candidate_categories=["token_shape"])))
        self.assertEqual(self.checks()["GLAB-054"]["status"], gs.NR)
        self.data["error_sanitization"]["sample_candidates_reviewed"] = True
        self.assertEqual(self.checks()["GLAB-054"]["status"], gs.NF)
        self.ev["error_inspection"]["sources"]["errors"]["canary_found"] = True
        self.assertEqual(self.checks()["GLAB-054"]["status"], gs.OPEN)

    def test_hash_mismatch_is_finding_only_against_trusted_baseline(self):
        self.ev["log_tools"]["paths"][self.tool]["sha256"] = "b" * 64
        self.assertEqual(self.checks()["GLAB-055"]["status"], gs.OPEN)
        self.data["tool_integrity"].pop("baseline_authenticated")
        self.assertEqual(self.checks()["GLAB-055"]["status"], gs.NR)

    def test_new_tool_missing_baseline_truncation_and_read_failure(self):
        self.ev["log_tools"]["paths"]["/usr/bin/agent"] = dict(exists=True, sha256="a" * 64)
        self.assertEqual(self.checks()["GLAB-055"]["status"], gs.NR)
        self.ev["log_tools"]["paths"].pop("/usr/bin/agent")
        self.ev["log_tools"]["truncated"] = True
        self.assertEqual(self.checks()["GLAB-055"]["status"], gs.NR)
        self.ev["log_tools"]["truncated"] = False
        self.ev["log_tools"]["paths"][self.tool]["hash_error"] = "file changed"
        self.assertEqual(self.checks()["GLAB-055"]["status"], gs.NR)

    def test_malformed_sections(self):
        for key in self.data:
            saved = self.data[key]
            self.data[key] = "bad"
            self.assertIn(gs.NR, {r["status"] for r in self.checks().values()})
            self.data[key] = saved

    def test_individual_checklist_bindings(self):
        results = gs.gitlab_stig_evaluate(self.ev, dict(audit_controls=self.policy))
        with open(os.path.join(os.path.dirname(__file__), "..", "roles", "stig_common", "files", "app_server_srg_index.json")) as stream:
            index = json.load(stream)
        bindings = gs.sc.stig_bind(results, index)
        for cid, vuln in (("GLAB-050", "V-204770"), ("GLAB-051", "V-204771"), ("GLAB-053", "V-204773"), ("GLAB-054", "V-204774")):
            self.assertEqual(bindings["bound"][vuln], [cid])

    def test_collector_hashes_and_exports_no_log_content(self):
        import contextlib
        import hashlib
        import io
        import runpy
        import tempfile
        import types
        from unittest.mock import patch
        collector = os.path.join(os.path.dirname(__file__), "..", "roles", "gitlab_stig_audit", "files", "audit_controls.py")
        with tempfile.TemporaryDirectory() as directory:
            tool = os.path.join(directory, "logger")
            payload = b"known tool contents"
            with open(tool, "wb") as stream:
                stream.write(payload)
            canary = "DUMMY_REDACTION_TEST_42"
            token = "glpat-FAKE_TEST_TOKEN_12345"
            with open(os.path.join(directory, "production_json.log"), "w") as stream:
                for _ in range(250):
                    stream.write(json.dumps(dict(time="2026-11-12T11:00:00Z", status=403, message=canary + token)) + "\n")
            output = io.StringIO()
            modules = {"pwd": types.SimpleNamespace(getpwuid=lambda _: types.SimpleNamespace(pw_name="root")),
                       "grp": types.SimpleNamespace(getgrgid=lambda _: types.SimpleNamespace(gr_name="root"))}
            acl = types.SimpleNamespace(stdout=b"", returncode=0)
            args = [collector, os.path.join(directory, "audit_json.log"), "", directory, json.dumps([tool]), directory, canary]
            with patch.dict(sys.modules, modules), patch.object(sys, "argv", args), patch("subprocess.run", return_value=acl), patch("glob.iglob", return_value=iter(())), contextlib.redirect_stdout(output):
                runpy.run_path(collector, run_name="__main__")
            evidence = json.loads(output.getvalue())
            self.assertEqual(evidence["log_tools"]["paths"][tool].get("sha256"), hashlib.sha256(payload).hexdigest(), evidence["log_tools"]["paths"][tool])
            source = evidence["error_inspection"]["sources"][os.path.join(directory, "production_json.log")]
            self.assertEqual(source["sampled_lines"], 200)
            self.assertTrue(source["canary_found"])
            self.assertIn("token_shape", source["candidate_categories"])
            self.assertTrue(evidence["error_inspection"]["events"])
            for secret in (canary, token, "known tool contents"):
                self.assertNotIn(secret, output.getvalue())
