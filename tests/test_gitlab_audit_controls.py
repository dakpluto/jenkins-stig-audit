import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "roles", "gitlab_stig_audit", "filter_plugins"))
import gitlab_stig as gs


class AuditControlsTests(unittest.TestCase):
    def setUp(self):
        self.policy = dict(evidence_max_age_hours=24, nonrepudiation_actions=["permission_changed"],
                           aggregates_logs=True, aggregation_sources=["puma"], aggregation_tolerance_seconds=1,
                           approved_logging_principals=["os:root", "gitlab:alice"], issm_approval_reference="ISSM-42",
                           privilege_operations=["admin_access"])
        self.doc = dict(observed_at="2026-11-12T12:00:00Z", reference="collector:report-42",
                        nonrepudiation=dict(coverage_verified=True, identity_binding_verified=True,
                                            independent_retention_verified=True, tamper_protection_verified=True),
                        aggregation=dict(sources=dict(puma=dict(received=True, timestamps_parseable=True,
                                                               correlation_verified=True, clock_offset_seconds=-0.5))),
                        logging_access=dict(effective_principals=["os:root", "gitlab:alice"],
                                            scope_reviewed=dict(os=True, gitlab=True, streaming=True)),
                        privilege_access=dict(coverage_verified=True),
                        startup=dict(automatic_logging_verified=True, current_start_verified=True,
                                     session_logging_verified=True, application_started_at="2026-11-12T10:00:00Z",
                                     logging_started_at="2026-11-12T09:59:59Z", first_session_record_at="2026-11-12T10:01:00Z"))
        self.doc["records"] = [dict(event_type=event, outcome=outcome, actor="alice", target="project:1",
                                    time="2026-11-12T11:00:00Z", source="collector:42")
                               for event, outcome in [("permission_changed", "success"), ("admin_access", "success"),
                                                      ("admin_access", "failure")]]

    def run_checks(self, doc=None, policy=None):
        result = gs.sc.Results(gs.CHECK_META)
        gs._audit_controls(result, dict(collected_at="2026-11-12T12:01:00Z",
                                       audit_control_evidence=self.doc if doc is None else doc),
                           self.policy if policy is None else policy)
        return {r["id"]: r["status"] for r in result.items}

    def test_complete_evidence_passes(self):
        self.assertEqual(set(self.run_checks().values()), {gs.NF})

    def test_missing_policy_and_evidence_never_pass(self):
        self.assertEqual(set(self.run_checks({}, {}).values()), {gs.NR})

    def test_stale_future_or_unreferenced_evidence(self):
        for key, value in [("observed_at", "2026-11-01T00:00:00Z"),
                           ("observed_at", "2026-11-13T00:00:00Z"), ("reference", "")]:
            doc = copy.deepcopy(self.doc)
            doc[key] = value
            self.assertEqual(set(self.run_checks(doc).values()), {gs.NR})

    def test_demonstrated_gaps_are_findings(self):
        self.doc["nonrepudiation"]["tamper_protection_verified"] = False
        self.doc["aggregation"]["sources"]["puma"]["clock_offset_seconds"] = 2
        self.doc["logging_access"]["effective_principals"].append("gitlab:mallory")
        self.doc["privilege_access"]["coverage_verified"] = False
        self.doc["startup"]["automatic_logging_verified"] = False
        self.assertEqual(set(self.run_checks().values()), {gs.OPEN})

    def test_missing_denied_record_is_inconclusive(self):
        self.doc["records"].pop()
        self.assertEqual(self.run_checks()["GLAB-033"], gs.NR)

    def test_missing_actor_and_old_record_are_inconclusive(self):
        self.doc["records"][0]["actor"] = ""
        self.assertEqual(self.run_checks()["GLAB-030"], gs.NR)
        self.doc["records"][1]["time"] = "2020-01-01T00:00:00Z"
        self.assertEqual(self.run_checks()["GLAB-033"], gs.NR)

    def test_aggregation_scope_required_for_na(self):
        self.policy["aggregates_logs"] = False
        self.assertEqual(self.run_checks()["GLAB-031"], gs.NR)
        self.policy["aggregation_scope_reference"] = "architecture-42"
        self.assertEqual(self.run_checks()["GLAB-031"], gs.NA)

    def test_unknown_source_and_nonfinite_offset(self):
        self.policy["aggregation_sources"].append("nginx")
        self.doc["aggregation"]["sources"]["puma"]["clock_offset_seconds"] = float("nan")
        self.assertEqual(self.run_checks()["GLAB-031"], gs.NR)

    def test_startup_order(self):
        self.doc["startup"]["logging_started_at"] = "2026-11-12T10:00:01Z"
        self.assertEqual(self.run_checks()["GLAB-034"], gs.OPEN)

    def test_collector_bounds_and_redacts(self):
        collector = os.path.join(os.path.dirname(__file__), "..", "roles", "gitlab_stig_audit", "files", "audit_controls.py")
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "audit.json")
            with open(path, "w") as stream:
                for _ in range(250):
                    stream.write(json.dumps(dict(author_id=1, secret="do-not-export", details=dict(event_type="x", custom_message="sensitive"))) + "\n")
            out = json.loads(subprocess.check_output([sys.executable, collector, path, ""], text=True))
            self.assertEqual(len(out["samples"].splitlines()), 200)
            self.assertNotIn("sensitive", out["samples"])
            self.assertNotIn("do-not-export", out["samples"])

    def test_malformed_external_sections_are_inconclusive(self):
        for section in ("nonrepudiation", "aggregation", "logging_access", "privilege_access", "startup", "records"):
            doc = copy.deepcopy(self.doc)
            doc[section] = "invalid"
            self.assertEqual(set(self.run_checks(doc).values()), {gs.NR})

    def test_exact_srg_mappings(self):
        expected = {"GLAB-030": "SRG-APP-000080", "GLAB-031": "SRG-APP-000086",
                    "GLAB-032": "SRG-APP-000090", "GLAB-033": "SRG-APP-000091", "GLAB-034": "SRG-APP-000092"}
        for cid, _, ids, _, _ in gs.CHECKS:
            if cid in expected:
                self.assertEqual(ids, [expected[cid]])
