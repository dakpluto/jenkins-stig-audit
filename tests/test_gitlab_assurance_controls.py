import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "roles", "gitlab_stig_audit", "filter_plugins"))
import gitlab_stig as gs
from gitlab_assurance_controls import evaluate_assurance_controls, VULN_IDS


class AssuranceControlsTests(unittest.TestCase):
    def setUp(self):
        self.policy = dict(privilege_modification_operations=["change-role"], privilege_deletion_operations=["revoke-role"],
            management_interfaces=["web"], session_termination_methods=["logout"], key_management_scopes=["database"],
            certificate_policy_requirements=dict(web={"class":3,"policy_oids":["1.2.3.4"],"approval_reference":"approval:42"}),
            log_transfer_sources=["audit"], log_transfer_real_time_limit_seconds=5, classified_crypto_paths=["classified-link"],
            audit_information_scopes=["audit"], mfa_access_matrix=dict(privileged=["web", "ssh"]), maintenance_paths=["maintenance"],
            organization_trust_stores=["gitlab"], approved_trust_anchors=dict(gitlab=["a" * 64]), cryptographic_key_stores=["secrets"])
        common = dict(tested_at="2026-11-12T11:00:00Z", test_reference="test:42", configuration_reference="config:42")
        def item(*flags):
            return dict(common, **dict.fromkeys(flags, True))
        self.root = {}
        for key, operation in (("privilege_modification", "change-role"), ("privilege_deletion", "revoke-role")):
            entry = item("coverage_verified")
            entry["records"] = [dict(operation=operation, outcome=outcome, actor="alice", target="user:42", source="record:42", individual_attribution_verified=True, time="2026-11-12T11:00:00Z") for outcome in ("success", "failure")]
            self.root[key] = dict(inventory_complete=True, gitlab_version="17.3.4", items={operation:entry})
        session = dict(actor="alice", session_reference="report-session:42", started_at="2026-11-12T10:00:00Z", ended_at="2026-11-12T11:00:00Z", termination_method="logout", start_source="start:42", end_source="end:42", correlation_verified=True)
        self.root["management_session_times"] = dict(inventory_complete=True, items=dict(web=dict(item("logging_coverage_verified"), records=[session])))
        pair = dict(concurrency_reference="overlap:42", sessions=[dict(actor="alice", source="session:1", workstation_reference="workstation:1", started_at="2026-11-12T10:00:00Z", ended_at="2026-11-12T11:00:00Z"), dict(actor="alice", source="session:2", workstation_reference="workstation:2", started_at="2026-11-12T10:30:00Z", ended_at="2026-11-12T11:30:00Z")])
        self.root["concurrent_management_logons"] = dict(inventory_complete=True, items=dict(web=dict(item("logging_coverage_verified", "distinct_workstations_verified", "concurrency_recorded"), records=[pair])))
        self.root["key_management"] = dict(inventory_complete=True, items=dict(database=dict(item("approved_technology_verified", "generation_distribution_verified", "access_storage_verified", "rotation_revocation_verified", "backup_destruction_verified"), approval_reference="approved:42", lifecycle_policy_reference="lifecycle:42")))
        self.root["certificate_class"] = dict(inventory_complete=True, items=dict(web=dict(item("approving_authority_verified", "certificate_class_verified", "chain_verified", "intended_usage_verified"), certificate_fingerprint="a" * 64)))
        self.root["log_transfer"] = dict(inventory_complete=True, items=dict(audit=dict(item("coverage_verified", "destination_receipt_verified", "history_verified", "real_time_verified"), interconnected=True, maximum_delivery_lag_seconds=1, destination_reference="collector:42", connectivity_scope_reference="network:42")))
        self.root["classified_crypto"] = dict(inventory_complete=True, classified_information_present=True, items={"classified-link":dict(item("nsa_approval_verified", "approved_configuration_verified", "operational_environment_verified", "scope_coverage_verified"), nsa_approval_reference="approval:42")})
        self.root["audit_information_alerts"] = dict(inventory_complete=True, recipient_policy_reference="ISSM:42", items=dict(audit=dict(events={event:item("unauthorized_event_detected", "delivery_verified", "recipient_roles_verified") for event in ("access", "modification", "deletion")})))
        self.root["mfa_strength"] = dict(inventory_complete=True, strength_policy_reference="MFA:42", accounts=dict(privileged={path:item("multiple_factors_verified", "mechanism_strength_verified", "enrollment_enforced", "bypass_prevented", "recovery_exceptions_reviewed") for path in ("web", "ssh")}))
        self.root["maintenance_separation"] = dict(inventory_complete=True, items=dict(maintenance=dict(item("logical_separation_verified", "routes_controls_verified", "other_session_separation_verified", "bypass_prevented"), topology_reference="topology:42")))
        self.root["organization_trust"] = dict(inventory_complete=True, items=dict(gitlab=item("effective_inventory_verified", "overrides_reviewed", "approval_verified")))
        self.root["key_storage"] = dict(inventory_complete=True, safeguard_policy_reference="keys:42", items=dict(secrets=dict(item("safeguards_verified", "effective_access_verified", "backup_protection_verified"), hardware_required=False, storage_type="file")))
        self.ev = dict(collected_at="2026-11-12T12:01:00Z", version="17.3.4", audit_control_evidence=dict(observed_at="2026-11-12T12:00:00Z", reference="review:42", assurance_controls=self.root), infrastructure=dict(public_certificates=dict(web=dict(complete=True, fingerprint="a" * 64, policy_oids=["1.2.3.4"], not_before="2026-01-01T00:00:00Z", not_after="2027-01-01T00:00:00Z")), trust_bundles=dict(gitlab=dict(complete=True, fingerprints=["a" * 64])), key_storage=dict(secrets=dict(complete=True, exists=True, world_readable=False, world_writable=False))))

    def checks(self, privileged_status=None):
        results = gs.sc.Results(gs.CHECK_META)
        if privileged_status is not None:
            results.add("GLAB-063", privileged_status, "Reused role/operation evidence", "source:42")
        evaluate_assurance_controls(results, self.ev, self.policy)
        return {r["id"]:r for r in results.items if r["id"] in VULN_IDS}

    def test_complete_and_privileged_activity_reuse(self):
        result = self.checks(gs.NF)
        self.assertEqual({r["status"] for r in result.values()}, {gs.NF})
        self.assertEqual(self.checks(gs.OPEN)["GLAB-090"]["status"], gs.OPEN)
        self.assertEqual(self.checks()["GLAB-090"]["status"], gs.NR)

    def test_missing_and_stale(self):
        self.ev["audit_control_evidence"]["observed_at"] = "2020-01-01T00:00:00Z"
        self.assertEqual({r["status"] for r in self.checks().values()}, {gs.NR})
        self.ev,self.policy = {},{}
        self.assertEqual({r["status"] for r in self.checks().values()}, {gs.NR})

    def test_privilege_both_outcomes_required(self):
        self.root["privilege_modification"]["items"]["change-role"]["records"].pop()
        self.assertEqual(self.checks()["GLAB-088"]["status"], gs.NR)
        self.root["privilege_deletion"]["items"]["revoke-role"]["coverage_verified"] = False
        self.assertEqual(self.checks()["GLAB-089"]["status"], gs.OPEN)

    def test_session_endings_and_overlap(self):
        record=self.root["management_session_times"]["items"]["web"]["records"][0]
        record["ended_at"]="2026-11-12T09:00:00Z"
        self.assertEqual(self.checks()["GLAB-091"]["status"], gs.OPEN)
        pair=self.root["concurrent_management_logons"]["items"]["web"]["records"][0]
        pair["sessions"][1]["started_at"]="2026-11-12T11:01:00Z"
        self.assertEqual(self.checks()["GLAB-092"]["status"], gs.NR)
        pair["sessions"][1]["started_at"]="2026-11-12T10:30:00Z"
        pair["sessions"][1]["workstation_reference"]="workstation:1"
        self.assertEqual(self.checks()["GLAB-092"]["status"], gs.NR)

    def test_key_management_and_certificate_policy(self):
        self.root["key_management"]["items"]["database"]["rotation_revocation_verified"]=False
        self.assertEqual(self.checks()["GLAB-093"]["status"], gs.OPEN)
        sample=self.ev["infrastructure"]["public_certificates"]["web"]
        sample["policy_oids"]=["9.9.9"]
        self.assertEqual(self.checks()["GLAB-094"]["status"], gs.OPEN)
        sample["policy_oids"]=["1.2.3.4"]
        sample["not_after"]="2025-01-01T00:00:00Z"
        self.assertEqual(self.checks()["GLAB-094"]["status"], gs.OPEN)

    def test_transfer_timing_for_both_connectivity_modes(self):
        item=self.root["log_transfer"]["items"]["audit"]
        item["maximum_delivery_lag_seconds"]=6
        self.assertEqual(self.checks()["GLAB-095"]["status"], gs.OPEN)
        item.update(interconnected=False,transfer_interval_hours=168,maximum_success_gap_hours=168,last_receipt_at="2026-11-12T11:00:00Z")
        self.assertEqual(self.checks()["GLAB-095"]["status"], gs.NF)
        item["last_receipt_at"]="2026-11-01T00:00:00Z"
        self.assertEqual(self.checks()["GLAB-095"]["status"], gs.OPEN)

    def test_classified_and_maintenance_absence_requires_scope(self):
        for key,policy,cid in (("classified_crypto","classified_crypto_paths","GLAB-096"),("maintenance_separation","maintenance_paths","GLAB-099")):
            self.policy[policy]=[]
            self.root[key]=dict(inventory_complete=True,classified_information_present=False,none_present=True)
            self.assertEqual(self.checks()[cid]["status"],gs.NR)
            self.root[key]["scope_reference"]="scope:42"
            self.assertEqual(self.checks()[cid]["status"],gs.NA)

    def test_all_audit_alert_events_and_mfa_paths_required(self):
        self.root["audit_information_alerts"]["items"]["audit"]["events"].pop("deletion")
        self.assertEqual(self.checks()["GLAB-097"]["status"],gs.NR)
        self.root["mfa_strength"]["accounts"]["privileged"]["ssh"]["bypass_prevented"]=False
        self.assertEqual(self.checks()["GLAB-098"]["status"],gs.OPEN)

    def test_unapproved_trust_and_world_exposed_key(self):
        self.ev["infrastructure"]["trust_bundles"]["gitlab"]["fingerprints"].append("b"*64)
        self.assertEqual(self.checks()["GLAB-100"]["status"],gs.OPEN)
        self.ev["infrastructure"]["key_storage"]["secrets"]["world_readable"]=True
        self.assertEqual(self.checks()["GLAB-101"]["status"],gs.OPEN)
        item=self.root["key_storage"]["items"]["secrets"]
        self.ev["infrastructure"]["key_storage"]["secrets"]["world_readable"]=False
        item["hardware_required"]=True
        self.assertEqual(self.checks()["GLAB-101"]["status"],gs.NR)
        item["hardware_protection_verified"]=False
        self.assertEqual(self.checks()["GLAB-101"]["status"],gs.OPEN)

    def test_every_rule_has_independent_binding(self):
        results=gs.gitlab_stig_evaluate(self.ev,dict(audit_controls=self.policy))
        with open(os.path.join(os.path.dirname(__file__),"..","roles","stig_common","files","app_server_srg_index.json")) as stream:
            index=json.load(stream)
        bound=gs.sc.stig_bind(results,index)["bound"]
        for cid,vid in VULN_IDS.items():
            self.assertEqual(bound[vid],[cid])

    def test_malformed_sections(self):
        for key in self.root:
            saved=self.root[key]
            self.root[key]=["bad"]
            self.assertIn(gs.NR,{r["status"] for r in self.checks().values()})
            self.root[key]=saved
