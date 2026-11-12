import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "roles", "gitlab_stig_audit", "filter_plugins"))
import gitlab_stig as gs
from gitlab_audit_extended import evaluate_extended


class ExtendedAuditTests(unittest.TestCase):
    def setUp(self):
        self.policy = dict(evidence_max_age_hours=24,
            privileged_access_paths={"sudo": "full_command", "shared-admin": "individual_identity"},
            required_log_tools=["/opt/gitlab/embedded/bin/svlogd"], approved_log_tool_writers=["root"],
            approved_log_tool_groups=["root"], backup_log_sources=["audit"], integrity_log_sources=["audit"])
        self.tool = self.policy["required_log_tools"][0]
        self.doc = dict(observed_at="2026-11-12T12:00:00Z", reference="report:42",
            privileged_recording=dict(paths={
                "sudo": dict(configuration_verified=True, coverage_verified=True, records=[dict(
                    time="2026-11-12T11:00:00Z", source="sudo:42", actor="alice", full_text_verified=True,
                    command_record_reference="session:42:command:1")]),
                "shared-admin": dict(configuration_verified=True, coverage_verified=True, records=[dict(
                    time="2026-11-12T11:00:00Z", source="session:43", individual="alice", account="root",
                    individual_identity_verified=True)])}),
            log_tool_protection=dict(inventory_complete=True, effective_access_reviewed=True,
                paths={self.tool: dict(access_restricted=True, modification_restricted=True, deletion_restricted=True)}),
            log_backup=dict(sources=dict(audit=dict(coverage_verified=True, separate_destination_verified=True,
                history_verified=True, destination_reference="backup:server2", schedule_interval_hours=24,
                maximum_success_gap_hours=48, last_success_at="2026-11-12T10:00:00Z"))),
            log_integrity=dict(sources=dict(audit=dict(mechanism="digital_signature", coverage_verified=True,
                mechanism_approved=True, verification_material_protected=True, verification_success=True,
                configuration_reference="signer:42", verification_reference="verify:42",
                last_verified_at="2026-11-12T11:00:00Z"))))
        self.ev = dict(collected_at="2026-11-12T12:01:00Z", audit_control_evidence=self.doc,
            log_tools=dict(acl_complete=True, paths={self.tool: dict(exists=True, nodes=[
                dict(path=self.tool, owner="root", group="root", mode="0755", kind="file"),
                dict(path="/opt/gitlab/embedded/bin", owner="root", group="root", mode="0755", kind="directory")])}))

    def checks(self):
        result = gs.sc.Results(gs.CHECK_META)
        evaluate_extended(result, self.ev, self.policy)
        return {r["id"]: r["status"] for r in result.items}

    def test_complete(self):
        self.assertEqual(set(self.checks().values()), {gs.NF})

    def test_empty(self):
        self.ev, self.policy = {}, {}
        self.assertEqual(set(self.checks().values()), {gs.NR})

    def test_stale_unreferenced_future_evidence(self):
        for key, value in [("reference", ""), ("observed_at", "2026-11-01T12:00:00Z"),
                           ("observed_at", "2026-11-13T12:00:00Z")]:
            with self.subTest(key=key, value=value):
                self.ev["audit_control_evidence"] = dict(self.doc, **{key: value})
                self.assertEqual(set(self.checks().values()), {gs.NR})

    def test_modes_do_not_prove_effective_authorization(self):
        self.doc["log_tool_protection"].pop("effective_access_reviewed")
        for cid in ("GLAB-036", "GLAB-037", "GLAB-038"):
            self.assertEqual(self.checks()[cid], gs.NR)

    def test_tool_permissions_and_parent_deletion(self):
        nodes = self.ev["log_tools"]["paths"][self.tool]["nodes"]
        nodes[0]["mode"] = "0777"
        self.assertEqual(self.checks()["GLAB-037"], gs.OPEN)
        self.assertEqual(self.checks()["GLAB-038"], gs.NF)
        nodes[1]["mode"] = "0777"
        self.assertEqual(self.checks()["GLAB-038"], gs.OPEN)

    def test_owner_group_and_sticky_ancestor(self):
        node = self.ev["log_tools"]["paths"][self.tool]["nodes"][1]
        node["group"], node["mode"] = "users", "0770"
        self.assertEqual(self.checks()["GLAB-038"], gs.OPEN)
        node["group"], node["mode"] = "root", "1777"
        self.assertEqual(self.checks()["GLAB-038"], gs.NR)
        node["owner"], node["mode"] = "mallory", "0755"
        self.assertEqual(self.checks()["GLAB-038"], gs.OPEN)

    def test_discovered_unreviewed_tool_blocks_pass(self):
        self.ev["log_tools"]["paths"]["/usr/bin/agent"] = copy.deepcopy(self.ev["log_tools"]["paths"][self.tool])
        self.assertEqual(self.checks()["GLAB-036"], gs.NR)

    def test_missing_required_tool(self):
        self.ev["log_tools"]["paths"][self.tool] = dict(exists=False)
        self.assertEqual(self.checks()["GLAB-037"], gs.OPEN)

    def test_missing_acl_and_truncation(self):
        for key, value in (("acl_complete", False), ("truncated", True)):
            self.ev["log_tools"][key] = value
            self.assertEqual(self.checks()["GLAB-037"], gs.NR)

    def test_tool_access_denied_by_review(self):
        self.doc["log_tool_protection"]["paths"][self.tool]["access_restricted"] = False
        self.assertEqual(self.checks()["GLAB-036"], gs.OPEN)

    def test_privileged_identity_must_identify_individual(self):
        item = self.doc["privileged_recording"]["paths"]["shared-admin"]
        item["records"][0]["individual"] = "root"
        self.assertEqual(self.checks()["GLAB-035"], gs.NR)
        item["recording_gap"] = True
        self.assertEqual(self.checks()["GLAB-035"], gs.OPEN)

    def test_command_reference_and_recent_observation_required(self):
        record = self.doc["privileged_recording"]["paths"]["sudo"]["records"][0]
        record["command_record_reference"] = ""
        self.assertEqual(self.checks()["GLAB-035"], gs.NR)
        record["command_record_reference"], record["time"] = "session:42", "2020-01-01T00:00:00Z"
        self.assertEqual(self.checks()["GLAB-035"], gs.NR)

    def test_backup_interval_history_and_separation(self):
        item = self.doc["log_backup"]["sources"]["audit"]
        for key, value in (("schedule_interval_hours", 169), ("maximum_success_gap_hours", 169),
                           ("separate_destination_verified", False), ("last_success_at", "2026-11-01T00:00:00Z")):
            saved = item[key]
            item[key] = value
            self.assertEqual(self.checks()["GLAB-039"], gs.OPEN)
            item[key] = saved
        item["schedule_interval_hours"] = 168
        self.assertEqual(self.checks()["GLAB-039"], gs.NF)
        item["maximum_success_gap_hours"] = float("nan")
        self.assertEqual(self.checks()["GLAB-039"], gs.NR)

    def test_integrity_tls_or_plain_hash_insufficient(self):
        item = self.doc["log_integrity"]["sources"]["audit"]
        for mechanism in ("tls", "sha256", "encryption"):
            item["mechanism"] = mechanism
            self.assertEqual(self.checks()["GLAB-040"], gs.NR)
        item["mechanism"] = "protected_hash_manifest"
        self.assertEqual(self.checks()["GLAB-040"], gs.NF)
        item["verification_material_protected"] = False
        self.assertEqual(self.checks()["GLAB-040"], gs.OPEN)

    def test_integrity_failure_and_old_verification(self):
        item = self.doc["log_integrity"]["sources"]["audit"]
        item["last_verified_at"] = "2026-01-01T00:00:00Z"
        self.assertEqual(self.checks()["GLAB-040"], gs.NR)
        item["verification_success"] = False
        self.assertEqual(self.checks()["GLAB-040"], gs.OPEN)

    def test_malformed_sections_do_not_crash(self):
        for key in ("privileged_recording", "log_tool_protection", "log_backup", "log_integrity"):
            self.ev["audit_control_evidence"] = dict(self.doc, **{key: ["bad"]})
            self.assertIn(gs.NR, self.checks().values())

    def test_rule_mappings(self):
        expected = dict(zip(range(35, 41), ("000101", "000121", "000122", "000123", "000125", "000126")))
        for cid, _, ids, _, _ in gs.CHECKS:
            index = int(cid.split("-")[1])
            if index in expected:
                self.assertEqual(ids, ["SRG-APP-" + expected[index]])

    def test_collector_resolves_tools_and_reports_acls(self):
        import contextlib
        import io
        import json
        import runpy
        import tempfile
        import types
        from unittest.mock import patch
        collector = os.path.join(os.path.dirname(__file__), "..", "roles", "gitlab_stig_audit", "files", "audit_controls.py")
        with tempfile.TemporaryDirectory() as directory:
            tool = os.path.join(directory, "logger")
            with open(tool, "w") as stream:
                stream.write("tool content must never be collected")
            output = io.StringIO()
            user = types.SimpleNamespace(pw_name="root")
            group = types.SimpleNamespace(gr_name="root")
            modules = {"pwd": types.SimpleNamespace(getpwuid=lambda _: user),
                       "grp": types.SimpleNamespace(getgrgid=lambda _: group)}
            acl = types.SimpleNamespace(stdout=b"# file: logger\nuser::rwx\n", returncode=0)
            with patch.dict(sys.modules, modules), patch.object(sys, "argv", [collector, "missing-log", "", directory, json.dumps([tool]), directory]), patch("subprocess.run", return_value=acl), patch("glob.iglob", return_value=iter(())), contextlib.redirect_stdout(output):
                runpy.run_path(collector, run_name="__main__")
            evidence = json.loads(output.getvalue())
            local = evidence["log_tools"]
            self.assertTrue(local["acl_complete"])
            nodes = local["paths"][tool]["nodes"]
            self.assertIn(os.path.realpath(tool), [node["path"] for node in nodes])
            self.assertIn(os.path.realpath(directory), [node["path"] for node in nodes])
            self.assertNotIn("tool content must never be collected", output.getvalue())
            self.assertTrue(evidence["errors"])
