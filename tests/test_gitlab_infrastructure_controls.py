import copy
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "roles", "gitlab_stig_audit", "filter_plugins"))
import gitlab_stig as gs
from gitlab_infrastructure_controls import evaluate_infrastructure_controls, VULN_IDS


class InfrastructureControlsTests(unittest.TestCase):
    def setUp(self):
        self.policy = dict(log_storage_volumes=["logs"], logging_failure_events=["write-failure"],
            authoritative_time_sources=["approved-time"], clock_max_offset_seconds=0.1, timestamp_log_sources=["audit"],
            enforcement_actions=["block-user"], reauthentication_triggers=["admin-mode"], pki_auth_paths=["idp"],
            federal_piv_issuers=["agency"], third_party_credential_providers=["approved-provider"], ficam_profiles=["approved-profile-v1"],
            protected_session_trust_stores=["gitlab"], approved_ca_fingerprints=["a" * 64], integrity_components=["repositories"],
            confidentiality_components=["repositories"], dos_safeguards=["gateway"], tls_connections=["web"],
            preparation_paths=["staging"], reception_paths=["handoff"], invalid_input_cases=["invalid-range"], retired_components=["old-agent"])
        self.root = {}
        common = dict(tested_at="2026-11-12T11:00:00Z", test_reference="test:42", configuration_reference="config:42")
        self.flags = {
            "failure_alerts": ("logging_failure_events", "detection_verified delivery_verified real_time_verified recipients_authorized"),
            "enforcement_logging": ("enforcement_actions", "change_correlated enforcement_recorded individual_attribution_verified"),
            "reauthentication": ("reauthentication_triggers", "trigger_exercised fresh_authentication_verified bypass_prevented"),
            "piv_acceptance": ("federal_piv_issuers", "trust_approved identity_mapping_verified successful_authentication_verified"),
            "piv_verification": ("federal_piv_issuers", "chain_verified validity_verified revocation_verified usage_verified identity_mapping_verified invalid_credentials_rejected"),
            "third_party_credentials": ("third_party_credential_providers", "provider_approved credential_approved successful_authentication_verified invalid_credentials_rejected"),
            "ficam_profiles": ("ficam_profiles", "profile_version_identified conformance_verified assurance_verified trust_verified claims_verified"),
            "at_rest_integrity": ("integrity_components", "scope_coverage_verified cryptographic_integrity_verified verification_material_protected verification_success"),
            "at_rest_confidentiality": ("confidentiality_components", "scope_coverage_verified encryption_verified key_management_verified approved_mechanism_verified"),
            "dos_protection": ("dos_safeguards", "threat_coverage_verified safeguard_enabled effective_limits_verified bypass_prevented"),
            "tls_versions": ("tls_connections", "approved_protocols_only certificate_validation_verified connection_coverage_verified"),
            "export_ciphers": ("tls_connections", "effective_cipher_policy_verified export_ciphers_disabled capable_enumeration_verified"),
            "transmission_crypto": ("tls_connections", "approved_algorithms_verified validated_modules_verified peer_validation_verified connection_coverage_verified"),
            "transmission_preparation": ("preparation_paths", "confidentiality_verified integrity_verified staging_queues_ipc_reviewed boundary_coverage_verified"),
            "reception": ("reception_paths", "confidentiality_verified integrity_verified decrypted_handoffs_reviewed boundary_coverage_verified"),
            "invalid_input_behavior": ("invalid_input_cases", "expected_behavior_documented expected_behavior_observed no_unintended_state_change continued_operation_verified")}
        for key, (policy_key, flags) in self.flags.items():
            item = dict(common, **dict.fromkeys(flags.split(), True))
            self.root[key] = dict(inventory_complete=True, gitlab_version="17.3.4", items={self.policy[policy_key][0]: item})
        self.item("enforcement_logging").update(change_reference="change:42", enforcement_record_reference="record:42")
        for key in ("third_party_credentials", "ficam_profiles"):
            self.item(key)["approval_profile_reference"] = "approved-profile:42"
        for key in ("at_rest_integrity", "at_rest_confidentiality", "transmission_crypto"):
            self.item(key)["cryptographic_mechanism_reference"] = "mechanism:42"
        self.item("export_ciphers").update(accepted_ciphers=["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"], enumeration_capability_reference="scanner:42")
        self.item("tls_versions")["approved_protocols"] = ["TLSv1.2", "TLSv1.3"]
        self.root["capacity_alerts"] = dict(inventory_complete=True, items=dict(logs=dict(common, threshold_percent=75,
            volume_coverage_verified=True, immediate_delivery_verified=True, sa_delivery_verified=True, isso_delivery_verified=True)))
        for key in ("clock_comparison", "clock_correction"):
            self.root[key] = dict(common, application_clock_coverage_verified=True, authoritative_source_verified=True,
                source="approved-time", provider="chrony", effective_source_polling_reviewed=True)
        self.root["clock_comparison"].update(maximum_comparison_interval_seconds=86400, comparison_history_verified=True)
        self.root["clock_correction"].update(correction_threshold_seconds=0.1, correction_behavior_verified=True)
        self.root["timestamp_precision"] = dict(inventory_complete=True, items=dict(audit=dict(common, format_coverage_verified=True)))
        self.root["revocation_cache"] = dict(inventory_complete=True, items=dict(idp=dict(common, cache_present=True,
            cache_freshness_verified=True, path_validation_supported=True, network_outage_exercised=True,
            cached_validation_verified=True, revoked_credentials_rejected=True)))
        self.root["protected_session_trust"] = dict(inventory_complete=True, items=dict(gitlab=dict(common,
            effective_trust_inventory_verified=True, overrides_reviewed=True, only_approved_authorities_verified=True)))
        self.root["high_availability"] = dict(common, mac_i=True, applicability_reference="MAC-I:42", cluster_verified=True,
            dependency_coverage_verified=True, replication_health_verified=True, failover_exercised=True)
        self.root["retired_components"] = dict(inventory_complete=True, gitlab_version="17.3.4", removal_policy_reference="cleanup:42",
            items={"old-agent": dict(common, removal_required=True, removed_verified=True, running_processes_reviewed=True, retained_components_reviewed=True)})
        self.ev = dict(collected_at="2026-11-12T12:01:00Z", version="17.3.4", audit_control_evidence=dict(
            observed_at="2026-11-12T12:00:00Z", reference="assessment:42", infrastructure_controls=self.root),
            infrastructure=dict(clock=dict(tracking_available=True), timestamp_logs=dict(audit=dict(seconds_count=5, unknown_count=0)),
                trust_bundles=dict(gitlab=dict(complete=True, fingerprints=["a" * 64])),
                retired_paths={"old-agent": dict(complete=True, paths={"/opt/old-agent": False})}))

    def item(self, section):
        return next(iter(self.root[section]["items"].values()))

    def checks(self):
        results = gs.sc.Results(gs.CHECK_META)
        evaluate_infrastructure_controls(results, self.ev, self.policy)
        return {r["id"]: r for r in results.items}

    def test_complete(self):
        result = self.checks()
        self.assertEqual(list(result), sorted(VULN_IDS))
        self.assertEqual({r["status"] for r in result.values()}, {gs.NF})

    def test_empty(self):
        self.ev, self.policy = {}, {}
        self.assertEqual({r["status"] for r in self.checks().values()}, {gs.NR})

    def test_stale_future_and_unreferenced(self):
        for key, value in (("observed_at", "2020-01-01T00:00:00Z"), ("observed_at", "2026-11-13T00:00:00Z"), ("reference", "")):
            self.ev["audit_control_evidence"][key] = value
            self.assertEqual({r["status"] for r in self.checks().values()}, {gs.NR})
            self.setUp()

    def test_every_declarative_rule_rejects_demonstrated_failure(self):
        ids = [65,69,70,72,73,74,75,77,78,80,81,82,83,84,85,86]
        for cid, (key, (_, flags)) in zip(ids, self.flags.items()):
            with self.subTest(cid=cid):
                flag = flags.split()[0]
                self.item(key)[flag] = False
                self.assertEqual(self.checks()["GLAB-%03d" % cid]["status"], gs.OPEN)
                self.item(key)[flag] = True

    def test_alert_and_clock_numeric_boundaries(self):
        self.item("capacity_alerts")["threshold_percent"] = 76
        self.root["clock_comparison"]["maximum_comparison_interval_seconds"] = 86401
        self.root["clock_correction"]["correction_threshold_seconds"] = 0.2
        for cid in (64,66,67):
            self.assertEqual(self.checks()["GLAB-%03d" % cid]["status"], gs.OPEN)
        self.policy["clock_max_offset_seconds"] = float("nan")
        self.assertEqual(self.checks()["GLAB-067"]["status"], gs.NR)

    def test_time_source_and_provider_need_evidence(self):
        self.root["clock_comparison"]["source"] = "unapproved"
        self.assertEqual(self.checks()["GLAB-066"]["status"], gs.OPEN)
        self.root["clock_comparison"]["source"] = "approved-time"
        self.ev["infrastructure"]["clock"]["tracking_available"] = False
        self.assertEqual(self.checks()["GLAB-066"]["status"], gs.NR)

    def test_timestamp_precision_and_unknown_formats(self):
        sample = self.ev["infrastructure"]["timestamp_logs"]["audit"]
        sample["coarse_count"] = 1
        self.assertEqual(self.checks()["GLAB-068"]["status"], gs.OPEN)
        sample["coarse_count"], sample["unknown_count"] = 0, 1
        self.assertEqual(self.checks()["GLAB-068"]["status"], gs.NR)

    def test_revocation_outage_failure_and_absence(self):
        self.item("revocation_cache")["cached_validation_verified"] = False
        self.assertEqual(self.checks()["GLAB-071"]["status"], gs.OPEN)
        self.policy["pki_auth_paths"] = []
        self.root["revocation_cache"] = dict(inventory_complete=True, none_present=True, scope_reference="inventory:42")
        self.assertEqual(self.checks()["GLAB-071"]["status"], gs.NA)
        self.ev["gitlab_yml"] = dict(smartcard=dict(enabled=True))
        self.assertEqual(self.checks()["GLAB-071"]["status"], gs.NR)

    def test_trust_fingerprints_and_incomplete_collection(self):
        sample = self.ev["infrastructure"]["trust_bundles"]["gitlab"]
        sample["fingerprints"].append("b" * 64)
        self.assertEqual(self.checks()["GLAB-076"]["status"], gs.OPEN)
        sample["complete"] = False
        self.assertEqual(self.checks()["GLAB-076"]["status"], gs.NR)
        self.policy["approved_ca_fingerprints"] = ["g" * 64]
        self.assertEqual(self.checks()["GLAB-076"]["status"], gs.NR)

    def test_ha_applicability_and_failover(self):
        self.root["high_availability"]["failover_exercised"] = False
        self.assertEqual(self.checks()["GLAB-079"]["status"], gs.OPEN)
        self.root["high_availability"] = dict(mac_i=False)
        self.assertEqual(self.checks()["GLAB-079"]["status"], gs.NR)
        self.root["high_availability"]["applicability_reference"] = "not-MAC-I:42"
        self.assertEqual(self.checks()["GLAB-079"]["status"], gs.NA)
        self.assertEqual(list(self.checks()), sorted(VULN_IDS))

    def test_live_cipher_observation_overrides_claimed_clean_policy(self):
        self.ev["infrastructure"]["cipher_scans"] = dict(web=dict(complete=True,
            accepted_ciphers=["TLS_RSA_EXPORT_WITH_RC4_40_MD5"], protocols=["TLSv1.0"]))
        self.assertEqual(self.checks()["GLAB-081"]["status"], gs.OPEN)
        self.assertEqual(self.checks()["GLAB-082"]["status"], gs.OPEN)
        self.ev["infrastructure"]["cipher_scans"]["web"] = dict(complete=False)
        self.assertEqual(self.checks()["GLAB-082"]["status"], gs.NR)

    def test_retired_component_presence_and_collection_errors(self):
        self.ev["infrastructure"]["retired_paths"]["old-agent"]["paths"]["/opt/old-agent"] = True
        self.assertEqual(self.checks()["GLAB-087"]["status"], gs.OPEN)
        self.ev["infrastructure"]["retired_paths"]["old-agent"]["paths"]["/opt/old-agent"] = False
        self.ev["infrastructure"]["errors"] = ["retired_paths: collection truncated"]
        self.assertEqual(self.checks()["GLAB-087"]["status"], gs.NR)

    def test_malformed_and_missing_inventory_items(self):
        for key in self.root:
            saved = self.root[key]
            self.root[key] = ["bad"]
            self.assertIn(gs.NR, {r["status"] for r in self.checks().values()})
            self.root[key] = saved
        self.policy["tls_connections"].append("registry")
        self.assertEqual(self.checks()["GLAB-081"]["status"], gs.NR)

    def test_explicit_bindings_and_missing_810(self):
        results = gs.gitlab_stig_evaluate(self.ev, dict(audit_controls=self.policy))
        with open(os.path.join(os.path.dirname(__file__), "..", "roles", "stig_common", "files", "app_server_srg_index.json")) as stream:
            index = json.load(stream)
        binding = gs.sc.stig_bind(results, index)
        for cid, vuln in VULN_IDS.items():
            self.assertEqual(binding["bound"][vuln], [cid])
        self.assertNotIn("V-204810", VULN_IDS.values())
        for cid in ("GLAB-079", "GLAB-080", "GLAB-081", "GLAB-082"):
            self.assertNotIn(cid, binding["ambiguous"])


class InfrastructureCollectorTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("infra_collector", os.path.join(os.path.dirname(__file__), "..", "roles", "gitlab_stig_audit", "files", "infrastructure_controls.py"))
        self.collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.collector)

    def test_timestamp_resolution_and_retired_paths_without_log_text(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "audit.json")
            with open(path, "w") as stream:
                for value in ("2026-11-12T11:00:00Z", "2026-11-12T11:00:00.123Z", "2026-11-12T11:00Z", "not-a-time"):
                    stream.write(json.dumps(dict(time=value, password="DUMMY-DO-NOT-EXPORT")) + "\n")
            with patch.object(self.collector, "command", return_value=(-1, "")):
                out = self.collector.collect(dict(timestamp_logs=dict(audit=path), retired_paths=dict(old=[path, os.path.join(directory, "missing")])))
            self.assertEqual(out["timestamp_logs"]["audit"], dict(seconds_count=2, coarse_count=1, unknown_count=1))
            self.assertTrue(out["retired_paths"]["old"]["paths"][path])
            self.assertFalse(out["retired_paths"]["old"]["paths"][os.path.join(directory, "missing")])
            self.assertNotIn("DUMMY-DO-NOT-EXPORT", json.dumps(out))

    def test_bundle_multiple_certificates_and_failed_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "ca.pem")
            with open(path, "w") as stream:
                stream.write("-----BEGIN CERTIFICATE-----\nTEST1\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nTEST2\n-----END CERTIFICATE-----")
            def command(argv, payload=None):
                return (0, "sha256 Fingerprint=" + ":".join(["AA"] * 32)) if argv[0] == "openssl" else (-1, "")
            with patch.object(self.collector, "command", side_effect=command):
                out = self.collector.collect(dict(trust_bundles=dict(gitlab=path)))
            self.assertTrue(out["trust_bundles"]["gitlab"]["complete"])
            self.assertEqual(len(out["trust_bundles"]["gitlab"]["fingerprints"]), 2)
            with patch.object(self.collector, "command", return_value=(-1, "")):
                out = self.collector.collect(dict(trust_bundles=dict(gitlab=path)))
            self.assertFalse(out["trust_bundles"]["gitlab"]["complete"])
            self.assertNotIn("TEST1", json.dumps(out))

    def test_optional_cipher_scan_parses_suites_and_uses_single_port(self):
        xml = '<nmaprun><host><ports><port><script id="ssl-enum-ciphers"><table key="TLSv1.2"><table key="ciphers"><table><elem key="name">TLS_RSA_EXPORT_WITH_RC4_40_MD5</elem></table></table></table></script></port></ports></host></nmaprun>'
        with patch.object(self.collector, "command", side_effect=lambda argv, payload=None: (0, xml) if argv[0] == "nmap" else (-1, "")) as command:
            out = self.collector.collect(dict(cipher_endpoints=dict(web=dict(host="gitlab.example.mil", port=443))))
        self.assertTrue(out["cipher_scans"]["web"]["complete"])
        self.assertEqual(out["cipher_scans"]["web"]["protocols"], ["TLSv1.2"])
        calls = [call.args[0] for call in command.call_args_list if call.args[0][0] == "nmap"]
        self.assertEqual(calls[0][calls[0].index("-p") + 1], "443")
        with patch.object(self.collector, "command", return_value=(-1, "")) as command:
            self.collector.collect({})
            self.assertFalse(any(call.args[0][0] == "nmap" for call in command.call_args_list))

    def test_bad_paths_and_truncated_inventory_stay_incomplete(self):
        with patch.object(self.collector, "command", return_value=(-1, "")):
            out = self.collector.collect(dict(trust_bundles=dict(store="relative.pem"), retired_paths=dict(old=["relative"]), timestamp_logs={str(i): "relative" for i in range(20)}))
        self.assertFalse(out["trust_bundles"]["store"]["complete"])
        self.assertFalse(out["retired_paths"]["old"]["complete"])
        self.assertTrue(out["errors"])

    def test_public_certificate_metadata_and_key_contents_never_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            cert=os.path.join(directory,"leaf.pem")
            secret=os.path.join(directory,"secret.key")
            with open(cert,"w") as stream:
                stream.write("-----BEGIN CERTIFICATE-----\nPUBLIC_TEST_ONLY\n-----END CERTIFICATE-----")
            with open(secret,"w") as stream:
                stream.write("DUMMY_PRIVATE_KEY_MUST_NOT_BE_READ")
            def command(argv,payload=None):
                if argv[0]=="openssl":
                    return 0,"SHA256 Fingerprint="+":".join(["AA"]*32)+"\n Policy: 1.2.3.4\nnotBefore=Jan  1 00:00:00 2026 GMT\nnotAfter=Jan  1 00:00:00 2027 GMT\n"
                return -1,""
            original=self.collector.bounded_read
            def bounded(path,*args,**kwargs):
                self.assertNotEqual(path,secret,"Key content must never be opened")
                return original(path,*args,**kwargs)
            with patch.object(self.collector,"command",side_effect=command),patch.object(self.collector,"bounded_read",side_effect=bounded):
                result=self.collector.collect(dict(public_certificates=dict(web=cert),key_storage=dict(keys=secret)))
            self.assertTrue(result["public_certificates"]["web"]["complete"])
            self.assertEqual(result["public_certificates"]["web"]["policy_oids"],["1.2.3.4"])
            self.assertTrue(result["key_storage"]["keys"]["exists"])
            self.assertNotIn("DUMMY_PRIVATE_KEY_MUST_NOT_BE_READ",json.dumps(result))
            self.assertNotIn("PUBLIC_TEST_ONLY",json.dumps(result))
