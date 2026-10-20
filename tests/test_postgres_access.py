"""Access authorization comparison: allowlists must not silently authorize excess access."""
import copy
import json
import unittest

from test_postgres_stig import pg, hardened, SETTINGS, by_id


def access_row(**changes):
    row = dict(role="reader", objects="tables", schema="app", object="orders", privilege="SELECT",
               grant_option=False, creator="")
    row.update(changes)
    return row


class AccessTests(unittest.TestCase):
    def setUp(self):
        self.ev = hardened()
        self.sql = json.loads(self.ev["sql"])
        self.ev["access"] = [dict(db="postgres", version=1, access=[access_row()],
                                  roles=[dict(name="reader", super=False, createrole=False, createdb=False,
                                              replication=False, bypassrls=False)], memberships=[])]
        self.policy = [dict(role="reader", database="postgres", objects="tables", schema="app",
                            object="orders", privileges=["SELECT"])]
        self.settings = dict(SETTINGS, approved_access=self.policy,
                             approved_access_hba=[{k: v for k, v in r.items() if k != "line"}
                                                  for r in self.sql["hba"]],
                             access_system_review="Access baseline 1, DBA review 2026-10-20")

    def result(self):
        self.ev["sql"] = json.dumps(self.sql)
        return by_id(pg.postgres_stig_evaluate(self.ev, self.settings))["CD16-00-000300"]

    def test_exact_approval_and_legacy_manual_behavior(self):
        self.assertEqual(self.result()["status"], pg.NF)
        self.settings.pop("approved_access")
        self.assertEqual(self.result()["status"], pg.NR)

    def test_database_role_schema_object_and_privilege_are_restricted(self):
        for field, value in (("database", "other"), ("role", "other"), ("schema", "other"),
                             ("object", "other"), ("privileges", ["INSERT"])):
            with self.subTest(field=field):
                policy = copy.deepcopy(self.policy)
                policy[0][field] = value
                self.settings["approved_access"] = policy
                self.assertEqual(self.result()["status"], pg.OPEN)

    def test_grant_option_and_ownership_need_explicit_approval(self):
        self.ev["access"][0]["access"][0]["grant_option"] = True
        self.assertEqual(self.result()["status"], pg.OPEN)
        self.policy[0]["grant_option"] = True
        self.assertEqual(self.result()["status"], pg.NF)
        self.ev["access"][0]["access"].append(access_row(privilege="OWNER"))
        self.assertEqual(self.result()["status"], pg.OPEN)
        self.policy[0]["privileges"].append("OWNER")
        self.assertEqual(self.result()["status"], pg.NF)

    def test_public_and_default_privileges(self):
        self.ev["access"][0]["access"] = [access_row(role="PUBLIC", objects="default_functions",
                                                   object="*", privilege="EXECUTE", creator="writer")]
        self.assertEqual(self.result()["status"], pg.OPEN)
        self.policy.append(dict(role="PUBLIC", database="postgres", objects="default_functions", schema="app",
                                privileges=["EXECUTE"], creator="writer"))
        self.assertEqual(self.result()["status"], pg.NF)
        self.policy[-1]["creator"] = "other"
        self.assertEqual(self.result()["status"], pg.OPEN)

    def test_membership_inheritance_set_role_and_admin_are_explicit(self):
        memberships = self.ev["access"][0]["memberships"]
        memberships.append(dict(role="alice", object="reader", admin=False, inherit=True, set=True))
        self.assertEqual(self.result()["status"], pg.OPEN)
        self.policy.append(dict(role="alice", database="*", objects="roles", object="reader",
                                privileges=["MEMBER", "INHERIT", "SET"]))
        self.assertEqual(self.result()["status"], pg.NF)
        memberships[0]["admin"] = True
        self.assertEqual(self.result()["status"], pg.OPEN)
        self.policy[-1]["privileges"].append("ADMIN")
        self.assertEqual(self.result()["status"], pg.NF)
        memberships.append(dict(role="bob", object="alice", admin=False, inherit=True, set=True))
        self.assertEqual(self.result()["status"], pg.OPEN)

    def test_predefined_role_powers_and_superuser_are_global(self):
        self.ev["access"][0]["memberships"].append(
            dict(role="reader", object="pg_read_all_data", admin=False, inherit=True, set=False))
        self.assertEqual(self.result()["status"], pg.OPEN)
        self.policy.append(dict(role="reader", database="postgres", objects="roles", object="pg_read_all_data",
                                privileges=["MEMBER", "INHERIT"]))
        self.assertEqual(self.result()["status"], pg.NR)
        self.policy[-1]["database"] = "*"
        self.assertEqual(self.result()["status"], pg.NF)
        self.ev["access"][0]["roles"][0]["super"] = True
        self.assertEqual(self.result()["status"], pg.OPEN)
        self.policy.append(dict(role="reader", database="*", objects="roles", privileges=["SUPERUSER"]))
        self.assertEqual(self.result()["status"], pg.NF)

    def test_missing_failed_or_unsupported_database_evidence_never_passes(self):
        for snapshot in (None, {}, dict(db="postgres", version=2, access=[], roles=[], memberships=[])):
            with self.subTest(snapshot=snapshot):
                self.ev["access"] = [] if snapshot is None else [snapshot]
                self.assertEqual(self.result()["status"], pg.NR)
        self.ev["access"] = []
        self.sql["databases"].append(dict(name="unreachable", connect=True))
        self.assertIn("unreachable", str(self.result()["evidence"]))

    def test_partial_inventory_still_reports_known_violation(self):
        self.sql["databases"].append(dict(name="unreachable", connect=True))
        self.ev["access"][0]["access"][0]["privilege"] = "DELETE"
        self.assertEqual(self.result()["status"], pg.OPEN)

    def test_disabled_database_not_silently_excluded(self):
        self.sql["databases"].append(dict(name="closed", connect=False))
        self.assertEqual(self.result()["status"], pg.NR)
        self.sql["databases"][-1]["name"] = "template0"
        self.assertEqual(self.result()["status"], pg.NF)

    def test_hba_must_match_and_be_read_live(self):
        self.sql["hba"][0]["user"] = ["other"]
        self.assertEqual(self.result()["status"], pg.OPEN)
        self.sql["hba"][0]["error"] = "invalid authentication method"
        self.assertEqual(self.result()["status"], pg.NR)
        self.sql["hba"] = []
        self.assertEqual(self.result()["status"], pg.NR)

    def test_hba_order_is_part_of_the_approval(self):
        self.settings["approved_access_hba"].reverse()
        self.assertEqual(self.result()["status"], pg.OPEN)

    def test_explicit_all_object_approval(self):
        self.settings["approved_access"] = [dict(role="reader", database="*", objects="*", privileges=["*"],
                                                creator="*", grant_option=True)]
        self.ev["access"][0]["roles"][0]["super"] = True
        self.ev["access"][0]["access"].append(access_row(objects="default_functions", privilege="EXECUTE",
                                                       creator="reader"))
        self.assertEqual(self.result()["status"], pg.NF)

    def test_missing_policy_sections_and_baseline_review(self):
        self.settings["approved_access_hba"] = None
        self.assertEqual(self.result()["status"], pg.NR)
        self.settings["approved_access_hba"] = []
        self.assertEqual(self.result()["status"], pg.OPEN)
        self.settings["approved_access_hba"] = self.sql["hba"]
        # Policy line numbers are not accepted: the policy must use normalized entries.
        self.assertEqual(self.result()["status"], pg.NR)
        self.settings["approved_access_hba"] = [{k: v for k, v in r.items() if k != "line"}
                                                for r in self.sql["hba"]]
        self.settings["access_system_review"] = ""
        self.assertEqual(self.result()["status"], pg.NR)

    def test_invalid_policy_never_crashes_or_passes(self):
        for policy in ("reader", {}, [None], [dict(self.policy[0], privileges="SELECT")],
                       [dict(self.policy[0], privleges=["SELECT"])],
                       [dict(self.policy[0], grant_option="false")],
                       [dict(self.policy[0], objects="default_tables")]):
            with self.subTest(policy=policy):
                self.settings["approved_access"] = policy
                self.assertEqual(self.result()["status"], pg.NR)

    def test_wildcards_are_explicit_and_case_is_preserved(self):
        self.policy[0].update(database="*", schema="*", object="*", privileges=["*"])
        self.assertEqual(self.result()["status"], pg.NF)
        self.ev["access"][0]["access"][0]["role"] = "Reader"
        self.assertEqual(self.result()["status"], pg.OPEN)

    def test_malformed_record_never_passes(self):
        for row in ({}, access_row(objects=[]), access_row(privilege=[]), access_row(objects="unsupported")):
            with self.subTest(row=row):
                self.ev["access"][0]["access"] = [row]
                self.assertEqual(self.result()["status"], pg.NR)

    def test_empty_allowlist_approves_nothing(self):
        self.settings["approved_access"] = []
        self.assertEqual(self.result()["status"], pg.OPEN)

    def test_missing_database_inventory_never_passes(self):
        self.sql["databases"] = []
        self.assertEqual(self.result()["status"], pg.NR)

    def test_invalid_hba_policy_returns_review(self):
        for policy in ("local all all peer", [None], [dict(type="local", database="all", user=["postgres"],
                                                        method="peer")]):
            with self.subTest(policy=policy):
                self.settings["approved_access_hba"] = policy
                self.assertEqual(self.result()["status"], pg.NR)

    def test_json_snapshots_are_decoded(self):
        self.ev["access"] = [json.dumps(self.ev["access"][0])]
        self.assertEqual(self.result()["status"], pg.NF)


if __name__ == "__main__":
    unittest.main()
