"""Unit tests for the postgres_stig_audit (Crunchy Data Postgres 16 STIG) evaluation logic.

Run with:  python -m unittest discover -s tests -v
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "roles", "postgres_stig_audit", "filter_plugins"))
import postgres_stig as pg  # noqa: E402

PGDATA = "/var/lib/pgsql/16/data"
LOG = PGDATA + "/log"
INSTALL = "/usr/pgsql-16"
SETTINGS = {"pg_user": "postgres", "approved_superusers": ["postgres"], "approved_admins": ["postgres"],
            "hba_exceptions": [r"^local all postgres\s+peer$"], "approved_extensions": ["pgaudit", "pgcrypto"],
            "approved_ports": [5432], "max_connections": "200", "log_timezone": "UTC", "syslog_facility": "local0",
            "classified": False, "security_labeling_required": False, "categories_required": None,
            "min_version": "16.4", "overrides": {}}


def stat(path, owner="postgres", group="postgres", mode="600", kind="f"):
    return "%s|%s|%s|%s|%s|1700000000.0|100" % (path, owner, group, mode, kind)


def settings(**over):
    s = {"data_directory": PGDATA, "config_file": PGDATA + "/postgresql.conf", "hba_file": PGDATA + "/pg_hba.conf",
         "ident_file": PGDATA + "/pg_ident.conf", "port": "5432", "listen_addresses": "*", "max_connections": "100",
         "ssl": "on", "ssl_cert_file": "server.crt", "ssl_key_file": "server.key", "ssl_ca_file": "root.crt",
         "ssl_crl_file": "root.crl", "password_encryption": "scram-sha-256", "shared_preload_libraries": "pgaudit",
         "pgaudit.log": "ddl, role, read, write", "pgaudit.log_catalog": "on", "log_destination": "stderr, syslog",
         "logging_collector": "on", "log_directory": "log", "log_file_mode": "0600",
         "log_line_prefix": "< %m %a %u %d %r %p %i %e %s %c >", "log_connections": "on", "log_disconnections": "on",
         "log_min_messages": "warning", "log_min_error_statement": "error", "client_min_messages": "error",
         "statement_timeout": "10000", "log_timezone": "UTC", "syslog_facility": "local0", "log_hostname": "off"}
    s.update(over)
    return dict((k, {"setting": v, "unit": None, "source": "configuration file"}) for k, v in s.items())


def hardened():
    sql = {
        "version": "PostgreSQL 16.6 on x86_64-pc-linux-gnu",
        "settings": settings(),
        "file_settings": {"tcp_keepalives_idle": "10", "tcp_keepalives_interval": "10", "tcp_keepalives_count": "10"},
        "roles": [{"name": "postgres", "super": True, "createrole": True, "createdb": True, "login": True,
                   "replication": True, "bypassrls": True, "connlimit": 10},
                  {"name": "app", "super": False, "createrole": False, "createdb": False, "login": True,
                   "replication": False, "bypassrls": False, "connlimit": 50}],
        "passwords": [{"name": "postgres", "kind": "none"}, {"name": "app", "kind": "scram-sha-256"}],
        "hba": [{"line": 1, "type": "local", "database": ["all"], "user": ["postgres"], "method": "peer", "options": None},
                {"line": 2, "type": "hostssl", "database": ["all"], "user": ["all"], "address": "10.0.0.0",
                 "netmask": "255.0.0.0", "method": "cert", "options": ["clientcert=verify-ca"]}],
        "ident": [{"map": "cac", "system": "/^(.*)$", "user": "\\1"}],
        "databases": [{"name": "postgres", "acl": None, "connect": True}],
        "pgcrypto_available": True,
    }
    db = {"db": "postgres", "extensions": [{"name": "plpgsql"}, {"name": "pgaudit"}], "untrusted_languages": None,
          "secdef": None, "schemas": [{"name": "public", "owner": "pg_database_owner", "acl": "{pg_database_owner=UC/pg_database_owner,=U/pg_database_owner}",
                                       "public_create": False}],
          "object_owners": ["app"], "function_owners": None, "rls_tables": 0}
    return {
        "version": "16.6", "running": True, "pgdata": PGDATA, "install_dir": INSTALL,
        "packages": "postgresql16|16.6-1PGDG.rhel8|Crunchy Data Solutions, Inc.\n"
                    "postgresql16-server|16.6-1PGDG.rhel8|Crunchy Data Solutions, Inc.\npgaudit_16|16.0-1|Crunchy",
        "sql": json.dumps(sql), "dbs": [json.dumps(db)], "files": {},
        "pgdata_stats": [stat(PGDATA, mode="700", kind="d"), stat(PGDATA + "/postgresql.conf"),
                         stat(PGDATA + "/pg_hba.conf")],
        "pgdata_violations": [],
        "file_stats": [stat(PGDATA + "/postgresql.conf"), stat(PGDATA + "/server.key"),
                       stat(PGDATA + "/root.crl"), stat(PGDATA, mode="700", kind="d")],
        "log_stats": [stat(LOG, mode="700", kind="d"), stat(LOG + "/postgresql-Mon.log")],
        "latest_log": "postgresql-Mon.log",
        "log_counts": ["AUDIT:|120", "connection authorized|30", "permission denied|2"],
        "install_stats": [stat(INSTALL, "root", "root", "755", "d"), stat(INSTALL + "/bin", "root", "root", "755", "d"),
                          stat(INSTALL + "/share/extension/pgaudit--16.0.sql", "root", "root", "644")],
        "install_violations": [],
        "install_owners": ["   812 postgresql16-server", "    40 postgresql16", "     6 pgaudit_16"],
        "cert_info": "subject=CN = db01.example.mil\nissuer=C = US, O = U.S. Government, OU = DoD, OU = PKI, CN = DOD SW CA-66",
        "openssl": "OpenSSL 1.1.1k  FIPS 25 Mar 2021",
        "system": {"fips_enabled": "1", "crypto_policy": "FIPS", "rsyslog": "*.* @@loghost.example.mil:514",
                   "disk": "/dev/sdb1 100G 10G 90G 10% /var/lib/pgsql", "repo_updates": {},
                   "accounts": {"postgres": {"passwd": "postgres:x:26:26::/var/lib/pgsql:/bin/bash", "id": "", "sudo": ""}}},
    }


def insecure():
    ev = hardened()
    sql = json.loads(ev["sql"])
    sql["settings"] = settings(ssl="off", shared_preload_libraries="", log_connections="off", log_disconnections="off",
                               log_line_prefix="%m [%p] ", log_file_mode="0640", client_min_messages="notice",
                               password_encryption="md5", log_destination="stderr", logging_collector="off",
                               statement_timeout="0", log_timezone="America/New_York", port="5433",
                               ssl_crl_file="")
    sql["file_settings"] = {}
    sql["roles"].append({"name": "dev", "super": True, "createrole": False, "createdb": True, "login": True,
                         "replication": False, "bypassrls": False, "connlimit": -1})
    sql["passwords"].append({"name": "dev", "kind": "md5"})
    sql["hba"] = [{"line": 1, "type": "local", "database": ["all"], "user": ["all"], "method": "trust", "options": None},
                  {"line": 2, "type": "host", "database": ["all"], "user": ["all"], "address": "0.0.0.0/0",
                   "method": "md5", "options": None}]
    ev["sql"] = json.dumps(sql)
    db = json.loads(ev["dbs"][0])
    db["extensions"].append({"name": "dblink"})
    db["untrusted_languages"] = ["plpython3u"]
    db["secdef"] = ["public.become_admin() (owner postgres)"]
    db["schemas"][0]["public_create"] = True
    ev["dbs"] = [json.dumps(db)]
    ev["packages"] += "\npostgresql13-server|13.9-1PGDG.rhel8|PGDG"
    ev["pgdata_stats"][0] = stat(PGDATA, "postgres", "postgres", "750", "d")
    ev["pgdata_violations"] = [stat(PGDATA + "/postgresql.conf", mode="644"), stat(PGDATA + "/backup.sql", "root", "root", "644")]
    ev["file_stats"][0] = stat(PGDATA + "/postgresql.conf", mode="644")
    ev["log_stats"] = [stat(LOG, mode="755", kind="d"), stat(LOG + "/postgresql-Mon.log", mode="644")]
    ev["install_violations"] = [stat(INSTALL + "/lib/evil.so", "postgres", "postgres", "775")]
    ev["install_owners"].append("      1 file /usr/pgsql-16/lib/evil.so is not owned by any package")
    ev["cert_info"] = ""
    ev["openssl"] = "OpenSSL 3.0.7 1 Nov 2022\nProviders:\n  default\n    name: OpenSSL Default Provider\n    status: active"
    ev["system"]["fips_enabled"] = "0"
    ev["system"]["rsyslog"] = ""
    ev["version"] = "16.2"
    return ev


def by_id(results):
    return dict((r["id"], r) for r in results)


class PostgresEvaluateTests(unittest.TestCase):
    def test_one_result_per_rule_bound_to_its_vuln_id(self):
        for ev in (hardened(), insecure(), {}):
            res = pg.postgres_stig_evaluate(ev, SETTINGS)
            self.assertEqual(len(res), 111)
            self.assertEqual(len(set(r["vuln_ids"][0] for r in res)), 111)
        idx = pg.INDEX
        m = pg.sc.stig_vuln_map(res, idx)
        self.assertTrue(all(len(v) == 1 and v[0]["bound"] for v in m.values()))

    def test_empty_evidence_never_passes(self):
        r = by_id(pg.postgres_stig_evaluate({}, {}))
        self.assertFalse([k for k, v in r.items() if v["status"] == pg.NF])

    def test_hardened(self):
        r = by_id(pg.postgres_stig_evaluate(hardened(), SETTINGS))
        opened = dict((k, v["finding_details"]) for k, v in r.items() if v["status"] == pg.OPEN)
        self.assertEqual(opened, {})
        for cid in ("CD16-00-000200", "CD16-00-000400", "CD16-00-003800", "CD16-00-003900", "CD16-00-004000",
                    "CD16-00-004100", "CD16-00-004400", "CD16-00-004700", "CD16-00-004900", "CD16-00-009400",
                    "CD16-00-010200", "CD16-00-011700", "CD16-00-012400", "CD16-00-002000", "CD16-00-002800",
                    "CD16-00-008400", "CD16-00-009100", "CD16-00-009300", "CD16-00-003200", "CD16-00-000100"):
            self.assertEqual(r[cid]["status"], pg.NF, "%s: %s" % (cid, r[cid]["finding_details"]))
        self.assertEqual(r["CD16-00-008300"]["status"], pg.NA)
        self.assertEqual(r["CD16-00-006400"]["status"], pg.NF)
        self.assertIn("AUDIT:=120", r["CD16-00-000800"]["evidence"])
        self.assertIn("test action", r["CD16-00-000800"]["comments"])

    def test_insecure(self):
        r = by_id(pg.postgres_stig_evaluate(insecure(), SETTINGS))
        for cid in ("CD16-00-000100", "CD16-00-000200", "CD16-00-000400", "CD16-00-000600", "CD16-00-000800",
                    "CD16-00-001000", "CD16-00-002000", "CD16-00-002400", "CD16-00-002500", "CD16-00-002600",
                    "CD16-00-002800", "CD16-00-003200", "CD16-00-003400", "CD16-00-003500", "CD16-00-003600",
                    "CD16-00-003800", "CD16-00-003900", "CD16-00-004000", "CD16-00-004400", "CD16-00-004600",
                    "CD16-00-004700", "CD16-00-004900", "CD16-00-005600", "CD16-00-006000", "CD16-00-006800",
                    "CD16-00-007000", "CD16-00-007500", "CD16-00-007700", "CD16-00-008400", "CD16-00-009100",
                    "CD16-00-009300", "CD16-00-009400", "CD16-00-011200", "CD16-00-012200", "CD16-00-012400"):
            self.assertEqual(r[cid]["status"], pg.OPEN, "%s: %s" % (cid, r[cid]["finding_details"]))
        self.assertIn("dev", r["CD16-00-000100"]["finding_details"])
        self.assertIn("trust", r["CD16-00-003600"]["finding_details"])
        self.assertIn("md5", r["CD16-00-003900"]["finding_details"])
        self.assertIn("dblink", r["CD16-00-003200"]["finding_details"])
        self.assertIn("plpython3u", r["CD16-00-006800"]["finding_details"])
        self.assertIn("backup.sql", r["CD16-00-005600"]["finding_details"])
        self.assertIn("evil.so", r["CD16-00-002800"]["finding_details"])
        self.assertIn("13", r["CD16-00-009100"]["finding_details"])
        self.assertEqual(r["CD16-00-006900"]["status"], pg.NR)   # SECURITY DEFINER needs review

    def test_settings_from_config_files_without_sql(self):
        ev = hardened()
        ev["sql"] = ""
        ev["dbs"] = []
        ev["files"] = {"postgresql.conf": "shared_preload_libraries = 'pgaudit'\npgaudit.log = 'all'\n"
                                          "log_connections = on\nlog_disconnections = on\nlogging_collector = on\n"
                                          "ssl = on   # tls\ntcp_keepalives_idle = 10\n",
                       "pg_hba.conf": "local all postgres peer\nhost all all 10.0.0.0 255.0.0.0 md5\n"}
        r = by_id(pg.postgres_stig_evaluate(ev, SETTINGS))
        self.assertEqual(r["CD16-00-009400"]["status"], pg.NF)
        self.assertEqual(r["CD16-00-004900"]["status"], pg.NF)
        self.assertEqual(r["CD16-00-003900"]["status"], pg.OPEN)
        self.assertEqual(r["CD16-00-004700"]["status"], pg.OPEN)   # interval/count/statement_timeout unset
        self.assertEqual(r["CD16-00-003200"]["status"], pg.NR)
        self.assertIn("settings source: file", r["CD16-00-009400"]["evidence"])

    def test_overrides_by_stig_id(self):
        s = dict(SETTINGS, overrides={"CD16-00-005400": {"status": "NotAFinding", "comment": "SSP 4.2"}})
        r = by_id(pg.postgres_stig_evaluate(hardened(), s))["CD16-00-005400"]
        self.assertEqual((r["status"], r["original_status"]), ("NotAFinding", "Not_Reviewed"))


class PostgresParsingTests(unittest.TestCase):
    def test_pgaudit_classes(self):
        self.assertEqual(pg._pgaudit_classes("all, -misc"), set(pg.AUDIT_CLASSES) - {"misc"})
        self.assertEqual(pg._pgaudit_classes("'ddl, role'"), {"ddl", "role"})
        self.assertEqual(pg._pgaudit_classes("none"), set())

    def test_parse_conf_and_hba(self):
        c = pg.parse_conf("log_line_prefix = '< %m %u >'  # x\nport 5433\n#ssl = on\nfoo = 'it''s'\n")
        self.assertEqual(c, {"log_line_prefix": "< %m %u >", "port": "5433", "foo": "it's"})
        h = pg.parse_hba("# c\nlocal all postgres peer\nhost all all 10.0.0.0 255.0.0.0 scram-sha-256\n"
                         "hostssl all all 0.0.0.0/0 cert clientcert=verify-full map=cac\n")
        self.assertEqual([(x["type"], x["method"], x["options"]) for x in h],
                         [("local", "peer", []), ("host", "scram-sha-256", []),
                          ("hostssl", "cert", ["clientcert=verify-full", "map=cac"])])
        self.assertEqual(h[1]["netmask"], "255.0.0.0")

    def test_pick_postmaster_and_paths(self):
        lines = ("100|/usr/pgsql-13/bin/postgres|/usr/pgsql-13/bin/postgres -D /var/lib/pgsql/13/data \n"
                 "200|/usr/pgsql-16/bin/postgres|/usr/pgsql-16/bin/postgres -D /var/lib/pgsql/16/data/ ")
        self.assertEqual(pg.pg_pick_postmaster(lines)["pid"], "200")
        self.assertEqual(pg.pg_pick_postmaster(lines, pgdata="/var/lib/pgsql/13/data")["pid"], "100")
        p = pg.pg_paths("", PGDATA, "log_directory = '/var/log/pgsql'\nssl_key_file = 'tls/server.key'\n")
        self.assertEqual((p["log_dir"], p["ssl_key_file"]), ("/var/log/pgsql", PGDATA + "/tls/server.key"))
        self.assertEqual(pg.pg_paths("", PGDATA)["config_file"], PGDATA + "/postgresql.conf")


if __name__ == "__main__":
    unittest.main()
