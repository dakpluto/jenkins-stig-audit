"""Unit tests for the nexus_stig_audit evaluation logic.

Run with:  python -m unittest discover -s tests -v
No Ansible installation is required.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "roles", "nexus_stig_audit", "filter_plugins"))
import nexus_stig as nx  # noqa: E402

SETTINGS = {"max_session_timeout": 15, "tls_termination": "auto", "min_java_major": 17, "min_version": "",
            "approved_ports": [], "overrides": {}, "audit_url": ""}

TLS_OK = "CONNECTED(00000003)\n---\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
TLS_NO = "CONNECTED(00000003)\n---\nNew, (NONE), Cipher is (NONE)\n"
BANNER = "You are accessing a U.S. Government (USG) Information System (IS)"
DEFAULTS = ("application-port=8081\napplication-host=0.0.0.0\n"
            "nexus-args=${jetty.etc}/jetty.xml,${jetty.etc}/jetty-http.xml,${jetty.etc}/jetty-requestlog.xml\n"
            "nexus-context-path=/${NEXUS_CONTEXT}\n")
INSTALL, DATA = "/opt/sonatype/nexus", "/opt/sonatype/sonatype-work/nexus3"


def stat(path, owner, group, mode, kind="f", size=100):
    return "%s|%s|%s|%s|%s|1700000000.0|%s" % (path, owner, group, mode, kind, size)


def api(**kw):
    return dict((k, {"status": 200, "json": v}) for k, v in kw.items())


def insecure_evidence():
    files = {"nexus-default.properties": DEFAULTS,
             "nexus.properties": "nexus.scripts.allowCreation=true\nnexus.security.randompassword=false\n",
             "nexus.rc": "#run_as_user=\"\"\n"}
    return {
        "collected_at": "2026-09-30T12:00:00Z", "running": True,
        "process": {"pid": "777", "user": "root", "exe": INSTALL + "/jdk/temurin_11/bin/java",
                    "java_version": 'openjdk version "11.0.20" 2023-07-18'},
        "service_user": "nexus", "install_dir": INSTALL, "data_dir": DATA, "rpm": "",
        "version": "3.41.1-01",
        "cmdline": [INSTALL + "/jdk/bin/java", "-Dkaraf.home=.", "-Dkaraf.data=../sonatype-work/nexus3",
                    "-Dcom.redhat.fips=false", "org.sonatype.nexus.karaf.NexusMain"],
        "files": files,
        "stats": [stat(DATA, "nexus", "nexus", "755", "d"),
                  stat(DATA + "/etc/nexus.properties", "nexus", "nexus", "644"),
                  stat(DATA + "/keystores", "nexus", "nexus", "755", "d"),
                  stat(DATA + "/admin.password", "nexus", "nexus", "644"),
                  stat(INSTALL, "nexus", "nexus", "775", "d"),
                  stat(INSTALL + "/bin", "nexus", "nexus", "755", "d")],
        "log_stats": [stat(DATA + "/log", "nexus", "nexus", "755", "d"),
                      stat(DATA + "/log/nexus.log", "nexus", "nexus", "644")],
        "world_writable": [DATA + "/tmp/x"],
        "rpm_verify": "",
        "system": {
            "listeners": 'LISTEN 0 50 *:8081 *:* users:(("java",pid=777,fd=8))\n'
                         'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=900,fd=3))',
            "firewalld_state": "not running", "fips_enabled": "0", "crypto_policy": "DEFAULT",
            "chronyd": "inactive", "timedatectl": "NTPSynchronized=no", "rsyslog": "",
            "disk": "/dev/sda1 50G 45G 5G 90% /",
            "accounts": {"nexus": {"passwd": "nexus:x:995:995::/home/nexus:/bin/bash",
                                   "id": "uid=995(nexus) gid=995(nexus) groups=995(nexus),10(wheel)", "sudo": ""}},
            "repo_updates": {}},
        "http": {"ui": {"url": "http://127.0.0.1:8081/", "status": 200, "content": "<html>Nexus</html>",
                        "server": "Nexus/3.41.1-01 (OSS)"},
                 "status": {"url": "http://127.0.0.1:8081/service/rest/v1/status", "status": 200,
                            "server": "Nexus/3.41.1-01 (OSS)"},
                 "repositories": {"url": "http://127.0.0.1:8081/service/rest/v1/repositories", "status": 200,
                                  "json": [{"name": "maven-central"}, {"name": "internal-releases"}]}},
        "tls": {},
        "api": api(anonymous={"enabled": True, "userId": "anonymous"},
                   realms=["NexusAuthenticatingRealm", "NpmToken"],
                   ldap=[{"name": "ad", "protocol": "ldap", "host": "dc01", "port": 389}],
                   users=[{"userId": "admin", "source": "default", "status": "active", "roles": ["nx-admin"]}],
                   repositories=[{"name": "maven-central", "format": "maven2", "type": "proxy"}]),
    }


def hardened_evidence():
    files = {"nexus-default.properties": DEFAULTS,
             "nexus.properties": "application-port-ssl=8443\n"
                                 "nexus-args=${jetty.etc}/jetty.xml,${jetty.etc}/jetty-https.xml,"
                                 "${jetty.etc}/jetty-requestlog.xml\n",
             "nexus.rc": "run_as_user=\"nexus\"\n"}
    return {
        "collected_at": "2026-09-30T12:00:00Z", "running": True,
        "process": {"pid": "777", "user": "nexus", "exe": "/usr/lib/jvm/java-17-openjdk-17.0.12/bin/java",
                    "java_version": 'openjdk version "17.0.12" 2024-07-16 LTS'},
        "service_user": "nexus", "install_dir": INSTALL, "data_dir": DATA, "rpm": "", "version": "3.72.0-04",
        "cmdline": ["/usr/lib/jvm/java-17-openjdk/bin/java", "-Dkaraf.data=" + DATA],
        "files": files,
        "stats": [stat(DATA, "nexus", "nexus", "750", "d"),
                  stat(DATA + "/etc/nexus.properties", "nexus", "nexus", "640"),
                  stat(DATA + "/etc/fabric/nexus-store.properties", "nexus", "nexus", "600"),
                  stat(DATA + "/keystores", "nexus", "nexus", "700", "d"),
                  stat(DATA + "/etc/ssl/keystore.jks", "nexus", "nexus", "600"),
                  stat(INSTALL, "root", "root", "755", "d"),
                  stat(INSTALL + "/bin", "root", "root", "755", "d"),
                  stat(INSTALL + "/system", "root", "root", "755", "d")],
        "log_stats": [stat(DATA + "/log", "nexus", "nexus", "750", "d"),
                      stat(DATA + "/log/audit", "nexus", "nexus", "750", "d"),
                      stat(DATA + "/log/audit/audit.log", "nexus", "nexus", "640", size=5000),
                      stat(DATA + "/log/request.log", "nexus", "nexus", "640")],
        "world_writable": [], "rpm_verify": "",
        "system": {
            "listeners": 'LISTEN 0 50 0.0.0.0:8443 0.0.0.0:* users:(("java",pid=777,fd=8))',
            "firewalld_state": "running", "fips_enabled": "1", "crypto_policy": "FIPS",
            "chronyd": "active", "timedatectl": "NTPSynchronized=yes",
            "rsyslog": "module(load=\"imfile\")\ninput(type=\"imfile\" File=\"%s/log/audit/audit.log\" Tag=\"nexus\")\n"
                       "*.* @@loghost.example.mil:514" % DATA,
            "disk": "/dev/sdb1 200G 20G 180G 10% " + DATA,
            "accounts": {"nexus": {"passwd": "nexus:x:995:995::/home/nexus:/sbin/nologin",
                                   "id": "uid=995(nexus) gid=995(nexus) groups=995(nexus)", "sudo": ""}},
            "repo_updates": {}},
        "http": {"ui": {"url": "https://127.0.0.1:8443/", "status": 200,
                        "content": "<div id='banner'>%s</div>" % BANNER, "server": ""},
                 "status": {"url": "https://127.0.0.1:8443/service/rest/v1/status", "status": 200, "server": ""},
                 "repositories": {"url": "https://127.0.0.1:8443/service/rest/v1/repositories", "status": 200,
                                  "json": []}},
        "tls": {"tls1": TLS_NO, "tls1_1": TLS_NO, "tls1_2": TLS_OK, "tls1_3": TLS_OK},
        "api": api(anonymous={"enabled": False, "userId": "anonymous"},
                   realms=["LdapRealm", "rutauth-realm"],
                   ldap=[{"name": "ad", "protocol": "ldaps", "host": "dc01", "port": 636, "useTrustStore": True}],
                   users=[{"userId": "admin", "source": "default", "status": "disabled", "roles": ["nx-admin"]}],
                   repositories=[{"name": "releases", "format": "maven2", "type": "hosted"}]),
    }


def by_id(results):
    return dict((r["id"], r) for r in results)


class NexusEvaluateTests(unittest.TestCase):
    def test_every_check_reported_once(self):
        for ev in (insecure_evidence(), hardened_evidence(), {}):
            self.assertEqual([r["id"] for r in nx.nexus_stig_evaluate(ev, SETTINGS)], [c[0] for c in nx.CHECKS])

    def test_empty_evidence_never_passes(self):
        r = by_id(nx.nexus_stig_evaluate({}, SETTINGS))
        self.assertFalse([k for k, v in r.items() if v["status"] == nx.NF])

    def test_insecure_server(self):
        r = by_id(nx.nexus_stig_evaluate(insecure_evidence(), SETTINGS))
        opened = [k for k, v in r.items() if v["status"] == nx.OPEN]
        for cid in ("NXRM-001", "NXRM-002", "NXRM-003", "NXRM-004", "NXRM-005", "NXRM-007", "NXRM-008",
                    "NXRM-009", "NXRM-011", "NXRM-012", "NXRM-013", "NXRM-014", "NXRM-016", "NXRM-017",
                    "NXRM-018", "NXRM-019", "NXRM-021", "NXRM-022", "NXRM-024"):
            self.assertIn(cid, opened, "%s: %s" % (cid, r[cid]["finding_details"]))
        self.assertIn("internal-releases", r["NXRM-002"]["finding_details"])
        self.assertIn("default password", r["NXRM-003"]["finding_details"])
        self.assertIn("bundled JDK", r["NXRM-011"]["finding_details"])
        self.assertIn("com.redhat.fips=false", r["NXRM-011"]["finding_details"])
        self.assertIn("running as root", r["NXRM-012"]["finding_details"])
        self.assertIn("admin.password", r["NXRM-013"]["finding_details"])
        self.assertIn("Java 11", r["NXRM-017"]["finding_details"])
        self.assertIn("Nexus/3.41.1-01", r["NXRM-018"]["finding_details"])
        self.assertEqual(r["NXRM-020"]["status"], nx.NF)   # jetty-requestlog.xml is in the default nexus-args
        self.assertEqual(r["NXRM-010"]["status"], nx.NR)

    def test_hardened_server(self):
        r = by_id(nx.nexus_stig_evaluate(hardened_evidence(), SETTINGS))
        expect = {"NXRM-004": nx.NR, "NXRM-006": nx.NR, "NXRM-007": nx.OPEN, "NXRM-015": nx.NR,
                  "NXRM-016": nx.NR, "NXRM-017": nx.NR, "NXRM-023": nx.NR}
        for cid, res in r.items():
            self.assertEqual(res["status"], expect.get(cid, nx.NF), "%s: %s" % (cid, res["finding_details"]))

    def test_without_api_credentials(self):
        ev = hardened_evidence()
        ev["api"] = {}
        r = by_id(nx.nexus_stig_evaluate(ev, SETTINGS))
        for cid in ("NXRM-001", "NXRM-002", "NXRM-003", "NXRM-004", "NXRM-005"):
            self.assertEqual(r[cid]["status"], nx.NR, cid)
        ev = insecure_evidence()
        ev["api"] = {}
        r = by_id(nx.nexus_stig_evaluate(ev, SETTINGS))
        self.assertEqual(r["NXRM-002"]["status"], nx.OPEN)   # repositories listed anonymously
        self.assertEqual(r["NXRM-003"]["status"], nx.OPEN)   # randompassword=false

    def test_http_loopback_behind_proxy(self):
        ev = hardened_evidence()
        ev["files"]["nexus.properties"] = "application-host=127.0.0.1\n"
        ev["system"]["listeners"] = ('LISTEN 0 50 127.0.0.1:8081 0.0.0.0:* users:(("java",pid=777,fd=8))\n'
                                     'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=12,fd=6))')
        self.assertEqual(by_id(nx.nexus_stig_evaluate(ev, SETTINGS))["NXRM-009"]["status"], nx.NF)
        ev["system"]["listeners"] = 'LISTEN 0 50 0.0.0.0:8081 0.0.0.0:* users:(("java",pid=777,fd=8))'
        ev["files"]["nexus.properties"] = ""
        self.assertEqual(by_id(nx.nexus_stig_evaluate(ev, SETTINGS))["NXRM-009"]["status"], nx.OPEN)


class NexusParsingTests(unittest.TestCase):
    def test_runtime_defaults_and_overrides(self):
        rt = nx.nexus_runtime({"nexus-default.properties": DEFAULTS})
        self.assertTrue(rt["http_enabled"])
        self.assertFalse(rt["https_enabled"])
        self.assertEqual(rt["probe"]["base_url"], "http://127.0.0.1:8081")
        rt = nx.nexus_runtime(hardened_evidence()["files"])
        self.assertEqual(rt["probe"]["base_url"], "https://127.0.0.1:8443")
        self.assertEqual((rt["probe"]["tls_host"], rt["probe"]["tls_port"]), ("127.0.0.1", 8443))
        self.assertEqual(rt["probe"]["plain_url"], "")
        rt = nx.nexus_runtime({"nexus-default.properties": DEFAULTS, "nexus.properties": "nexus-context-path=/nexus"},
                              audit_url="https://repo.example.mil/nexus/")
        self.assertEqual(rt["probe"]["base_url"], "https://repo.example.mil/nexus")
        self.assertEqual(rt["probe"]["tls_port"], 443)
        self.assertEqual(rt["context"], "/nexus")

    def test_jvm_properties_from_vmoptions(self):
        rt = nx.nexus_runtime({"nexus.vmoptions": "-Xms2703m\n-Dkaraf.data=../sonatype-work/nexus3\n"
                                                  "-Dnexus.security.randompassword=false\n"})
        self.assertEqual(rt["jvm"]["nexus.security.randompassword"], "false")

    def test_version(self):
        self.assertEqual(nx.nexus_version("/opt/nexus-3.61.0-02\n"), "3.61.0-02")
        self.assertEqual(nx.nexus_version("/opt/sonatype/nexus\nnexus-base/3.70.1-02"), "3.70.1-02")
        self.assertEqual(nx.nexus_version("/opt/nexus\nsonatype-nexus-repository-3.78.0-14.jar"), "3.78.0-14")
        self.assertEqual(nx.nexus_version("/opt/nexus", "Nexus/3.41.1-01 (OSS)"), "3.41.1-01")
        self.assertEqual(nx.nexus_version("/opt/nexus"), "")

    def test_api_sanitize(self):
        out = nx.nexus_api_sanitize([{"name": "ad", "authPassword": "x", "connection": {"secretKey": "y", "host": "h"}}])
        self.assertEqual(out, [{"name": "ad", "connection": {"host": "h"}}])


if __name__ == "__main__":
    unittest.main()
