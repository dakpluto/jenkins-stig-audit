"""Unit tests for the controller-side evaluation logic.

Run with:  python -m unittest discover -s tests -v
No Ansible installation is required.
"""
import json
import os
import sys
import unittest
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "roles", "jenkins_stig_audit", "filter_plugins"))
import jenkins_stig as js  # noqa: E402

FIX = os.path.join(HERE, "fixtures")


def fixture(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return fh.read()


SETTINGS = {
    "max_session_timeout": 15, "tls_termination": "auto", "approved_ports": [],
    "approved_plugins": [], "prohibited_plugins": [], "min_java_major": 17,
    "update_center_max_age_days": 7,
    "dangerous_properties": [
        {"name": "hudson.security.csrf.GlobalCrumbIssuerConfiguration.DISABLE_CSRF_PROTECTION", "value": "true"},
        {"name": "permissive-script-security.enabled"}],
    "error_disclosure_properties": ["jenkins.model.Jenkins.SHOW_STACK_TRACE"],
    "overrides": {}, "audit_url": "",
}

TLS_OK = "CONNECTED(00000003)\n---\nNew, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384\n"
TLS_NO = "CONNECTED(00000003)\n---\nNew, (NONE), Cipher is (NONE)\n"


def insecure_evidence():
    cmd = ["/usr/lib/jvm/java-11-openjdk/bin/java", "-Djava.awt.headless=true",
           "-Dhudson.security.csrf.GlobalCrumbIssuerConfiguration.DISABLE_CSRF_PROTECTION=true",
           "-Dhudson.model.DirectoryBrowserSupport.CSP=", "-Djenkins.model.Jenkins.SHOW_STACK_TRACE=true",
           "-jar", "/usr/share/java/jenkins.war", "--webroot=/var/cache/jenkins/war", "--httpPort=8080"]
    return {
        "collected_at": "2026-09-28T12:00:00Z", "home": "/var/lib/jenkins", "running": True,
        "rpm_version": "2.401.1-1.1",
        "runtime": js.jenkins_runtime(cmd),
        "process": {"pid": "4242", "user": "root", "java_version": 'openjdk version "11.0.22" 2024-01-16 LTS'},
        "service_user": "root", "war": "/usr/share/java/jenkins.war",
        "files": {"config.xml": fixture("config_insecure.xml"),
                  "secrets/slave-to-master-security-kill-switch": "true\n",
                  "jenkins.model.JenkinsLocationConfiguration.xml":
                      "<?xml version='1.1' encoding='UTF-8'?><jenkins.model.JenkinsLocationConfiguration>"
                      "<jenkinsUrl>http://jenkins.example.mil:8080/</jenkinsUrl></jenkins.model.JenkinsLocationConfiguration>",
                  "jenkins.security.apitoken.ApiTokenPropertyConfiguration.xml":
                      "<jenkins.security.apitoken.ApiTokenPropertyConfiguration><tokenGenerationOnCreationEnabled>true"
                      "</tokenGenerationOnCreationEnabled><creationOfLegacyTokenEnabled>false</creationOfLegacyTokenEnabled>"
                      "</jenkins.security.apitoken.ApiTokenPropertyConfiguration>"},
        "stats": ["/var/lib/jenkins|jenkins|jenkins|755|d|1700000000.0|4096",
                  "/var/lib/jenkins/secrets|jenkins|jenkins|755|d|1700000000.0|4096",
                  "/var/lib/jenkins/secrets/master.key|jenkins|jenkins|644|f|1700000000.0|256",
                  "/var/lib/jenkins/secrets/initialAdminPassword|jenkins|jenkins|640|f|1700000000.0|33",
                  "/var/lib/jenkins/config.xml|jenkins|jenkins|644|f|1700000000.0|2000",
                  "/usr/share/java/jenkins.war|jenkins|jenkins|664|f|1700000000.0|90000000"],
        "log_stats": ["/var/log/jenkins|jenkins|jenkins|755|d|1700000000.0|4096",
                      "/var/log/jenkins/jenkins.log|jenkins|jenkins|644|f|1700000000.0|4096"],
        "world_writable": ["/var/lib/jenkins/tmp.sh"],
        "plugins": ["git|5.0.0|false", "anything-goes-formatter|1.0|false", "old-thing|0.1|true"],
        "passwd": "jenkins:x:990:985:Jenkins Automation Server:/var/lib/jenkins:/bin/bash",
        "id": "uid=990(jenkins) gid=985(jenkins) groups=985(jenkins),10(wheel),992(docker)",
        "sudo": "User jenkins may run the following commands on host:\n    (ALL) NOPASSWD: ALL",
        "rpm_verify": "S.5....T.    /usr/share/java/jenkins.war\nS.5....T.  c /etc/sysconfig/jenkins",
        "listeners": 'LISTEN 0 50 *:8080 *:* users:(("java",pid=4242,fd=8))\n'
                     'LISTEN 0 50 *:41234 *:* users:(("java",pid=4242,fd=9))\n'
                     'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=900,fd=3))',
        "firewalld_state": "not running", "fips_enabled": "0", "crypto_policy": "DEFAULT",
        "chronyd": "inactive", "timedatectl": "Timezone=UTC\nNTPSynchronized=no",
        "rsyslog": "module(load=\"imuxsock\")\n*.info;mail.none /var/log/messages",
        "disk": "Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 50G 40G 10G 80% /",
        "http": {"login": {"url": "http://127.0.0.1:8080/login", "status": 200,
                           "content": "<html><body>Sign in to Jenkins</body></html>",
                           "x_jenkins": "2.401.1", "x_hudson": "1.395"},
                 "anon_api": {"url": "http://127.0.0.1:8080/api/json", "status": 200}},
        "tls": {},
        "update_center": fixture("update_center.json"), "update_center_age_days": 30,
    }


def hardened_evidence():
    cmd = ["/usr/lib/jvm/java-17-openjdk/bin/java", "-Djava.awt.headless=true",
           "-jar", "/usr/share/java/jenkins.war", "--httpPort=-1", "--httpsPort=8443",
           "--httpsKeyStore=/etc/jenkins/keystore.p12", "--httpsKeyStorePassword=********",
           "--sessionTimeout=15", "--accessLoggerClassName=winstone.accesslog.SimpleAccessLogger",
           "--simpleAccessLogger.file=/var/log/jenkins/access_log"]
    return {
        "collected_at": "2026-09-28T12:00:00Z", "home": "/var/lib/jenkins", "running": True,
        "rpm_version": "2.462.3-1.1",
        "runtime": js.jenkins_runtime(cmd),
        "process": {"pid": "777", "user": "jenkins", "java_version": 'openjdk version "17.0.12" 2024-07-16 LTS'},
        "service_user": "jenkins", "war": "/usr/share/java/jenkins.war",
        "files": {"config.xml": fixture("config_hardened.xml"),
                  "audit-trail.xml": fixture("audit_trail.xml"),
                  "org.jenkinsci.main.modules.sshd.SSHD.xml": "<org.jenkinsci.main.modules.sshd.SSHD><port>-1</port></org.jenkinsci.main.modules.sshd.SSHD>",
                  "jenkins.model.JenkinsLocationConfiguration.xml":
                      "<jenkins.model.JenkinsLocationConfiguration><jenkinsUrl>https://jenkins.example.mil/</jenkinsUrl></jenkins.model.JenkinsLocationConfiguration>"},
        "stats": ["/var/lib/jenkins|jenkins|jenkins|750|d|1700000000.0|4096",
                  "/var/lib/jenkins/secrets|jenkins|jenkins|700|d|1700000000.0|4096",
                  "/var/lib/jenkins/secrets/master.key|jenkins|jenkins|600|f|1700000000.0|256",
                  "/var/lib/jenkins/config.xml|jenkins|jenkins|640|f|1700000000.0|2000",
                  "/usr/share/java/jenkins.war|root|root|644|f|1700000000.0|90000000"],
        "log_stats": ["/var/log/jenkins|jenkins|jenkins|750|d|1700000000.0|4096",
                      "/var/log/jenkins/audit-0.log|jenkins|jenkins|640|f|1700000000.0|4096",
                      "/var/log/jenkins/access_log|jenkins|jenkins|640|f|1700000000.0|4096"],
        "world_writable": [],
        "plugins": ["audit-trail|361.v82cde86c784e|false", "saml|4.464.vea_cb_75d7f5e0|false",
                    "matrix-auth|3.2.2|false", "git|5.2.2|false"],
        "passwd": "jenkins:x:990:985:Jenkins Automation Server:/var/lib/jenkins:/sbin/nologin",
        "id": "uid=990(jenkins) gid=985(jenkins) groups=985(jenkins)",
        "sudo": "User jenkins is not allowed to run sudo on host.",
        "rpm_verify": "S.5....T.  c /etc/sysconfig/jenkins",
        "listeners": 'LISTEN 0 50 *:8443 *:* users:(("java",pid=777,fd=8))\n'
                     'LISTEN 0 50 *:50000 *:* users:(("java",pid=777,fd=9))',
        "firewalld_state": "running", "fips_enabled": "1", "crypto_policy": "FIPS",
        "chronyd": "active", "timedatectl": "Timezone=UTC\nNTPSynchronized=yes",
        "rsyslog": 'input(type="imfile" File="/var/log/jenkins/audit-*.log" Tag="jenkins-audit")\n*.* @@logs.example.mil:6514',
        "disk": "",
        "http": {"login": {"url": "https://127.0.0.1:8443/login", "status": 200,
                           "content": "<div>You are accessing a U.S. Government (USG) Information System</div>"},
                 "anon_api": {"url": "https://127.0.0.1:8443/api/json", "status": 403}},
        "tls": {"tls1": TLS_NO, "tls1_1": TLS_NO, "tls1_2": TLS_OK, "tls1_3": TLS_OK.replace("TLSv1.2", "TLSv1.3")},
        "update_center": fixture("update_center.json"), "update_center_age_days": 1.0,
    }


def by_id(results):
    return dict((r["id"], r) for r in results)


class RuntimeTests(unittest.TestCase):
    def test_process_args(self):
        rt = js.jenkins_runtime(["java", "-DJENKINS_HOME=/data/jenkins", "-jar", "/opt/jenkins.war",
                                 "--httpPort=-1", "--httpsPort=8443", "--httpsListenAddress=10.1.1.5",
                                 "--prefix=/ci/", "--sessionTimeout=10"])
        self.assertEqual(rt["properties"]["JENKINS_HOME"], "/data/jenkins")
        self.assertEqual(rt["war"], "/opt/jenkins.war")
        self.assertEqual(rt["session_timeout"], 10)
        self.assertEqual(rt["probe"]["base_url"], "https://10.1.1.5:8443/ci")
        self.assertEqual(rt["probe"]["plain_url"], "")
        self.assertEqual(rt["probe"]["tls_port"], 8443)

    def test_sysconfig_when_not_running(self):
        env = 'JENKINS_HOME="/var/lib/jenkins"\nJENKINS_PORT="8080"\nJENKINS_HTTPS_PORT="8443"\n' \
              'JENKINS_ARGS="--sessionTimeout=30"\nJENKINS_ENABLE_ACCESS_LOG="yes"'
        rt = js.jenkins_runtime([], env)
        self.assertEqual(rt["source"], "config")
        self.assertEqual(rt["https_port"], 8443)
        self.assertEqual(rt["session_timeout"], 30)
        self.assertTrue(rt["access_logger"])
        self.assertEqual(rt["probe"]["plain_url"], "http://127.0.0.1:8080/login")

    def test_systemd_environment(self):
        env = 'Environment="JENKINS_PORT=-1" "JENKINS_HTTPS_PORT=8443"\nEnvironment="JENKINS_OPTS=--sessionTimeout=15"'
        rt = js.jenkins_runtime([], env)
        self.assertEqual(rt["http_port"], -1)
        self.assertEqual(rt["session_timeout"], 15)

    def test_audit_url_overrides_probe(self):
        rt = js.jenkins_runtime(["--httpPort=8080", "--httpListenAddress=127.0.0.1"], "", "https://ci.example.mil/")
        self.assertEqual(rt["probe"]["base_url"], "https://ci.example.mil")
        self.assertEqual((rt["probe"]["tls_host"], rt["probe"]["tls_port"]), ("ci.example.mil", 443))


class EvaluateTests(unittest.TestCase):
    def test_every_check_reported_once(self):
        for ev in (insecure_evidence(), hardened_evidence(), {}):
            res = js.jenkins_stig_evaluate(ev, SETTINGS)
            self.assertEqual([r["id"] for r in res], [c[0] for c in js.CHECKS])
            for r in res:
                self.assertIn(r["status"], js.STATUS_ORDER)

    def test_insecure_host(self):
        r = by_id(js.jenkins_stig_evaluate(insecure_evidence(), SETTINGS))
        expect_open = ["JNKS-002", "JNKS-003", "JNKS-004", "JNKS-005", "JNKS-007", "JNKS-008",
                       "JNKS-010", "JNKS-011", "JNKS-013", "JNKS-014", "JNKS-015", "JNKS-016",
                       "JNKS-017", "JNKS-018", "JNKS-019", "JNKS-020", "JNKS-021", "JNKS-022",
                       "JNKS-023", "JNKS-024", "JNKS-025", "JNKS-026", "JNKS-027", "JNKS-029"]
        for cid in expect_open:
            self.assertEqual(r[cid]["status"], js.OPEN, "%s: %s" % (cid, r[cid]["finding_details"]))
        self.assertIn("anonymous", r["JNKS-002"]["finding_details"])
        self.assertIn("authenticated", r["JNKS-002"]["finding_details"])
        self.assertIn("random", r["JNKS-018"]["finding_details"])
        self.assertIn("SECURITY-9999", r["JNKS-020"]["finding_details"])
        self.assertIn("core 2.401.1", r["JNKS-020"]["finding_details"])
        self.assertIn("Java 11", r["JNKS-020"]["finding_details"])
        self.assertIn("Deprecated plugins installed: anything-goes-formatter", r["JNKS-019"]["finding_details"])
        self.assertIn("old-thing", r["JNKS-019"]["finding_details"])
        self.assertIn("initialAdminPassword", r["JNKS-015"]["finding_details"])
        self.assertIn("jenkins.war", r["JNKS-016"]["finding_details"])
        self.assertIn("wheel", r["JNKS-014"]["finding_details"])
        self.assertEqual(r["JNKS-012"]["status"], js.NR)

    def test_hardened_host(self):
        r = by_id(js.jenkins_stig_evaluate(hardened_evidence(), SETTINGS))
        expect_nf = ["JNKS-001", "JNKS-002", "JNKS-007", "JNKS-008", "JNKS-010", "JNKS-011",
                     "JNKS-012", "JNKS-013", "JNKS-014", "JNKS-015", "JNKS-016", "JNKS-017",
                     "JNKS-020", "JNKS-021", "JNKS-022", "JNKS-023", "JNKS-024", "JNKS-025",
                     "JNKS-026", "JNKS-027", "JNKS-029"]
        for cid in expect_nf:
            self.assertEqual(r[cid]["status"], js.NF, "%s: %s" % (cid, r[cid]["finding_details"]))
        self.assertEqual(r["JNKS-003"]["status"], js.NA)
        self.assertEqual(r["JNKS-004"]["status"], js.NR)   # federated: verify IdP
        self.assertEqual(r["JNKS-005"]["status"], js.NA)
        self.assertEqual(r["JNKS-018"]["status"], js.NR)   # no approved port list supplied
        self.assertEqual(r["JNKS-019"]["status"], js.NR)
        self.assertEqual(r["JNKS-009"]["status"], js.OPEN)

    def test_update_center_already_parsed(self):
        # Ansible converts a JSON-looking string fact into a dict before the filter sees it.
        ev = hardened_evidence()
        expected = js.jenkins_stig_evaluate(ev, SETTINGS)
        ev["update_center"] = json.loads(ev["update_center"])
        self.assertEqual(js.jenkins_stig_evaluate(ev, SETTINGS), expected)

    def test_approved_lists_and_overrides(self):
        s = dict(SETTINGS, approved_ports=[8443], approved_plugins=["audit-trail", "saml", "matrix-auth", "git"],
                 overrides={"JNKS-009": {"status": "Not_Applicable", "comment": "IdP limits sessions"},
                            "JNKS-004": {"status": "bogus"}})
        r = by_id(js.jenkins_stig_evaluate(hardened_evidence(), s))
        self.assertEqual(r["JNKS-018"]["status"], js.OPEN)          # 50000 not approved
        self.assertIn("50000", r["JNKS-018"]["finding_details"])
        self.assertEqual(r["JNKS-019"]["status"], js.NF)
        self.assertEqual(r["JNKS-009"]["status"], js.NA)
        self.assertEqual(r["JNKS-009"]["original_status"], js.OPEN)
        self.assertIn("IdP limits sessions", r["JNKS-009"]["comments"])
        self.assertEqual(r["JNKS-004"]["status"], js.NR)            # invalid override ignored

    def test_weak_tls_and_proxy(self):
        ev = hardened_evidence()
        ev["tls"]["tls1_1"] = TLS_OK.replace("TLSv1.2", "TLSv1.1")
        r = by_id(js.jenkins_stig_evaluate(ev, SETTINGS))
        self.assertEqual(r["JNKS-012"]["status"], js.OPEN)
        # loopback HTTP behind nginx on 443 is acceptable
        ev = hardened_evidence()
        ev["runtime"] = js.jenkins_runtime(["-jar", "/usr/share/java/jenkins.war", "--httpPort=8080",
                                            "--httpListenAddress=127.0.0.1", "--sessionTimeout=10"])
        ev["listeners"] = ('LISTEN 0 50 [::ffff:127.0.0.1]:8080 *:* users:(("java",pid=777,fd=8))\n'
                           'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=55,fd=6))')
        r = by_id(js.jenkins_stig_evaluate(ev, SETTINGS))
        self.assertEqual(r["JNKS-011"]["status"], js.NF, r["JNKS-011"]["finding_details"])

    def test_role_strategy_and_ldap(self):
        ev = hardened_evidence()
        ev["files"]["config.xml"] = fixture("config_role_ldap.xml")
        r = by_id(js.jenkins_stig_evaluate(ev, SETTINGS))
        self.assertEqual(r["JNKS-002"]["status"], js.OPEN)
        self.assertIn("anonymous", r["JNKS-002"]["finding_details"])
        self.assertEqual(r["JNKS-006"]["status"], js.OPEN)
        self.assertIn("ldap://", r["JNKS-006"]["finding_details"])
        self.assertEqual(r["JNKS-004"]["status"], js.OPEN)
        self.assertEqual(r["JNKS-005"]["status"], js.NA)


class ChecklistTests(unittest.TestCase):
    def test_xccdf_bind_and_ckl(self):
        x = js.stig_xccdf_rules(os.path.join(FIX, "mini_xccdf.xml"))
        self.assertEqual(len(x["rules"]), 4)
        res = js.jenkins_stig_evaluate(insecure_evidence(), SETTINGS)
        b = js.stig_bind(res, x)
        self.assertIn("V-900001", b["bound"])                       # SRG-APP-000068 unique
        self.assertIn("JNKS-021", b["ambiguous"])                   # SRG-APP-000516 x2
        ckl = js.stig_ckl(res, x, {"host_name": "jenkins01", "collected_at": "now"})
        root = ET.fromstring(ckl.split("\n", 2)[2])
        vulns = root.findall(".//VULN")
        self.assertEqual(len(vulns), 4)
        st = dict((v.find("STIG_DATA/ATTRIBUTE_DATA").text, v.find("STATUS").text) for v in vulns)
        self.assertEqual(st["V-900001"], "Open")                    # banner missing
        self.assertEqual(st["V-900003"], "Not_Reviewed")            # ambiguous 000516
        self.assertEqual(st["V-900004"], "Not_Reviewed")            # nothing automated
        # explicit binding resolves ambiguity
        ckl = js.stig_ckl(res, x, {}, {"JNKS-021": ["SRG-APP-000516-AS-000237"]})
        root = ET.fromstring(ckl.split("\n", 2)[2])
        st = dict((v.find("STIG_DATA/ATTRIBUTE_DATA").text, v.find("STATUS").text) for v in root.findall(".//VULN"))
        self.assertEqual(st["V-900002"], "Open")
        self.assertEqual(st["V-900003"], "Not_Reviewed")

    def test_vuln_map_matches_binding(self):
        x = js.stig_xccdf_rules(os.path.join(FIX, "mini_xccdf.xml"))
        res = js.jenkins_stig_evaluate(insecure_evidence(), SETTINGS)
        m = js.stig_vuln_map(res, x)
        self.assertEqual(set(m), set(r["id"] for r in res))
        banner = [c for c, vs in m.items() if any(v["vuln_num"] == "V-900001" for v in vs)]
        self.assertTrue(banner)
        self.assertTrue(all(v["bound"] for c in banner for v in m[c] if v["vuln_num"] == "V-900001"))
        self.assertEqual([(v["vuln_num"], v["bound"]) for v in m["JNKS-021"]],
                         [("V-900002", False), ("V-900003", False)])
        m = js.stig_vuln_map(res, x, {"JNKS-021": ["V-900002"]})
        self.assertEqual([(v["vuln_num"], v["bound"], v["rule_ver"]) for v in m["JNKS-021"]],
                         [("V-900002", True, "SRG-APP-000516-AS-000237")])

    def test_bundled_index_maps_vuln_ids(self):
        with open(os.path.join(os.path.dirname(FIX), "..", "roles", "stig_common", "files",
                               "app_server_srg_index.json")) as f:
            x = json.load(f)
        self.assertTrue(all(r["rule_ver"].startswith("SRG-APP-") for r in x["rules"]))
        res = js.jenkins_stig_evaluate(insecure_evidence(), SETTINGS)
        m = js.stig_vuln_map(res, x)
        self.assertEqual([v["vuln_num"] for v in m["JNKS-003"] if v["bound"]], ["V-204712"])

    def test_csv_and_summary(self):
        res = js.jenkins_stig_evaluate(hardened_evidence(), SETTINGS)
        self.assertTrue(js.stig_csv(res).startswith("Check,Severity,Status"))
        s = js.stig_summary(res)
        self.assertEqual(s["total"], len(js.CHECKS))
        self.assertEqual(sum(s["by_status"].values()), len(js.CHECKS))


if __name__ == "__main__":
    unittest.main()
