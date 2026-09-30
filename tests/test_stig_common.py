"""Unit tests for the shared stig_common filter plugin.

Run with:  python -m unittest discover -s tests -v
"""
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "roles", "stig_common", "filter_plugins"))
sys.path.insert(0, os.path.join(HERE, "..", "roles", "gitlab_stig_audit", "filter_plugins"))
sys.path.insert(0, os.path.join(HERE, "..", "roles", "nexus_stig_audit", "filter_plugins"))
import stig_common as sc  # noqa: E402
import gitlab_stig as gs  # noqa: E402
import nexus_stig as nx  # noqa: E402

FIX = os.path.join(HERE, "fixtures")
INDEX = os.path.join(HERE, "..", "roles", "stig_common", "files", "app_server_srg_index.json")


def load_index():
    with open(INDEX) as f:
        return json.load(f)


class RedactTests(unittest.TestCase):
    def test_secrets_are_masked(self):
        text = "\n".join([
            "gitlab_rails['smtp_password'] = \"hunter2\"",
            "gitlab_rails['ldap_servers'] = { 'main' => { 'password' => 'p@ss' } }",
            "  bind_password: plainvalue",
            "providers: [{\"name\":\"oidc\",\"args\":{\"client_options\":{\"secret\":\"abc123\"}}}]",
            "password=dbpass",
            "jdbcUrl=jdbc:postgresql://db:5432/nexus?user=nx&password=dbpass2",
            "url: https://svc:topsecret@host.example.mil/x",
            "<Set name=\"KeyStorePassword\">changeit</Set>",
            "<Property name=\"jetty.ssl.password\" default=\"kmpass\"/>",
        ])
        out = sc.stig_redact(text)
        for secret in ("hunter2", "p@ss", "plainvalue", "abc123", "dbpass", "dbpass2", "topsecret", "changeit", "kmpass"):
            self.assertNotIn(secret, out, secret)

    def test_settings_survive(self):
        text = ("external_url 'https://gitlab.example.mil'\nnexus.security.randompassword=false\n"
                "password_authentication_enabled_for_web: true\nsession_expire_delay: 15\n")
        self.assertEqual(sc.stig_redact(text), text)

    def test_strip_comments(self):
        self.assertEqual(sc.stig_redact("# a = 'x'\n\nb = 1\n", strip_comments=True), "b = 1")


class HostCheckTests(unittest.TestCase):
    def test_log_perms_honor_parent_directory(self):
        stats = ["/var/log/gitlab|root|root|0755|d", "/var/log/gitlab/rails|git|root|0700|d",
                 "/var/log/gitlab/rails/production.log|git|git|0644|f"]
        status, _, _ = sc.eval_log_perms(stats, ["root", "git"], traverse_dirs=["/var/log/gitlab"])
        self.assertEqual(status, sc.NF)
        status, details, _ = sc.eval_log_perms(stats, ["root", "git"])
        self.assertEqual(status, sc.OPEN)   # /var/log/gitlab 0755 is only allowed as a traverse dir
        stats[1] = "/var/log/gitlab/rails|git|root|0755|d"
        status, details, _ = sc.eval_log_perms(stats, ["root", "git"], traverse_dirs=["/var/log/gitlab"])
        self.assertIn("production.log", " ".join(details))

    def test_accounts_shell_exception(self):
        host = {"accounts": {"git": {"passwd": "git:x:998:998::/var/opt/gitlab:/bin/sh", "id": "", "sudo": ""}}}
        self.assertEqual(sc.eval_accounts(host, ["git"], {"git": "ssh"})[0], sc.NF)
        self.assertEqual(sc.eval_accounts(host, ["git"])[0], sc.OPEN)
        self.assertEqual(sc.eval_accounts({}, ["git"])[0], sc.NR)

    def test_rpm_verify_ignores_config_and_docs(self):
        ev = []
        issues = sc.rpm_verify_issues("S.5....T.  c /etc/x\nmissing   d /usr/share/doc/y\n..5......    /opt/bin/z", ev)
        self.assertEqual(issues, ["Packaged file altered: /opt/bin/z (..5......)"])


class ReportTests(unittest.TestCase):
    def test_every_check_uses_known_srg_ids_or_is_documented(self):
        bases = set(r["group_title"] for r in load_index()["rules"])
        retired = {"SRG-APP-000342"}   # not in V4R5; kept to match the Jenkins role
        for mod in (gs, nx):
            for cid, _, srgs, sev, _ in mod.CHECKS:
                self.assertIn(sev, ("high", "medium", "low"))
                for srg in srgs:
                    self.assertTrue(srg in bases or srg in retired, "%s %s" % (cid, srg))

    def test_ckl_for_new_products(self):
        x = sc.stig_xccdf_rules(os.path.join(FIX, "mini_xccdf.xml"))
        res = nx.nexus_stig_evaluate({}, {})
        ckl = sc.stig_ckl(res, x, {"tool": "nexus_stig_audit", "collected_at": "now"})
        self.assertTrue(ckl.startswith('<?xml version="1.0"'))
        self.assertIn("Assessed by nexus_stig_audit", ckl)
        self.assertEqual(len(re.findall("<VULN>", ckl)), len(x["rules"]))

    def test_vuln_map_against_bundled_index(self):
        idx = load_index()
        for mod, ev in ((gs, {}), (nx, {})):
            res = getattr(mod, [f for f in dir(mod) if f.endswith("_stig_evaluate")][0])(ev, {})
            m = sc.stig_vuln_map(res, idx)
            bound = [c for c, vs in m.items() if any(v["bound"] for v in vs)]
            self.assertGreater(len(bound), len(res) // 2, mod.__name__)


if __name__ == "__main__":
    unittest.main()
