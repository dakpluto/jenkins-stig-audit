"""Unit tests for the gitlab_stig_audit evaluation logic.

Run with:  python -m unittest discover -s tests -v
No Ansible installation is required (the YAML test needs PyYAML, which Ansible ships).
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "roles", "gitlab_stig_audit", "filter_plugins"))
import gitlab_stig as gs  # noqa: E402

try:
    import yaml  # noqa: F401
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

SETTINGS = {
    "max_session_timeout": 15, "max_inactive_days": 35, "tls_termination": "auto", "min_version": "",
    "approved_ports": [], "approved_services": [], "overrides": {}, "audit_url": "",
    "expected_settings": {"usage_ping_enabled": False, "gravatar_enabled": False},
    "service_accounts": ["git", "gitlab-www"],
    "shell_exceptions": {"git": "gitlab-shell needs a shell"},
}

TLS_OK = "CONNECTED(00000003)\n---\nNew, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384\n"
TLS_NO = "CONNECTED(00000003)\n---\nNew, (NONE), Cipher is (NONE)\n"
BANNER = "You are accessing a U.S. Government (USG) Information System (IS)"

GITLAB_YML = """
production: &base
  gitlab:
    host: gitlab.example.mil
    port: 443
    https: true
  ldap:
    enabled: true
    servers:
      main:
        host: dc01.example.mil
        port: 636
        encryption: simple_tls
        verify_certificates: true
        password: '********'
  omniauth:
    enabled: false
    providers: []
  smartcard:
    enabled: true
    ca_file: /etc/gitlab/ssl/dod-cas.pem
"""


def stat(path, owner, group, mode, kind="f"):
    return "%s|%s|%s|%s|%s|1700000000.0|100" % (path, owner, group, mode, kind)


def rails(settings, **extra):
    out = {"settings": settings, "admins": ["root", "alice"], "dormant": 0, "terms": ""}
    out.update(extra)
    return "WARNING: something\n" + json.dumps(out)


def insecure_evidence():
    return {
        "collected_at": "2026-09-30T12:00:00Z", "running": True,
        "package": {"name": "gitlab-ce", "version": "16.1.0-ce.0.el8"},
        "packages": "gitlab-ce|16.1.0-ce.0.el8\ngitlab-runner|16.1.0-1",
        "version": "16.1.0",
        "services": "run: gitaly: (pid 1) 10s\nrun: nginx: (pid 2) 10s\nrun: puma: (pid 3) 10s\n"
                    "run: mattermost: (pid 4) 10s\ndown: registry: 0s",
        "external_url": "http://gitlab.example.mil",
        "gitlab_rb": "external_url 'http://gitlab.example.mil'\ngitlab_workhorse['listen_network'] = \"tcp\"",
        "gitlab_yml": {"production": {"gitlab": {"host": "gitlab.example.mil", "port": 80, "https": False},
                                      "ldap": {"enabled": True, "servers": {"main": {
                                          "host": "dc01", "port": 389, "encryption": "plain",
                                          "verify_certificates": False}}},
                                      "omniauth": {"enabled": False, "providers": []},
                                      "smartcard": {"enabled": False}}},
        "rails": rails({
            "signup_enabled": True, "require_admin_approval_after_user_signup": False,
            "require_two_factor_authentication": False, "admin_mode": False, "session_expire_delay": 10080,
            "remember_me_enabled": True, "password_authentication_enabled_for_web": True,
            "password_authentication_enabled_for_git": True, "default_project_visibility": 20,
            "restricted_visibility_levels": [], "allow_local_requests_from_web_hooks_and_services": True,
            "allow_local_requests_from_system_hooks": True, "deactivate_dormant_users": False,
            "deactivate_dormant_users_period": 90, "enforce_terms": False,
            "usage_ping_enabled": True, "gravatar_enabled": True}, dormant=7),
        "processes": "root /opt/gitlab/embedded/bin/gitaly /var/opt/gitlab/gitaly/config.toml\n"
                     "git puma 6.3.0 (unix:///var/opt/gitlab/gitlab-rails/sockets/gitlab.socket) [gitlab-puma-worker]",
        "stats": [stat("/etc/gitlab", "root", "root", "777", "d"),
                  stat("/etc/gitlab/gitlab.rb", "root", "root", "644"),
                  stat("/etc/gitlab/gitlab-secrets.json", "git", "root", "644"),
                  stat("/etc/gitlab/initial_root_password", "root", "root", "600"),
                  stat("/etc/gitlab/ssl/gitlab.example.mil.key", "root", "root", "644"),
                  stat("/opt/gitlab", "git", "git", "775", "d")],
        "log_stats": [stat("/var/log/gitlab", "root", "root", "777", "d"),
                      stat("/var/log/gitlab/gitlab-rails", "git", "root", "755", "d"),
                      stat("/var/log/gitlab/gitlab-rails/production_json.log", "git", "git", "666")],
        "world_writable": ["/var/opt/gitlab/backups/dump.tar"],
        "rpm_verify_ran": True,
        "rpm_verify": "S.5....T.    /opt/gitlab/embedded/bin/ruby\n.M.......  c /opt/gitlab/etc/foo\n"
                      "missing   d /opt/gitlab/share/doc/readme",
        "system": {
            "listeners": 'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=2,fd=7))\n'
                         'LISTEN 0 1024 0.0.0.0:8181 0.0.0.0:* users:(("gitlab-workhorse",pid=5,fd=3))\n'
                         'LISTEN 0 128 0.0.0.0:9090 0.0.0.0:* users:(("prometheus",pid=6,fd=3))',
            "firewalld_state": "not running", "fips_enabled": "0", "crypto_policy": "DEFAULT",
            "chronyd": "inactive", "timedatectl": "NTPSynchronized=no",
            "rsyslog": "*.info /var/log/messages", "disk": "/dev/sda1 50G 40G 10G 80% /",
            "accounts": {
                "git": {"passwd": "git:x:998:998::/var/opt/gitlab:/bin/sh",
                        "id": "uid=998(git) gid=998(git) groups=998(git),10(wheel)", "sudo": ""},
                "gitlab-www": {"passwd": "gitlab-www:x:997:997::/var/opt/gitlab/nginx:/bin/bash",
                               "id": "uid=997(gitlab-www) gid=997(gitlab-www) groups=997(gitlab-www)",
                               "sudo": "User gitlab-www may run the following commands on host:\n (ALL) ALL"}},
            "repo_updates": {},
        },
        "http": {
            "sign_in": {"url": "http://gitlab.example.mil/users/sign_in", "status": 200,
                        "content": "<html>Sign in</html>", "server": "nginx/1.24.0"},
            "api_version": {"url": "http://gitlab.example.mil/api/v4/version", "status": 200},
            "api_projects": {"url": "http://gitlab.example.mil/api/v4/projects?per_page=5", "status": 200,
                             "json": [{"path_with_namespace": "group/secret-sauce"}]},
        },
        "tls": {},
    }


def hardened_evidence():
    return {
        "collected_at": "2026-09-30T12:00:00Z", "running": True,
        "package": {"name": "gitlab-fips", "version": "17.4.1-ee.0.el8"},
        "packages": "gitlab-fips|17.4.1-ee.0.el8",
        "version": "17.4.1",
        "services": "run: gitaly: (pid 1) 10s\nrun: nginx: (pid 2) 10s\nrun: puma: (pid 3) 10s",
        "external_url": "https://gitlab.example.mil",
        "gitlab_rb": "external_url 'https://gitlab.example.mil'\nnginx['redirect_http_to_https'] = true\n"
                     "logging['udp_log_shipping_host'] = '10.1.1.50'",
        "gitlab_yml": GITLAB_YML if HAVE_YAML else {"production": {
            "gitlab": {"host": "gitlab.example.mil", "port": 443, "https": True},
            "ldap": {"enabled": True, "servers": {"main": {"host": "dc01", "port": 636, "encryption": "simple_tls",
                                                           "verify_certificates": True}}},
            "omniauth": {"enabled": False, "providers": []},
            "smartcard": {"enabled": True, "ca_file": "/etc/gitlab/ssl/dod-cas.pem"}}},
        "rails": rails({
            "signup_enabled": False, "require_admin_approval_after_user_signup": True,
            "require_two_factor_authentication": True, "two_factor_grace_period": 0, "admin_mode": True,
            "session_expire_delay": 15, "remember_me_enabled": False,
            "password_authentication_enabled_for_web": False, "password_authentication_enabled_for_git": False,
            "default_project_visibility": 0, "default_group_visibility": 0, "restricted_visibility_levels": [20],
            "allow_local_requests_from_web_hooks_and_services": False,
            "allow_local_requests_from_system_hooks": False, "deactivate_dormant_users": False,
            "deactivate_dormant_users_period": 90, "enforce_terms": True,
            "usage_ping_enabled": False, "gravatar_enabled": False}, terms=BANNER),
        "processes": "git puma 6.4.2 (unix:///var/opt/gitlab/gitlab-rails/sockets/gitlab.socket)\n"
                     "git /opt/gitlab/embedded/bin/gitaly /var/opt/gitlab/gitaly/config.toml",
        "stats": [stat("/etc/gitlab", "root", "root", "775", "d"),
                  stat("/etc/gitlab/gitlab.rb", "root", "root", "600"),
                  stat("/etc/gitlab/gitlab-secrets.json", "root", "root", "600"),
                  stat("/etc/gitlab/ssl/gitlab.example.mil.key", "root", "root", "600"),
                  stat("/var/opt/gitlab/.ssh/authorized_keys", "git", "git", "600"),
                  stat("/opt/gitlab", "root", "root", "755", "d"),
                  stat("/opt/gitlab/embedded/bin", "root", "root", "755", "d")],
        "log_stats": [stat("/var/log/gitlab", "root", "root", "755", "d"),
                      stat("/var/log/gitlab/gitlab-rails", "git", "root", "700", "d"),
                      stat("/var/log/gitlab/gitlab-rails/audit_json.log", "git", "git", "644"),
                      stat("/var/log/gitlab/nginx", "root", "root", "700", "d"),
                      stat("/var/log/gitlab/nginx/gitlab_access.log", "root", "root", "644")],
        "world_writable": [], "rpm_verify_ran": True, "rpm_verify": ".M.......  c /opt/gitlab/etc/x",
        "system": {
            "listeners": 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=2,fd=7))\n'
                         'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=2,fd=8))\n'
                         'LISTEN 0 128 127.0.0.1:9090 0.0.0.0:* users:(("prometheus",pid=6,fd=3))\n'
                         'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=9,fd=3))',
            "firewalld_state": "running", "firewalld_config": "services: https ssh",
            "fips_enabled": "1", "crypto_policy": "FIPS",
            "chronyd": "active", "timedatectl": "NTPSynchronized=yes",
            "rsyslog": "*.* @@loghost.example.mil:514", "disk": "/dev/sdb1 200G 20G 180G 10% /var/log/gitlab",
            "accounts": {
                "git": {"passwd": "git:x:998:998::/var/opt/gitlab:/bin/sh",
                        "id": "uid=998(git) gid=998(git) groups=998(git)", "sudo": ""},
                "gitlab-www": {"passwd": "gitlab-www:x:997:997::/var/opt/gitlab/nginx:/bin/false",
                               "id": "uid=997(gitlab-www) gid=997(gitlab-www) groups=997(gitlab-www)", "sudo": ""}},
            "repo_updates": {},
        },
        "http": {
            "sign_in": {"url": "https://gitlab.example.mil/users/sign_in", "status": 200,
                        "content": "<div class='description'><p>%s</p></div>" % BANNER, "server": "nginx"},
            "api_version": {"url": "https://gitlab.example.mil/api/v4/version", "status": 401},
            "api_projects": {"url": "https://gitlab.example.mil/api/v4/projects?per_page=5", "status": 200, "json": []},
            "plain_http": {"url": "http://gitlab.example.mil/users/sign_in", "status": 301,
                           "location": "https://gitlab.example.mil/users/sign_in"},
        },
        "tls": {"tls1": TLS_NO, "tls1_1": TLS_NO, "tls1_2": TLS_OK, "tls1_3": TLS_OK},
    }


def by_id(results):
    return dict((r["id"], r) for r in results)


class GitLabEvaluateTests(unittest.TestCase):
    def test_every_check_reported_once(self):
        for ev in (insecure_evidence(), hardened_evidence(), {}):
            ids = [r["id"] for r in gs.gitlab_stig_evaluate(ev, SETTINGS)]
            self.assertEqual(ids, [c[0] for c in gs.CHECKS])

    def test_empty_evidence_is_not_a_finding_nowhere(self):
        r = by_id(gs.gitlab_stig_evaluate({}, SETTINGS))
        self.assertFalse([k for k, v in r.items() if v["status"] == gs.NF])

    def test_insecure_server(self):
        r = by_id(gs.gitlab_stig_evaluate(insecure_evidence(), SETTINGS))
        opened = [k for k, v in r.items() if v["status"] == gs.OPEN]
        for cid in ("GLAB-001", "GLAB-002", "GLAB-003", "GLAB-004", "GLAB-005", "GLAB-006", "GLAB-007",
                    "GLAB-008", "GLAB-009", "GLAB-010", "GLAB-011", "GLAB-013", "GLAB-014", "GLAB-015",
                    "GLAB-016", "GLAB-017", "GLAB-018", "GLAB-019", "GLAB-021", "GLAB-022", "GLAB-023",
                    "GLAB-024", "GLAB-025", "GLAB-026", "GLAB-028", "GLAB-029"):
            self.assertIn(cid, opened, "%s: %s" % (cid, r[cid]["finding_details"]))
        self.assertIn("secret-sauce", r["GLAB-002"]["finding_details"])
        self.assertIn("not the GitLab FIPS build", r["GLAB-013"]["finding_details"])
        self.assertIn("run as root", r["GLAB-014"]["finding_details"])
        self.assertIn("wheel", r["GLAB-014"]["finding_details"])
        self.assertNotIn("git has an interactive", r["GLAB-014"]["finding_details"])
        self.assertIn("initial_root_password", r["GLAB-015"]["finding_details"])
        self.assertIn("/opt/gitlab/embedded/bin/ruby", r["GLAB-016"]["finding_details"])
        self.assertNotIn("/opt/gitlab/etc/foo", r["GLAB-016"]["finding_details"])
        self.assertIn("gitlab-runner", r["GLAB-017"]["finding_details"])
        self.assertIn("9090", r["GLAB-018"]["finding_details"])
        self.assertIn("usage_ping_enabled", r["GLAB-019"]["finding_details"])
        self.assertIn("8181", r["GLAB-011"]["finding_details"])
        self.assertEqual(r["GLAB-012"]["status"], gs.NR)
        self.assertEqual(r["GLAB-020"]["status"], gs.NR)

    def test_hardened_server(self):
        r = by_id(gs.gitlab_stig_evaluate(hardened_evidence(), SETTINGS))
        expect_other = {"GLAB-009": gs.OPEN, "GLAB-019": gs.NR, "GLAB-020": gs.NR, "GLAB-027": gs.NR,
                        "GLAB-029": gs.NR, "GLAB-018": gs.NR}
        for cid, res in r.items():
            self.assertEqual(res["status"], expect_other.get(cid, gs.NF),
                             "%s: %s" % (cid, res["finding_details"]))

    def test_banner_without_acknowledgment_is_open(self):
        ev = hardened_evidence()
        ev["rails"] = ev["rails"].replace('"enforce_terms": true', '"enforce_terms": false')
        self.assertEqual(by_id(gs.gitlab_stig_evaluate(ev, SETTINGS))["GLAB-010"]["status"], gs.OPEN)

    def test_without_rails_settings(self):
        ev = hardened_evidence()
        ev["rails"] = ""
        r = by_id(gs.gitlab_stig_evaluate(ev, SETTINGS))
        for cid in ("GLAB-001", "GLAB-003", "GLAB-007", "GLAB-008", "GLAB-021", "GLAB-029"):
            self.assertEqual(r[cid]["status"], gs.NR, cid)
        self.assertEqual(r["GLAB-004"]["status"], gs.NF)  # smartcard is in gitlab.yml

    def test_approved_ports_and_services(self):
        s = dict(SETTINGS, approved_ports=[22, 80, 443], approved_services=["gitaly", "nginx", "puma"],
                 min_version="17.4.0")
        r = by_id(gs.gitlab_stig_evaluate(hardened_evidence(), s))
        self.assertEqual(r["GLAB-018"]["status"], gs.NF, r["GLAB-018"]["finding_details"])
        self.assertEqual(r["GLAB-019"]["status"], gs.NF)
        self.assertEqual(r["GLAB-020"]["status"], gs.NF)
        s["min_version"] = "17.10.0"
        self.assertEqual(by_id(gs.gitlab_stig_evaluate(hardened_evidence(), s))["GLAB-020"]["status"], gs.OPEN)

    def test_overrides(self):
        s = dict(SETTINGS, overrides={"GLAB-009": {"status": "NotAFinding", "comment": "IdP limits sessions"}})
        r = by_id(gs.gitlab_stig_evaluate(hardened_evidence(), s))["GLAB-009"]
        self.assertEqual((r["status"], r["original_status"]), ("NotAFinding", "Open"))
        self.assertIn("IdP limits sessions", r["comments"])


class GitLabParsingTests(unittest.TestCase):
    def test_gitlab_rb(self):
        rb = gs.gitlab_rb("external_url 'https://g.example.mil'\n# nginx['x'] = 1\n"
                          "nginx[\"redirect_http_to_https\"] = true\nlogging['udp_log_shipping_host'] = '10.0.0.5'")
        self.assertEqual(rb["external_url"], "https://g.example.mil")
        self.assertEqual(rb["nginx['redirect_http_to_https']"], "true")
        self.assertEqual(rb["logging['udp_log_shipping_host']"], "10.0.0.5")
        self.assertNotIn("nginx['x']", rb)

    @unittest.skipUnless(HAVE_YAML, "PyYAML not installed")
    def test_external_url_from_gitlab_yml(self):
        self.assertEqual(gs.gitlab_external_url(GITLAB_YML), "https://gitlab.example.mil")
        self.assertEqual(gs.gitlab_external_url(GITLAB_YML, "external_url 'https://x.mil/'"), "https://x.mil")
        self.assertEqual(gs.gitlab_external_url("not: [valid"), "")

    def test_probe_plan(self):
        p = gs.gitlab_probe_plan("https://gitlab.example.mil:8443/git")
        self.assertEqual((p["tls_host"], p["tls_port"]), ("gitlab.example.mil", 8443))
        self.assertEqual(p["plain_url"], "http://gitlab.example.mil/git/users/sign_in")
        p = gs.gitlab_probe_plan("http://gitlab.example.mil", "https://lb.example.mil")
        self.assertEqual(p["base_url"], "https://lb.example.mil")
        self.assertEqual(gs.gitlab_probe_plan("")["base_url"], "")

    @unittest.skipUnless(HAVE_YAML, "PyYAML not installed")
    def test_gitlab_yml_summary(self):
        summary = gs.gitlab_yml_summary(GITLAB_YML + "  extra:\n    pattern: !ruby/regexp /x/\n")
        self.assertEqual(summary["ldap"]["servers"]["main"]["encryption"], "simple_tls")
        self.assertNotIn("password", summary["ldap"]["servers"]["main"])
        self.assertTrue(summary["smartcard"]["enabled"])
        self.assertEqual(gs.gitlab_external_url(summary), "https://gitlab.example.mil")
        ev = hardened_evidence()
        ev["gitlab_yml"] = summary
        self.assertEqual(by_id(gs.gitlab_stig_evaluate(ev, SETTINGS))["GLAB-006"]["status"], gs.NF)
        ev["gitlab_yml"] = gs.gitlab_yml_summary("production: [unclosed")
        r = by_id(gs.gitlab_stig_evaluate(ev, SETTINGS))
        self.assertEqual(r["GLAB-006"]["status"], gs.NR)
        self.assertIn("could not be parsed", r["GLAB-006"]["finding_details"])

    def test_runit_loggers_are_not_root_app_processes(self):
        # First VM run: svlogd/runsv run as root by design and name the service in their arguments.
        ev = hardened_evidence()
        ev["processes"] = ("root svlogd /var/log/gitlab/gitaly\nroot runsv sidekiq\n"
                           "root svlogd -tt /var/log/gitlab/puma\ngit puma: cluster worker 0: 1234 [gitlab-puma-worker]")
        self.assertEqual(by_id(gs.gitlab_stig_evaluate(ev, SETTINGS))["GLAB-014"]["status"], gs.NF)
        ev["processes"] = "root /opt/gitlab/embedded/bin/ruby /opt/gitlab/embedded/bin/sidekiq-cluster *"
        self.assertEqual(by_id(gs.gitlab_stig_evaluate(ev, SETTINGS))["GLAB-014"]["status"], gs.OPEN)

    def test_reconfigure_owned_structure_sql(self):
        ev = hardened_evidence()
        ev["rpm_verify"] = ".....U...    /opt/gitlab/embedded/service/gitlab-rails/db/structure.sql"
        r = by_id(gs.gitlab_stig_evaluate(ev, SETTINGS))["GLAB-016"]
        self.assertEqual(r["status"], gs.NF, r["finding_details"])
        ev["rpm_verify"] = "S.5....T.    /opt/gitlab/embedded/service/gitlab-rails/db/structure.sql"
        self.assertEqual(by_id(gs.gitlab_stig_evaluate(ev, SETTINGS))["GLAB-016"]["status"], gs.OPEN)

    def test_rails_partial_failure_keeps_settings(self):
        ev = hardened_evidence()
        data = gs._rails(ev["rails"])
        data.pop("dormant", None)
        data["errors"] = {"dormant": "NoMethodError: undefined method `humans'"}
        ev["rails"] = json.dumps(data)
        r = by_id(gs.gitlab_stig_evaluate(ev, SETTINGS))
        self.assertEqual(r["GLAB-003"]["status"], gs.NF)
        self.assertIn("humans", r["GLAB-029"]["evidence"])

    def test_rails_output(self):
        self.assertEqual(gs._rails("noise\n{\"settings\": {\"a\": 1}}\n")["settings"], {"a": 1})
        self.assertEqual(gs._rails("boom"), {})


if __name__ == "__main__":
    unittest.main()
