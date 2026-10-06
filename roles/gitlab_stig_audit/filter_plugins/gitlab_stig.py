# -*- coding: utf-8 -*-
"""
Controller-side evaluation logic for the gitlab_stig_audit role (Omnibus GitLab on RHEL 8).

The role's tasks only collect evidence (read-only); every pass/fail decision is
made here so it can be unit tested without Ansible (tests/test_gitlab_stig.py).

Filters exported:
  gitlab_probe_plan    - external_url / audit URL -> URLs and TLS endpoint to probe
  gitlab_stig_evaluate - evidence dict -> list of check results
"""
from __future__ import absolute_import, division, print_function

import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "stig_common", "filter_plugins"))
import stig_common as sc  # noqa: E402

NF, OPEN, NA, NR = sc.NF, sc.OPEN, sc.NA, sc.NR

# srg_ids are base SRG requirement IDs, matched against the Application Server SRG.
CHECKS = [
    ("GLAB-001", "GitLab must authenticate users through the DoD enterprise ICAM, not local passwords",
     ["SRG-APP-000148"], "medium",
     "Configure LDAP (gitlab_rails['ldap_servers']), SAML/OIDC (gitlab_rails['omniauth_providers']) or smartcard "
     "authentication, then Admin > Settings > General > Sign-in restrictions: clear 'Allow password authentication "
     "for the web interface', or list the documented break-glass account(s) that keep it (e.g. root) in "
     "gitlab_stig_break_glass_accounts."),
    ("GLAB-002", "GitLab must restrict public visibility and anonymous access",
     ["SRG-APP-000033"], "high",
     "Admin > Settings > General > Visibility and access controls: add 'Public' to Restricted visibility levels, "
     "set default project/group/snippet visibility to Private or Internal, and make existing public projects private."),
    ("GLAB-003", "GitLab self-registration must be disabled or require administrator approval",
     ["SRG-APP-000033"], "medium",
     "Admin > Settings > General > Sign-up restrictions: clear 'Sign-up enabled' (or at least enable 'Require "
     "admin approval for new sign-ups')."),
    ("GLAB-004", "GitLab must require multifactor authentication",
     ["SRG-APP-000149", "SRG-APP-000820"], "high",
     "Admin > Settings > General > Sign-in restrictions: enable 'Enforce two-factor authentication' with a 0-hour "
     "grace period, enable smartcard authentication, or federate to an IdP that enforces MFA."),
    ("GLAB-005", "GitLab must accept and electronically verify DoD PIV/CAC credentials",
     ["SRG-APP-000391", "SRG-APP-000392"], "high",
     "Enable smartcard authentication (gitlab_rails['smartcard_enabled'] = true with smartcard_ca_file set to the "
     "DoD root/intermediate CA bundle), or federate (SAML/OIDC) to an IdP that requires CAC/PIV."),
    ("GLAB-006", "LDAP authentication traffic must be encrypted and certificates validated",
     ["SRG-APP-000172", "SRG-APP-000439"], "medium",
     "Set 'encryption' => 'simple_tls' (LDAPS) or 'start_tls' and 'verify_certificates' => true for every "
     "gitlab_rails['ldap_servers'] entry, then run gitlab-ctl reconfigure."),
    ("GLAB-007", "GitLab 'Remember me' persistent sessions must be disabled",
     ["SRG-APP-000400"], "medium",
     "Admin > Settings > General > Sign-in restrictions: clear 'Allow users to extend their session' (remember me)."),
    ("GLAB-008", "GitLab sessions must expire after the organization-defined inactivity period",
     ["SRG-APP-000295"], "medium",
     "Admin > Settings > General > Account and limit: set 'Session duration (minutes)' to the organization limit."),
    ("GLAB-009", "GitLab must limit concurrent sessions per account",
     ["SRG-APP-000001"], "low",
     "GitLab has no per-account concurrent session limit. Enforce it at the IdP/reverse proxy or record the risk "
     "acceptance with gitlab_stig_overrides."),
    ("GLAB-010", "The DoD Notice and Consent Banner must be displayed and acknowledged before access",
     ["SRG-APP-000068", "SRG-APP-000069"], "medium",
     "Admin > Settings > Appearance > Sign-in page description: add the Standard Mandatory DoD Notice and Consent "
     "Banner. Enforce acknowledgment with Admin > Settings > General > Terms of Service and Privacy Policy "
     "('All users must accept') containing the banner."),
    ("GLAB-011", "GitLab must only be reachable over HTTPS",
     ["SRG-APP-000014", "SRG-APP-000015", "SRG-APP-000439", "SRG-APP-000172"], "high",
     "Set external_url 'https://...' with a DoD-issued certificate (nginx['ssl_certificate']), set "
     "nginx['redirect_http_to_https'] = true, and keep Puma/Workhorse on Unix sockets or loopback."),
    ("GLAB-012", "GitLab TLS endpoints must not accept SSL or TLS 1.0/1.1",
     ["SRG-APP-000014", "SRG-APP-000439"], "medium",
     "Set nginx['ssl_protocols'] = 'TLSv1.2 TLSv1.3' (Omnibus default) or restrict the reverse proxy's protocols."),
    ("GLAB-013", "FIPS 140-validated cryptography must be used",
     ["SRG-APP-000179", "SRG-APP-000514"], "high",
     "Run 'fips-mode-setup --enable' and reboot, and install the GitLab FIPS package (gitlab-fips) so GitLab's "
     "bundled components use the system's FIPS-validated OpenSSL."),
    ("GLAB-014", "GitLab must run under non-privileged, non-interactive service accounts",
     ["SRG-APP-000342"], "medium",
     "Keep Puma, Sidekiq, Gitaly and Workhorse running as 'git'. No service account may have UID 0, sudo rights or "
     "wheel/docker membership; set /sbin/nologin on accounts that do not need a shell."),
    ("GLAB-015", "GitLab configuration, secrets and private keys must be protected",
     ["SRG-APP-000380", "SRG-APP-000171", "SRG-APP-000176"], "medium",
     "chmod 0600 /etc/gitlab/gitlab.rb /etc/gitlab/gitlab-secrets.json /etc/gitlab/ssl/*.key (owner root); delete "
     "/etc/gitlab/initial_root_password; remove world-writable files."),
    ("GLAB-016", "GitLab application binaries must be protected from modification",
     ["SRG-APP-000133"], "medium",
     "Keep /opt/gitlab owned by root and not writable by the git account; reinstall the package if 'rpm -V' "
     "reports modified files."),
    ("GLAB-017", "Administrative functions must be separated from user functions",
     ["SRG-APP-000211"], "medium",
     "Admin > Settings > General > Sign-in restrictions: enable 'Admin Mode' so administrators re-authenticate "
     "before admin actions. Run CI jobs on dedicated runner hosts, not on the GitLab server."),
    ("GLAB-018", "GitLab must only use approved (PPSM) ports and protocols",
     ["SRG-APP-000142"], "medium",
     "Bind Prometheus, exporters, Redis, PostgreSQL and Puma to localhost or Unix sockets, keep firewalld active, "
     "and declare gitlab_stig_approved_ports."),
    ("GLAB-019", "Unnecessary GitLab components and features must be disabled",
     ["SRG-APP-000141"], "medium",
     "Disable unused bundled services in gitlab.rb (registry['enable'], gitlab_pages['enable'], mattermost['enable'], "
     "prometheus_monitoring['enable'] = false), set the listed application settings, and declare "
     "gitlab_stig_approved_services."),
    ("GLAB-020", "GitLab must be a supported release with security updates installed",
     ["SRG-APP-000456", "SRG-APP-001035"], "medium",
     "Upgrade to a GitLab release that still receives security fixes (the current and two previous minor releases) "
     "and apply security patch releases within 30 days."),
    ("GLAB-021", "GitLab must block outbound requests to the local network from webhooks and integrations",
     ["SRG-APP-000516"], "medium",
     "Admin > Settings > Network > Outbound requests: clear 'Allow requests to the local network from webhooks and "
     "integrations' and '... from system hooks'; allowlist required internal hosts instead."),
    ("GLAB-022", "GitLab must not reveal version details to unauthenticated users",
     ["SRG-APP-000266", "SRG-APP-000267"], "low",
     "Keep /api/v4/version authenticated (default), keep nginx['server_tokens'] off, and strip version headers at "
     "any reverse proxy."),
    ("GLAB-023", "GitLab must generate audit records for security-relevant events",
     ["SRG-APP-000089", "SRG-APP-000095", "SRG-APP-000096", "SRG-APP-000097", "SRG-APP-000098",
      "SRG-APP-000099", "SRG-APP-000100", "SRG-APP-000503", "SRG-APP-000509"], "medium",
     "Use GitLab Premium/Ultimate audit events (with streaming to the SIEM) and collect "
     "/var/log/gitlab/gitlab-rails/audit_json.log."),
    ("GLAB-024", "GitLab must log remote (HTTP) access",
     ["SRG-APP-000016"], "low",
     "Keep the bundled NGINX access log (/var/log/gitlab/nginx/gitlab_access.log) enabled, or log at the reverse proxy."),
    ("GLAB-025", "GitLab log files must be protected from unauthorized read, modification and deletion",
     ["SRG-APP-000118", "SRG-APP-000119", "SRG-APP-000120"], "medium",
     "Keep /var/log/gitlab/<service> directories 0700/0750 (Omnibus default) and log files 0640 or stricter; "
     "/var/log/gitlab itself must not be group/world writable."),
    ("GLAB-026", "GitLab audit records must be off-loaded to a centralized log server",
     ["SRG-APP-000358"], "low",
     "Set logging['udp_log_shipping_host'] in gitlab.rb, or read /var/log/gitlab with rsyslog imfile and forward it."),
    ("GLAB-027", "Audit storage capacity must be allocated and monitored",
     ["SRG-APP-000357", "SRG-APP-000359"], "low",
     "Place /var/log/gitlab on a filesystem sized for retention and alert the SA/ISSO at 75% usage."),
    ("GLAB-028", "Audit time stamps must come from a synchronized, authoritative time source",
     ["SRG-APP-000116", "SRG-APP-000374", "SRG-APP-000920"], "medium",
     "Enable chronyd and synchronize to a DoD-approved time source."),
    ("GLAB-029", "Accounts must be disabled after 35 days of inactivity",
     ["SRG-APP-000163", "SRG-APP-000705"], "medium",
     "Disable inactive accounts at the IdP/directory (GitLab blocks LDAP users removed from the directory), or "
     "Admin > Settings > General > Account and limit: enable dormant user deactivation (GitLab's minimum period "
     "is 90 days, so record the gap with gitlab_stig_overrides)."),
]
CHECK_META = sc.catalog(CHECKS)

# Components that ship inside Omnibus and should only listen on loopback/sockets.
INTERNAL_PROCS = ("puma", "ruby", "bundle", "gitaly", "workhorse", "redis", "postgres", "prometheus",
                  "exporter", "alertmanager", "grafana", "sidekiq", "patroni", "consul", "pgbouncer")
PUBLIC_PROCS = ("nginx", "gitlab-sshd", "registry", "gitlab-pages", "gitlab-kas", "mattermost")
APP_PROCESS_RX = r"(^|/)(puma|sidekiq|gitaly|gitlab-workhorse)\b"
PUBLIC_LEVEL = 20
# Packaged files `gitlab-ctl reconfigure` hands to the git user (so migrations can dump the schema).
RECONFIGURE_OWNED = ("embedded/service/gitlab-rails/db/structure.sql", "embedded/service/gitlab-rails/db/schema.rb")


# ---------------------------------------------------------------------------
# parsing helpers
# ---------------------------------------------------------------------------
def _load_yaml(text):
    """Rendered gitlab.yml -> (its 'production' section or {}, parse error or "")."""
    if isinstance(text, dict):
        return text.get("production", text), ""
    if not text:
        return {}, ""
    try:
        import yaml

        class Loader(yaml.SafeLoader):
            pass

        # Rails YAML can carry Ruby tags (!ruby/regexp, !ruby/object:...); read them as plain values.
        def untagged(loader, suffix, node):
            if isinstance(node, yaml.MappingNode):
                return loader.construct_mapping(node)
            if isinstance(node, yaml.SequenceNode):
                return loader.construct_sequence(node)
            return loader.construct_scalar(node)

        Loader.add_multi_constructor("!", untagged)
        data = yaml.load(text, Loader=Loader)  # noqa: S506 - SafeLoader subclass
    except Exception as e:  # noqa: BLE001 - any parse problem means "no evidence"
        return {}, "%s: %s" % (type(e).__name__, str(e).splitlines()[0][:200] if str(e) else "")
    if not isinstance(data, dict):
        return {}, "unexpected top-level %s" % type(data).__name__
    return data.get("production", data) or {}, ""


def _yaml(text):
    """Rendered gitlab.yml -> its 'production' section (or {} when unavailable)."""
    return _load_yaml(text)[0]


def gitlab_yml_summary(text):
    """Unredacted gitlab.yml -> only the non-secret settings the checks read, so it is parsed before
    redaction can alter it.  A parse failure is kept in 'parse_error'."""
    gl, err = _load_yaml(text)
    if err or not gl:
        return {"parse_error": err or ("empty" if not text else "no production section")}
    pick = lambda d, keys: dict((k, d[k]) for k in keys if isinstance(d, dict) and k in d)  # noqa: E731
    ldap = gl.get("ldap") or {}
    omni = gl.get("omniauth") or {}
    return {
        "gitlab": pick(gl.get("gitlab") or {}, ("host", "https", "port", "relative_url_root")),
        "ldap": dict(pick(ldap, ("enabled",)), servers=dict(
            (label, pick(srv or {}, ("host", "port", "encryption", "verify_certificates")))
            for label, srv in (ldap.get("servers") or {}).items())),
        "omniauth": dict(pick(omni, ("enabled",)), providers=[
            {"name": p.get("name", "?")} for p in (omni.get("providers") or []) if isinstance(p, dict)]),
        "smartcard": pick(gl.get("smartcard") or {}, ("enabled", "ca_file", "required_for_git_access")),
    }


def gitlab_rb(text):
    """Top-level assignments from gitlab.rb: {"external_url": "...", "nginx['listen_https']": "false", ...}."""
    out = {}
    for line in sc._lines(text):
        s = line.strip()
        if s.startswith("#"):
            continue
        m = re.match(r"""^external_url\s+['"]([^'"]+)['"]""", s)
        if m:
            out["external_url"] = m.group(1)
            continue
        m = re.match(r"""^([a-z_]+(?:\[['"][^'"]+['"]\])+)\s*=\s*(.+?)\s*$""", s)
        if m:
            key = re.sub(r"\[\"([^\"]+)\"\]", r"['\1']", m.group(1))
            out[key] = m.group(2).strip().strip("'\"")
    return out


def _rails(stdout):
    """Last JSON object line printed by the gitlab-rails runner task."""
    if isinstance(stdout, dict):
        return stdout
    for line in reversed(sc._lines(stdout)):
        if line.strip().startswith("{"):
            data = sc._json(line.strip())
            if isinstance(data, dict):
                return data
    return {}


def gitlab_external_url(gitlab_yml, gitlab_rb_text=""):
    """external_url from gitlab.rb, else rebuilt from the rendered gitlab.yml."""
    url = gitlab_rb(gitlab_rb_text).get("external_url")
    if url:
        return url.rstrip("/")
    g = _yaml(gitlab_yml).get("gitlab") or {}
    if not g.get("host"):
        return ""
    https = _bool(g.get("https"), False)
    port = sc._int(g.get("port"))
    default = 443 if https else 80
    return "%s://%s%s%s" % ("https" if https else "http", g["host"], ":%d" % port if port and port != default else "",
                            (g.get("relative_url_root") or "").rstrip("/"))


def gitlab_probe_plan(external_url, audit_url=""):
    """URLs to probe from the target, derived from the audit URL or external_url."""
    base = (audit_url or external_url or "").rstrip("/")
    plan = {"base_url": base, "tls_host": "", "tls_port": 0, "plain_url": ""}
    m = re.match(r"^(https?)://([^/:]+|\[[^\]]+\])(?::(\d+))?(/.*)?$", base)
    if not m:
        return plan
    scheme, host, port, path = m.group(1), m.group(2), m.group(3), m.group(4) or ""
    if scheme == "https":
        plan["tls_host"] = host.strip("[]")
        plan["tls_port"] = int(port or 443)
        plan["plain_url"] = "http://%s%s/users/sign_in" % (host, path)
    return plan


def _command(args):
    """The program a `ps` args line runs (the script for ruby/bundle), not its arguments: runit's
    `svlogd /var/log/gitlab/gitaly` and `runsv gitaly` run as root by design and are not GitLab itself."""
    words = str(args).split()
    if len(words) > 1 and re.search(r"(^|/)(ruby|bundle)$", words[0]):
        return words[1]
    return words[0] if words else ""


def _bool(v, default=None):
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        return v
    return sc._truthy(v)


def _levels(v):
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [sc._int(x) for x in v]
    return [sc._int(x) for x in re.findall(r"\d+", str(v))]


def _vis(v):
    return {0: "private", 10: "internal", 20: "public"}.get(sc._int(v), str(v))


# ---------------------------------------------------------------------------
# filter: gitlab_stig_evaluate
# ---------------------------------------------------------------------------
def gitlab_stig_evaluate(ev, settings=None):
    s = settings or {}
    ev = ev or {}
    host = ev.get("system") or {}
    rb = gitlab_rb(ev.get("gitlab_rb"))
    gl, gl_err = _load_yaml(ev.get("gitlab_yml"))
    if isinstance(gl, dict) and "parse_error" in gl:   # from gitlab_yml_summary
        gl, gl_err = {}, gl["parse_error"]
    if gl_err and gl_err != "empty":
        no_gl = "gitlab.yml could not be parsed (%s)." % gl_err
    else:
        no_gl = "gitlab.yml could not be read; run the audit with become: true."
    rails = _rails(ev.get("rails"))
    st = rails.get("settings") or {}
    have_st = bool(st)
    no_st = ("Application settings could not be read (gitlab-rails runner failed or "
             "gitlab_stig_query_settings is false).")
    if rails.get("error"):
        no_st = "gitlab-rails runner failed: %s" % rails["error"]
    http = ev.get("http") or {}
    stats = sc._parse_stats(ev.get("stats"))
    listeners = sc._listeners(host.get("listeners"))
    running = bool(ev.get("running"))
    package = ev.get("package") or {}
    edition = package.get("name", "")
    external_url = ev.get("external_url") or gitlab_external_url(gl, ev.get("gitlab_rb"))
    cfg_dir = (ev.get("config_dir") or "/etc/gitlab").rstrip("/")
    log_dir = (ev.get("log_dir") or "/var/log/gitlab").rstrip("/")
    install_dir = (ev.get("install_dir") or "/opt/gitlab").rstrip("/")
    tls_mode = s.get("tls_termination", "auto")
    R = sc.Results(CHECK_META)

    ldap = gl.get("ldap") or {}
    ldap_on = _bool(ldap.get("enabled"), False)
    omni = gl.get("omniauth") or {}
    providers = [p.get("name", "?") for p in (omni.get("providers") or []) if isinstance(p, dict)]
    omni_on = bool(providers) and _bool(omni.get("enabled"), True)
    smart = gl.get("smartcard") or {}
    smart_on = _bool(smart.get("enabled"), False)
    pw_web = _bool(st.get("password_authentication_enabled_for_web"), True)
    break_glass = sc._names(s.get("break_glass_accounts"))
    externals = (["LDAP"] if ldap_on else []) + (["OmniAuth: %s" % ", ".join(providers)] if omni_on else []) + \
                (["smartcard"] if smart_on else [])
    auth_ev = ["gitlab.yml ldap.enabled=%s" % ldap_on, "omniauth providers: %s" % (", ".join(providers) or "none"),
               "smartcard.enabled=%s" % smart_on,
               "password_authentication_enabled_for_web=%s" % st.get("password_authentication_enabled_for_web", "?"),
               "password_authentication_enabled_for_git=%s" % st.get("password_authentication_enabled_for_git", "?")]
    have_gl = bool(gl)

    # GLAB-001 ------------------------------------------------------------
    if not have_gl:
        R.add("GLAB-001", NR, no_gl, auth_ev)
    elif not externals:
        R.add("GLAB-001", OPEN, "Only GitLab's local password database is configured; no LDAP, SAML/OIDC or "
              "smartcard authentication.", auth_ev)
    elif not have_st:
        R.add("GLAB-001", NR, "Enterprise authentication is configured (%s). %s Verify password sign-in for the web "
              "interface is disabled." % ("; ".join(externals), no_st), auth_ev)
    elif pw_web:
        msg = "Enterprise authentication is configured (%s), but local password sign-in for the web interface is " \
              "still enabled." % "; ".join(externals)
        local = rails.get("local_users")
        if not isinstance(local, list):
            R.add("GLAB-001", OPEN, msg, auth_ev,
                  comments="If this is only for a documented break-glass account, list it in "
                           "gitlab_stig_break_glass_accounts or record it with gitlab_stig_overrides.")
        else:
            others = [u for u in local if str(u).lower() not in break_glass]
            exempt = [u for u in local if str(u).lower() in break_glass]
            auth_ev.append("active accounts without an LDAP/SAML/OIDC identity: %s" % (", ".join(
                "%s%s" % (u, " (break-glass)" if u in exempt else "") for u in local) or "none"))
            if others:
                R.add("GLAB-001", OPEN, msg + " Accounts that can only sign in with a GitLab password and are not "
                      "documented break-glass accounts: %s." % ", ".join(others[:20]), auth_ev,
                      comments="List documented break-glass accounts in gitlab_stig_break_glass_accounts.")
            else:
                R.add("GLAB-001", NF, "Users authenticate through %s. Password sign-in is still enabled, but %s." % (
                      "; ".join(externals), "the only accounts without an enterprise identity are documented "
                      "break-glass accounts (%s)" % ", ".join(exempt) if exempt else
                      "every active account has an enterprise identity"), auth_ev,
                      comments="Break-glass accounts per gitlab_stig_break_glass_accounts. Verify their credentials "
                               "are sealed/vaulted and their use is logged and reviewed.")
    else:
        R.add("GLAB-001", NF, "Users authenticate through %s; local password web sign-in is disabled." %
              "; ".join(externals), auth_ev)

    # GLAB-002 ------------------------------------------------------------
    issues, ev_lines = [], []
    if have_st:
        restricted = _levels(st.get("restricted_visibility_levels"))
        ev_lines.append("restricted_visibility_levels=%s" % (", ".join(_vis(l) for l in restricted) or "none"))
        if PUBLIC_LEVEL not in restricted:
            issues.append("'Public' is not a restricted visibility level; users can create public projects and groups.")
        for k in ("default_project_visibility", "default_group_visibility", "default_snippet_visibility"):
            if k in st:
                ev_lines.append("%s=%s" % (k, _vis(st[k])))
                if sc._int(st[k]) == PUBLIC_LEVEL:
                    issues.append("%s is public." % k)
    ap = http.get("api_projects") or {}
    if ap.get("status"):
        ev_lines.append("Unauthenticated GET %s -> HTTP %s" % (ap.get("url"), ap.get("status")))
        body = ap.get("json")
        if ap.get("status") == 200 and isinstance(body, list) and body:
            issues.append("Unauthenticated users can list public projects, e.g. %s." %
                          ", ".join(str(p.get("path_with_namespace", "?")) for p in body[:5] if isinstance(p, dict)))
    if issues:
        R.add("GLAB-002", OPEN, issues, ev_lines)
    elif not have_st:
        R.add("GLAB-002", NR, no_st + " No public projects were visible anonymously.", ev_lines)
    else:
        R.add("GLAB-002", NF, "Public visibility is restricted and no project is visible anonymously.", ev_lines)

    # GLAB-003 ------------------------------------------------------------
    if not have_st:
        R.add("GLAB-003", NR, no_st)
    else:
        su = _bool(st.get("signup_enabled"), True)
        appr = _bool(st.get("require_admin_approval_after_user_signup"), False)
        ev_lines = ["signup_enabled=%s" % st.get("signup_enabled"),
                    "require_admin_approval_after_user_signup=%s" % st.get("require_admin_approval_after_user_signup")]
        if not su:
            R.add("GLAB-003", NF, "Self-registration is disabled.", ev_lines)
        elif appr:
            R.add("GLAB-003", NF, "Self-registration is enabled, but every new account needs administrator approval.",
                  ev_lines, comments="Disabling sign-up entirely is preferred.")
        else:
            R.add("GLAB-003", OPEN, "Anyone who can reach GitLab can create an account without approval.", ev_lines)

    # GLAB-004 ------------------------------------------------------------
    tfa = _bool(st.get("require_two_factor_authentication"), False)
    grace = st.get("two_factor_grace_period")
    mfa_ev = auth_ev + ["require_two_factor_authentication=%s" % st.get("require_two_factor_authentication", "?"),
                        "two_factor_grace_period=%s hours" % grace]
    if smart_on:
        R.add("GLAB-004", NF, "Smartcard (certificate) authentication is enabled.", mfa_ev,
              comments="GLAB-001 reports whether password sign-in can still bypass it.")
    elif tfa:
        R.add("GLAB-004", NF, "Two-factor authentication is enforced for all users (grace period %s hours)." % grace, mfa_ev)
    elif omni_on and have_st and not pw_web:
        R.add("GLAB-004", NR, "Authentication is federated (%s). Verify the IdP enforces MFA, then record the "
              "result with gitlab_stig_overrides." % ", ".join(providers), mfa_ev)
    elif not (have_gl and have_st):
        R.add("GLAB-004", NR, no_gl if not have_gl else no_st, mfa_ev)
    else:
        R.add("GLAB-004", OPEN, "Multifactor authentication is not enforced.", mfa_ev)

    # GLAB-005 ------------------------------------------------------------
    piv_ev = auth_ev + ["smartcard ca_file=%s" % smart.get("ca_file", "(unset)"),
                        "smartcard required_for_git_access=%s" % smart.get("required_for_git_access", "?")]
    if smart_on:
        R.add("GLAB-005", NF, "Smartcard (CAC/PIV) authentication is enabled.", piv_ev,
              comments="Verify smartcard_ca_file contains only the DoD root and intermediate CAs.")
    elif omni_on and have_st and not pw_web:
        R.add("GLAB-005", NR, "Authentication is federated (%s). Verify the IdP requires CAC/PIV." % ", ".join(providers), piv_ev)
    elif not have_gl:
        R.add("GLAB-005", NR, no_gl, piv_ev)
    else:
        R.add("GLAB-005", OPEN, "GitLab does not accept PIV/CAC credentials (no smartcard or CAC-enforcing IdP).", piv_ev)

    # GLAB-006 ------------------------------------------------------------
    if not gl:
        R.add("GLAB-006", NR, no_gl)
    elif not ldap_on:
        R.add("GLAB-006", NA, "LDAP authentication is not enabled.")
    else:
        issues, ev_lines = [], []
        for label, srv in sorted((ldap.get("servers") or {}).items()):
            srv = srv or {}
            enc = str(srv.get("encryption", "plain")).lower()
            verify = _bool(srv.get("verify_certificates"), True)
            ev_lines.append("%s: host=%s port=%s encryption=%s verify_certificates=%s" %
                            (label, srv.get("host"), srv.get("port"), enc, verify))
            if enc in ("plain", "", "none"):
                issues.append("LDAP server '%s' uses unencrypted LDAP (encryption=%s)." % (label, enc))
            if not verify:
                issues.append("LDAP server '%s' does not verify certificates." % label)
        if not ev_lines:
            R.add("GLAB-006", NR, "LDAP is enabled but no servers were found in gitlab.yml.")
        else:
            R.verdict("GLAB-006", issues, "All LDAP servers use TLS with certificate validation.", ev_lines)

    # GLAB-007 ------------------------------------------------------------
    if not have_st:
        R.add("GLAB-007", NR, no_st)
    elif "remember_me_enabled" not in st:
        R.add("GLAB-007", NR, "This GitLab release has no setting to disable 'Remember me'; the option is always "
              "offered.", comments="Upgrade, or record a risk acceptance with gitlab_stig_overrides.")
    elif _bool(st.get("remember_me_enabled"), True):
        R.add("GLAB-007", OPEN, "'Remember me' is enabled; users can extend sessions with a persistent cookie.",
              "remember_me_enabled=%s" % st.get("remember_me_enabled"))
    else:
        R.add("GLAB-007", NF, "'Remember me' is disabled.", "remember_me_enabled=false")

    # GLAB-008 ------------------------------------------------------------
    limit = sc._int(s.get("max_session_timeout"), 15)
    if not have_st:
        R.add("GLAB-008", NR, no_st)
    else:
        d = sc._int(st.get("session_expire_delay"))
        if d is None:
            R.add("GLAB-008", NR, "session_expire_delay was not returned.")
        else:
            R.verdict("GLAB-008", ["Session duration is %d minutes (organization limit %d)." % (d, limit)] if d > limit else [],
                      "Session duration is %d minutes (limit %d)." % (d, limit), "session_expire_delay=%s" % d)

    # GLAB-009 ------------------------------------------------------------
    R.add("GLAB-009", OPEN, "GitLab provides no mechanism to limit concurrent sessions per account.",
          comments="Mitigate at the IdP/proxy or document a risk acceptance via gitlab_stig_overrides.")

    # GLAB-010 ------------------------------------------------------------
    rx = s.get("banner_regex") or sc.DEFAULT_BANNER
    status, details, ev_lines = sc.eval_banner(http.get("sign_in"), rx, running or bool(s.get("audit_url")))
    terms = str(rails.get("terms") or "")
    enforce = _bool(st.get("enforce_terms"), False)
    if have_st:
        ev_lines = ev_lines + ["enforce_terms=%s" % enforce,
                               "terms contain the banner: %s" % bool(re.search(rx, terms, re.I))]
    if status == NF and have_st and not (enforce and re.search(rx, terms, re.I)):
        R.add("GLAB-010", OPEN, "The banner is shown on the sign-in page, but users are not required to acknowledge "
              "it (no enforced Terms of Service containing the banner).", ev_lines)
    elif status == NF and not have_st:
        R.add("GLAB-010", NF, details, ev_lines, comments="Verify the banner requires explicit acknowledgment.")
    else:
        R.add("GLAB-010", status, details, ev_lines)

    # GLAB-011 ------------------------------------------------------------
    issues, ev_lines = [], ["external_url=%s" % (external_url or "?")]
    if external_url and not external_url.lower().startswith("https://"):
        issues.append("external_url uses http:// (%s)." % external_url)
    for k in ("nginx['redirect_http_to_https']", "nginx['listen_https']", "gitlab_workhorse['listen_network']"):
        if k in rb:
            ev_lines.append("gitlab.rb %s = %s" % (k, rb[k]))
    pp = http.get("plain_http") or {}
    if pp.get("status"):
        ev_lines.append("GET %s -> HTTP %s %s" % (pp.get("url"), pp.get("status"), pp.get("location", "")))
        if pp.get("status") == 200:
            issues.append("GitLab is served over plaintext HTTP at %s." % pp.get("url"))
        elif 300 <= (pp.get("status") or 0) < 400 and not str(pp.get("location", "")).lower().startswith("https://"):
            issues.append("Plaintext HTTP redirects somewhere other than HTTPS (%s)." % pp.get("location"))
    exposed_app = [l for l in listeners if not sc._is_loopback(l["addr"]) and
                   any(p in l["proc"] for p in ("puma", "workhorse", "ruby", "bundle"))]
    if exposed_app:
        issues.append("Application server port(s) reachable without NGINX/TLS: %s" %
                      ", ".join(sc._fmt_listener(l) for l in exposed_app))
    if not external_url and not listeners:
        R.add("GLAB-011", NR, "external_url could not be determined and no listeners were observed.", ev_lines)
    else:
        R.verdict("GLAB-011", issues, "GitLab is only reachable over HTTPS.", ev_lines,
                  comments="TLS is terminated by a reverse proxy; verify only the proxy can reach GitLab."
                  if tls_mode == "proxy" else "")

    # GLAB-012 ------------------------------------------------------------
    plan = gitlab_probe_plan(external_url, s.get("audit_url", ""))
    status, details, ev_lines = sc.eval_tls(ev.get("tls"), "%s:%s" % (plan["tls_host"], plan["tls_port"]))
    R.add("GLAB-012", status, details, ev_lines)

    # GLAB-013 ------------------------------------------------------------
    extra = []
    if edition and "fips" not in edition:
        extra.append("The installed package is %s, not the GitLab FIPS build (gitlab-fips); its bundled "
                     "components do not use FIPS-validated cryptography." % edition)
    status, details, ev_lines = sc.eval_fips(host, extra_issues=extra)
    R.add("GLAB-013", status, details, ev_lines + ["package: %s %s" % (edition or "?", package.get("version", ""))])

    # GLAB-014 ------------------------------------------------------------
    accounts = s.get("service_accounts") or ["git"]
    status, details, ev_lines = sc.eval_accounts(host, accounts, s.get("shell_exceptions") or {})
    root_procs = [l for l in sc._lines(ev.get("processes"))
                  if l.split(None, 1)[0] == "root" and re.search(APP_PROCESS_RX, _command(l.split(None, 1)[-1]))]
    issues = list(details) if status == OPEN else []
    if root_procs:
        issues.append("GitLab application processes run as root: %s" % "; ".join(p[:120] for p in root_procs[:5]))
    if issues:
        R.add("GLAB-014", OPEN, issues, ev_lines)
    else:
        R.add("GLAB-014", status, details, ev_lines)

    # GLAB-015 ------------------------------------------------------------
    issues, ev_lines = [], []
    rules = [(cfg_dir, 0o002, None), (cfg_dir + "/gitlab.rb", 0o077, "root"),
             (cfg_dir + "/gitlab-secrets.json", 0o077, "root"),
             ((ev.get("data_dir") or "/var/opt/gitlab").rstrip("/") + "/.ssh/authorized_keys", 0o077, None)]
    rules += [(p, 0o077, None) for p in stats if p.startswith(cfg_dir + "/ssl/") and p.endswith(".key")]
    for path, mask, owner in rules:
        st_ = stats.get(path)
        if not st_:
            continue
        ev_lines.append(sc._fmt_stat(st_))
        m = sc._mode(st_)
        if m is not None and m & mask:
            issues.append("%s mode %s is too permissive (must not include %04o)." % (path, st_["mode"], mask))
        if owner and st_.get("owner") != owner:
            issues.append("%s is owned by %s (must be %s)." % (path, st_.get("owner"), owner))
    if stats.get(cfg_dir + "/initial_root_password"):
        issues.append("%s/initial_root_password still exists." % cfg_dir)
    ww = sc._lines(ev.get("world_writable"))
    if ww:
        issues.append("%d world-writable file(s) under GitLab directories, e.g. %s" % (len(ww), ", ".join(ww[:5])))
    if not stats.get(cfg_dir + "/gitlab.rb"):
        R.add("GLAB-015", NR, "Could not stat %s/gitlab.rb; run the audit with become: true." % cfg_dir, ev_lines)
    else:
        R.verdict("GLAB-015", issues, "GitLab configuration, secrets and keys are restricted.", ev_lines)

    # GLAB-016 ------------------------------------------------------------
    issues, ev_lines = [], []
    for path in (install_dir, install_dir + "/bin", install_dir + "/embedded/bin"):
        st_ = stats.get(path)
        if not st_:
            continue
        ev_lines.append(sc._fmt_stat(st_))
        m = sc._mode(st_)
        if st_.get("owner") != "root":
            issues.append("%s is owned by %s (must be root)." % (path, st_.get("owner")))
        if m is not None and m & 0o022:
            issues.append("%s is group/world writable (mode %s)." % (path, st_["mode"]))
    issues += sc.rpm_verify_issues(ev.get("rpm_verify"), ev_lines,
                                   owner_changes=[install_dir + "/" + p for p in RECONFIGURE_OWNED])
    if not ev_lines:
        R.add("GLAB-016", NR, "%s was not found; verify binary protections manually." % install_dir)
    else:
        R.verdict("GLAB-016", issues, "GitLab binaries are root-owned and match the RPM database.", ev_lines,
                  comments="" if ev.get("rpm_verify_ran") else "rpm -V was skipped (gitlab_stig_rpm_verify).")

    # GLAB-017 ------------------------------------------------------------
    admins = rails.get("admins")
    issues, ev_lines = [], ["admin_mode=%s" % st.get("admin_mode", "?")]
    if admins is not None:
        ev_lines.append("%d active administrator(s): %s" % (len(admins), ", ".join(admins)))
    runner = [p for p in sc._lines(ev.get("packages")) if p.startswith("gitlab-runner")]
    if runner:
        issues.append("GitLab Runner is installed on the GitLab server (%s); CI jobs can run on the application "
                      "server." % runner[0].replace("|", " "))
    if have_st and not _bool(st.get("admin_mode"), False):
        issues.append("Admin Mode is disabled; administrators use admin functions in their normal user session.")
    if not have_st and not issues:
        R.add("GLAB-017", NR, no_st, ev_lines)
    else:
        R.verdict("GLAB-017", issues, "Admin Mode is enabled and no runner is installed on the server.", ev_lines)

    # GLAB-018 ------------------------------------------------------------
    gl_listeners = [l for l in listeners if any(p in l["proc"] for p in INTERNAL_PROCS + PUBLIC_PROCS)]
    status, details, ev_lines = sc.eval_ports(host, gl_listeners, s.get("approved_ports"), "GitLab")
    internal = [l for l in gl_listeners if not sc._is_loopback(l["addr"]) and
                any(p in l["proc"] for p in INTERNAL_PROCS)]
    if internal:
        issues = list(details) if status == OPEN else []
        issues.append("Internal component(s) listen on non-loopback addresses: %s" %
                      ", ".join(sc._fmt_listener(l) for l in internal))
        R.add("GLAB-018", OPEN, issues, ev_lines)
    else:
        R.add("GLAB-018", status, details, ev_lines)

    # GLAB-019 ------------------------------------------------------------
    services = sorted(set(m.group(2) for m in re.finditer(r"^(run|down|fail):\s*([\w\-]+):", str(ev.get("services") or ""), re.M)
                          if m.group(1) == "run"))
    issues, ev_lines = [], ["running services: %s" % (", ".join(services) or "unknown")]
    approved = s.get("approved_services") or []
    if approved:
        extra = [x for x in services if x not in approved]
        if extra:
            issues.append("Bundled services not in the approved baseline: %s" % ", ".join(extra))
    for k, want in sorted((s.get("expected_settings") or {}).items()):
        if k not in st:
            continue
        ev_lines.append("%s=%s (expected %s)" % (k, st[k], want))
        if str(st[k]).lower() != str(want).lower():
            issues.append("Application setting %s is %s (expected %s)." % (k, st[k], want))
    if issues:
        R.add("GLAB-019", OPEN, issues, ev_lines)
    elif approved and services:
        R.add("GLAB-019", NF, "Only approved components are running.", ev_lines)
    else:
        R.add("GLAB-019", NR, "Review the running components for mission need (or set "
              "gitlab_stig_approved_services to automate).", ev_lines)

    # GLAB-020 ------------------------------------------------------------
    version = ev.get("version") or package.get("version", "")
    status, details, ev_lines = sc.eval_updates(version, s.get("min_version"), host.get("repo_updates"), "GitLab")
    R.add("GLAB-020", status, details, ev_lines)

    # GLAB-021 ------------------------------------------------------------
    keys = ("allow_local_requests_from_web_hooks_and_services", "allow_local_requests_from_system_hooks")
    if not have_st:
        R.add("GLAB-021", NR, no_st)
    else:
        on = [k for k in keys if _bool(st.get(k), False)]
        R.verdict("GLAB-021", ["%s is enabled (server-side request forgery risk)." % k for k in on],
                  "Webhooks, integrations and system hooks cannot reach the local network.",
                  ["%s=%s" % (k, st.get(k, "?")) for k in keys])

    # GLAB-022 ------------------------------------------------------------
    issues, ev_lines = [], []
    av = http.get("api_version") or {}
    si = http.get("sign_in") or {}
    if av.get("status"):
        ev_lines.append("Unauthenticated GET %s -> HTTP %s" % (av.get("url"), av.get("status")))
        if av.get("status") == 200:
            issues.append("The version API answers unauthenticated requests.")
    server = si.get("server") or av.get("server")
    if server:
        ev_lines.append("Server: %s" % server)
        if re.search(r"\d", str(server)):
            issues.append("The Server header discloses version information (%s)." % server)
    if not ev_lines:
        R.add("GLAB-022", NR, "GitLab HTTP endpoints could not be probed.")
    else:
        R.verdict("GLAB-022", issues, "No version information is disclosed to unauthenticated users.", ev_lines)

    # GLAB-023 ------------------------------------------------------------
    log_stats = sc._parse_stats(ev.get("log_stats"))
    audit = log_stats.get(log_dir + "/gitlab-rails/audit_json.log")
    ev_lines = ["package: %s" % (edition or "?"),
                "audit_json.log: %s" % (sc._fmt_stat(audit) + " size=%s" % audit.get("size") if audit else "absent")]
    if not audit:
        R.add("GLAB-023", OPEN, "No GitLab audit log (%s/gitlab-rails/audit_json.log) was found." % log_dir, ev_lines)
    elif edition.startswith("gitlab-ce"):
        R.add("GLAB-023", NR, "GitLab CE writes audit_json.log but records only a subset of audit events; verify it "
              "covers the SRG's auditable events or use GitLab Premium/Ultimate.", ev_lines)
    else:
        R.add("GLAB-023", NF, "GitLab audit events are recorded.", ev_lines,
              comments="Verify audit events (and streaming, if used) cover the organization's auditable events.")

    # GLAB-024 ------------------------------------------------------------
    acc = log_stats.get(log_dir + "/nginx/gitlab_access.log")
    if acc:
        R.add("GLAB-024", NF, "The bundled NGINX access log records HTTP access.", sc._fmt_stat(acc))
    elif "nginx" in services and tls_mode != "proxy":
        R.add("GLAB-024", OPEN, "The bundled NGINX is running but writes no access log (%s/nginx/gitlab_access.log)." % log_dir)
    else:
        R.add("GLAB-024", NR, "The bundled NGINX is not serving GitLab; verify the reverse proxy's access log records "
              "source, time, request and outcome.")

    # GLAB-025 ------------------------------------------------------------
    owners = ["root"] + list(accounts)
    status, details, ev_lines = sc.eval_log_perms(ev.get("log_stats"), owners, traverse_dirs=[log_dir])
    R.add("GLAB-025", status, details, ev_lines)

    # GLAB-026 ------------------------------------------------------------
    remote = []
    ship = rb.get("logging['udp_log_shipping_host']")
    if ship and not sc._is_loopback(ship):
        remote.append("logging['udp_log_shipping_host'] = %s" % ship)
    status, details, ev_lines = sc.eval_offload(host, [log_dir], remote)
    R.add("GLAB-026", status, details, ev_lines)

    # GLAB-027 / GLAB-028 ---------------------------------------------------
    R.add("GLAB-027", *sc.eval_storage(host))
    R.add("GLAB-028", *sc.eval_time(host))

    # GLAB-029 ------------------------------------------------------------
    max_days = sc._int(s.get("max_inactive_days"), 35)
    dormant = rails.get("dormant")
    ev_lines = ["deactivate_dormant_users=%s" % st.get("deactivate_dormant_users", "?"),
                "deactivate_dormant_users_period=%s days" % st.get("deactivate_dormant_users_period", "?"),
                "active human accounts idle > %d days: %s" % (max_days, "?" if dormant is None else dormant)]
    idle = rails.get("dormant_users")
    if isinstance(idle, list) and idle:
        exempt = [u for u in idle if str(u).lower() in break_glass]
        ev_lines.append("idle accounts: %s%s" % (", ".join(idle[:20]), " ..." if len(idle) > 20 else ""))
        if exempt and dormant is not None:
            ev_lines.append("documented break-glass accounts not counted: %s" % ", ".join(exempt))
            dormant = max(sc._int(dormant, 0) - len(exempt), 0)
    if (rails.get("errors") or {}).get("dormant"):
        ev_lines.append("idle account count failed: %s" % rails["errors"]["dormant"])
    if not have_st:
        R.add("GLAB-029", NR, no_st, ev_lines)
    elif sc._int(dormant, 0) > 0:
        R.add("GLAB-029", OPEN, "%s active account(s) have been idle for more than %d days." % (dormant, max_days), ev_lines)
    elif _bool(st.get("deactivate_dormant_users"), False) and \
            (sc._int(st.get("deactivate_dormant_users_period"), 999) or 999) <= max_days:
        R.add("GLAB-029", NF, "Dormant accounts are deactivated after %s days." % st.get("deactivate_dormant_users_period"), ev_lines)
    elif ldap_on or omni_on:
        R.add("GLAB-029", NR, "Accounts come from %s. Verify the directory/IdP disables accounts after %d days of "
              "inactivity." % ("; ".join(externals), max_days), ev_lines)
    else:
        R.add("GLAB-029", OPEN, "Local accounts are not disabled after %d days of inactivity." % max_days, ev_lines)

    return sc.apply_overrides(R.items, s.get("overrides"))


class FilterModule(object):
    def filters(self):
        return {
            "gitlab_external_url": gitlab_external_url,
            "gitlab_yml_summary": gitlab_yml_summary,
            "gitlab_probe_plan": gitlab_probe_plan,
            "gitlab_stig_evaluate": gitlab_stig_evaluate,
        }
