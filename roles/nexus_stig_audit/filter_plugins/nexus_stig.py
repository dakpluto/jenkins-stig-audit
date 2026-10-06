# -*- coding: utf-8 -*-
"""
Controller-side evaluation logic for the nexus_stig_audit role (Sonatype Nexus
Repository 3 on RHEL 8).

The role's tasks only collect evidence (read-only); every pass/fail decision is
made here so it can be unit tested without Ansible (tests/test_nexus_stig.py).

Filters exported:
  nexus_runtime        - effective listener/context settings and the URLs to probe
  nexus_version        - Nexus version from the install layout or Server header
  nexus_api_sanitize   - drop password fields from REST API responses
  nexus_stig_evaluate  - evidence dict -> list of check results
"""
from __future__ import absolute_import, division, print_function

import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "stig_common", "filter_plugins"))
import stig_common as sc  # noqa: E402

NF, OPEN, NA, NR = sc.NF, sc.OPEN, sc.NA, sc.NR

CHECKS = [
    ("NXRM-001", "Nexus must authenticate users through the DoD enterprise ICAM, not local accounts",
     ["SRG-APP-000148"], "medium",
     "Administration > Security > LDAP (ldaps://) or SAML to the DoD IdP, then Administration > Security > "
     "Realms: remove 'Local Authenticating Realm' from the active list, or list the documented break-glass local "
     "account(s) it is kept for in nexus_stig_break_glass_accounts."),
    ("NXRM-002", "Nexus anonymous access must be disabled",
     ["SRG-APP-000033"], "high",
     "Administration > Security > Anonymous Access: clear 'Allow anonymous users to access the server'."),
    ("NXRM-003", "The built-in shared 'admin' account must be disabled and never use the default password",
     ["SRG-APP-000153"], "medium",
     "Grant nx-admin to named (LDAP/SAML) administrators, then set the local 'admin' user's status to Disabled. "
     "Remove -Dnexus.security.randompassword=false / nexus.security.randompassword=false."),
    ("NXRM-004", "Nexus must require DoD PIV/CAC or multifactor authentication",
     ["SRG-APP-000149", "SRG-APP-000391", "SRG-APP-000392", "SRG-APP-000820"], "high",
     "Use SAML to an IdP that requires CAC/PIV (Nexus Pro), or a reverse proxy that requires a DoD client "
     "certificate and passes the identity with the Remote User Token (rutauth) realm."),
    ("NXRM-005", "LDAP authentication traffic must be encrypted",
     ["SRG-APP-000172", "SRG-APP-000439"], "medium",
     "Administration > Security > LDAP: set every connection's protocol to ldaps and trust the directory's DoD CA."),
    ("NXRM-006", "Nexus sessions must expire after the organization-defined inactivity period",
     ["SRG-APP-000295"], "medium",
     "Administration > System > Capabilities > UI: Settings: set 'Session timeout' to the organization limit."),
    ("NXRM-007", "Nexus must limit concurrent sessions per account",
     ["SRG-APP-000001"], "low",
     "Nexus has no per-account concurrent session limit. Enforce it at the IdP/reverse proxy or record the risk "
     "acceptance with nexus_stig_overrides."),
    ("NXRM-008", "The DoD Notice and Consent Banner must be displayed before access",
     ["SRG-APP-000068", "SRG-APP-000069"], "medium",
     "Display the Standard Mandatory DoD Notice and Consent Banner with explicit acknowledgment before login "
     "(IdP login page, reverse proxy splash page, or the Branding capability in Nexus Pro)."),
    ("NXRM-009", "Nexus must only be reachable over HTTPS",
     ["SRG-APP-000014", "SRG-APP-000015", "SRG-APP-000439", "SRG-APP-000172"], "high",
     "Enable HTTPS (add ${jetty.etc}/jetty-https.xml to nexus-args and set application-port-ssl with a DoD-issued "
     "certificate) and remove jetty-http.xml, or set application-host=127.0.0.1 behind a TLS-terminating proxy."),
    ("NXRM-010", "Nexus TLS endpoints must not accept SSL or TLS 1.0/1.1",
     ["SRG-APP-000014", "SRG-APP-000439"], "medium",
     "Restrict protocols to TLS 1.2+ (RHEL crypto-policy DEFAULT/FIPS with the system JDK, IncludeProtocols in "
     "jetty-https.xml, or the proxy's ssl_protocols)."),
    ("NXRM-011", "FIPS 140-validated cryptography must be used",
     ["SRG-APP-000179", "SRG-APP-000514"], "high",
     "Run 'fips-mode-setup --enable' and reboot, run Nexus on the RHEL OpenJDK (INSTALL4J_JAVA_HOME_OVERRIDE) "
     "rather than a bundled JDK, and do not pass -Dcom.redhat.fips=false."),
    ("NXRM-012", "Nexus must run under a non-privileged, non-interactive service account",
     ["SRG-APP-000342"], "medium",
     "Set run_as_user=\"nexus\" in bin/nexus.rc (or User=nexus in the systemd unit); give the account /sbin/nologin, "
     "no sudo rights and no wheel/docker membership."),
    ("NXRM-013", "Nexus configuration, credentials and private keys must be protected",
     ["SRG-APP-000380", "SRG-APP-000171", "SRG-APP-000176"], "medium",
     "chmod 0750 the data directory (owner nexus); 0640 etc/nexus.properties; 0600 etc/fabric/nexus-store.properties "
     "and keystores; 0700 keystores/; delete admin.password after first login; remove world-writable files."),
    ("NXRM-014", "Nexus application binaries must be protected from modification",
     ["SRG-APP-000133"], "medium",
     "Keep the installation directory (bin, lib, system, etc) owned by root and not writable by the nexus account."),
    ("NXRM-015", "Nexus must only use approved (PPSM) ports and protocols",
     ["SRG-APP-000142"], "medium",
     "Bind Nexus to the registered ports only (application-port/-ssl, Docker connector ports), keep firewalld "
     "active, and declare nexus_stig_approved_ports."),
    ("NXRM-016", "Unnecessary Nexus features must be disabled",
     ["SRG-APP-000141"], "medium",
     "Remove nexus.scripts.allowCreation=true from etc/nexus.properties, delete stored scripts, and remove "
     "repositories and formats that are not mission-required."),
    ("NXRM-017", "Nexus must be a supported release with security updates installed",
     ["SRG-APP-000456", "SRG-APP-001035"], "medium",
     "Upgrade to a Nexus release covered by Sonatype's support policy and apply security releases within 30 days; "
     "run a supported Java release."),
    ("NXRM-018", "Nexus must not reveal version details to unauthenticated users",
     ["SRG-APP-000266", "SRG-APP-000267"], "low",
     "Remove or rewrite the 'Server: Nexus/<version>' response header at the reverse proxy "
     "(e.g. nginx proxy_hide_header Server)."),
    ("NXRM-019", "Nexus must generate audit records for security-relevant events",
     ["SRG-APP-000089", "SRG-APP-000095", "SRG-APP-000096", "SRG-APP-000097", "SRG-APP-000098",
      "SRG-APP-000099", "SRG-APP-000100", "SRG-APP-000503", "SRG-APP-000509"], "medium",
     "Administration > System > Capabilities: create and enable the 'Audit' capability (writes log/audit/audit.log)."),
    ("NXRM-020", "Nexus must log remote (HTTP) access",
     ["SRG-APP-000016"], "low",
     "Keep ${jetty.etc}/jetty-requestlog.xml in nexus-args (writes log/request.log), or log at the reverse proxy."),
    ("NXRM-021", "Nexus log files must be protected from unauthorized read, modification and deletion",
     ["SRG-APP-000118", "SRG-APP-000119", "SRG-APP-000120"], "medium",
     "chmod 0750 the log directories and 0640 (or stricter) the log files; owner nexus or root."),
    ("NXRM-022", "Nexus audit records must be off-loaded to a centralized log server",
     ["SRG-APP-000358"], "low",
     "Read <data>/log/audit/audit.log and request.log with rsyslog imfile and forward them (omfwd/@@)."),
    ("NXRM-023", "Audit storage capacity must be allocated and monitored",
     ["SRG-APP-000357", "SRG-APP-000359"], "low",
     "Place the Nexus log directory on a filesystem sized for retention and alert the SA/ISSO at 75% usage."),
    ("NXRM-024", "Audit time stamps must come from a synchronized, authoritative time source",
     ["SRG-APP-000116", "SRG-APP-000374", "SRG-APP-000920"], "medium",
     "Enable chronyd and synchronize to a DoD-approved time source."),
]
CHECK_META = sc.catalog(CHECKS)

LOCAL_REALM = "NexusAuthenticatingRealm"
PKI_REALMS = ("rutauth-realm",)
IDP_REALMS = ("SamlRealm",)
DIR_REALMS = ("LdapRealm", "Crowd")
DEFAULT_ARGS = "${jetty.etc}/jetty.xml,${jetty.etc}/jetty-http.xml,${jetty.etc}/jetty-requestlog.xml"
NO_API = ("Set nexus_stig_api_user / nexus_stig_api_password (a read-only account; see the README) so the "
          "security configuration can be read from the REST API.")


# ---------------------------------------------------------------------------
# filters used by the tasks
# ---------------------------------------------------------------------------
def nexus_runtime(files, cmdline=None, audit_url=""):
    """Effective Nexus settings from nexus-default.properties, nexus.properties and the JVM command line."""
    files = files or {}
    props = sc._parse_env(files.get("nexus-default.properties"))
    props.update(sc._parse_env(files.get("nexus.properties")))
    jvm = sc._jvm_properties(cmdline) if cmdline else {}
    if not jvm:
        jvm = sc._jvm_properties([l.strip() for l in sc._lines(files.get("nexus.vmoptions"))])
    args = props.get("nexus-args") or DEFAULT_ARGS
    # unresolved ${VAR} placeholders (e.g. the stock /${NEXUS_CONTEXT}) expand to nothing
    ctx = "/" + re.sub(r"\$\{[^}]*\}", "", props.get("nexus-context-path", "/")).strip("/")
    ctx = "" if ctx == "/" else ctx
    rt = {"props": props, "jvm": jvm, "nexus_args": args, "context": ctx,
          "http_enabled": "jetty-http.xml" in args, "https_enabled": "jetty-https.xml" in args,
          "request_log": "jetty-requestlog.xml" in args,
          "http_port": sc._int(props.get("application-port"), 8081),
          "https_port": sc._int(props.get("application-port-ssl"), None),
          "host": props.get("application-host", "0.0.0.0")}

    h = rt["host"]
    h = "127.0.0.1" if h in ("", "0.0.0.0", "::", "*") else ("[%s]" % h if ":" in h else h)
    plan = {"base_url": "", "tls_host": "", "tls_port": 0, "plain_url": ""}
    if audit_url:
        plan["base_url"] = audit_url.rstrip("/")
        m = re.match(r"^https://([^/:]+|\[[^\]]+\])(?::(\d+))?", plan["base_url"])
        if m:
            plan["tls_host"], plan["tls_port"] = m.group(1).strip("[]"), int(m.group(2) or 443)
    elif rt["https_enabled"] and rt["https_port"]:
        plan["base_url"] = "https://%s:%d%s" % (h, rt["https_port"], ctx)
        plan["tls_host"], plan["tls_port"] = h.strip("[]"), rt["https_port"]
    elif rt["http_enabled"]:
        plan["base_url"] = "http://%s:%d%s" % (h, rt["http_port"], ctx)
    if rt["http_enabled"] and plan["base_url"].startswith("https"):
        plan["plain_url"] = "http://%s:%d%s/" % (h, rt["http_port"], ctx)
    rt["probe"] = plan
    return rt


def nexus_version(layout, server_header=""):
    """Version from `readlink -f <install>` / nexus-base dir / launcher jar names, else the Server header."""
    for pat in (r"nexus-base/(\d+\.\d+\.\d+-\d+)", r"sonatype-nexus-repository-(\d+\.\d+\.\d+-\d+)\.jar",
                r"nexus-(\d+\.\d+\.\d+-\d+)", r"Nexus/(\d+\.\d+\.\d+-\d+)"):
        m = re.search(pat, "%s\n%s" % (layout or "", server_header or ""))
        if m:
            return m.group(1)
    return ""


def nexus_api_sanitize(data):
    """Remove password-like fields from REST API responses before they are stored."""
    if isinstance(data, dict):
        return dict((k, nexus_api_sanitize(v)) for k, v in data.items() if not re.search(r"password|secret", k, re.I))
    if isinstance(data, list):
        return [nexus_api_sanitize(v) for v in data]
    return data


# ---------------------------------------------------------------------------
# filter: nexus_stig_evaluate
# ---------------------------------------------------------------------------
def _api(ev, key):
    """(available, json) for an authenticated REST API response."""
    r = (ev.get("api") or {}).get(key) or {}
    return r.get("status") == 200, r.get("json")


def nexus_stig_evaluate(ev, settings=None):
    s = settings or {}
    ev = ev or {}
    host = ev.get("system") or {}
    files = ev.get("files") or {}
    rt = ev.get("runtime") or nexus_runtime(files, ev.get("cmdline"), s.get("audit_url", ""))
    props, jvm = rt.get("props") or {}, rt.get("jvm") or {}
    http = ev.get("http") or {}
    stats = sc._parse_stats(ev.get("stats"))
    log_stats = sc._parse_stats(ev.get("log_stats"))
    running = bool(ev.get("running"))
    proc = ev.get("process") or {}
    pid = str(proc.get("pid") or "")
    listeners = sc._listeners(host.get("listeners"))
    nx_listeners = [l for l in listeners if pid and l["pid"] == pid]
    install = (ev.get("install_dir") or "").rstrip("/")
    data = (ev.get("data_dir") or "").rstrip("/")
    svc = ev.get("service_user") or "nexus"
    tls_mode = s.get("tls_termination", "auto")
    R = sc.Results(CHECK_META)

    have_realms, realms = _api(ev, "realms")
    realms = realms or []
    externals = [r for r in realms if r in PKI_REALMS + IDP_REALMS + DIR_REALMS]
    realm_ev = ["active realms: %s" % (", ".join(realms) if have_realms else "not read (no API credentials)")]
    have_users, users = _api(ev, "users")
    local_users = [u for u in users or [] if isinstance(u, dict) and
                   str(u.get("source", "default")).lower() == "default" and
                   str(u.get("status", "")).lower() in ("active", "changepassword")]
    break_glass = sc._names(s.get("break_glass_accounts"))
    api_user = str(s.get("api_user") or "").lower()

    # NXRM-001 ------------------------------------------------------------
    if not have_realms:
        R.add("NXRM-001", NR, NO_API, realm_ev)
    elif not externals:
        R.add("NXRM-001", OPEN, "Only Nexus' local user database is used; no LDAP, SAML or PKI realm is active.", realm_ev)
    elif LOCAL_REALM in realms:
        msg = "Enterprise authentication is active (%s), but the Local Authenticating Realm is also active." % \
            ", ".join(externals)
        if not have_users:
            R.add("NXRM-001", OPEN, msg, realm_ev + ["local users: not read (needs nx-users-read)"],
                  comments="If this is only for a documented break-glass account, list it in "
                           "nexus_stig_break_glass_accounts or record it with nexus_stig_overrides.")
        else:
            def kind(uid):
                u = uid.lower()
                return "break-glass" if u in break_glass else ("audit API account" if u == api_user else "")
            ids = [str(u.get("userId", "?")) for u in local_users]
            realm_ev.append("enabled local users: %s" % (", ".join("%s%s" % (i, " (%s)" % kind(i) if kind(i) else "")
                                                                   for i in ids) or "none"))
            others = [i for i in ids if not kind(i)]
            exempt = [i for i in ids if kind(i) == "break-glass"]
            if others:
                R.add("NXRM-001", OPEN, msg + " Enabled local accounts that are not documented break-glass accounts: "
                      "%s." % ", ".join(others[:20]), realm_ev,
                      comments="List documented break-glass accounts in nexus_stig_break_glass_accounts.")
            else:
                R.add("NXRM-001", NF, "Users authenticate through %s. The Local Authenticating Realm is active, but "
                      "%s." % (", ".join(externals),
                               "the only enabled local accounts are documented break-glass accounts (%s)" %
                               ", ".join(exempt) if exempt else
                               "no local account other than the audit API account is enabled"), realm_ev,
                      comments="Break-glass accounts per nexus_stig_break_glass_accounts. Verify their credentials "
                               "are sealed/vaulted and their use is logged and reviewed.")
    else:
        R.add("NXRM-001", NF, "Users authenticate through %s; the local realm is not active." % ", ".join(externals), realm_ev)

    # NXRM-002 ------------------------------------------------------------
    have_anon, anon = _api(ev, "anonymous")
    issues, ev_lines = [], []
    if have_anon:
        ev_lines.append("anonymous access enabled=%s (user %s)" % ((anon or {}).get("enabled"), (anon or {}).get("userId")))
        if (anon or {}).get("enabled"):
            issues.append("Anonymous access is enabled.")
    rp = http.get("repositories") or {}
    if rp.get("status"):
        ev_lines.append("Unauthenticated GET %s -> HTTP %s" % (rp.get("url"), rp.get("status")))
        if rp.get("status") == 200 and isinstance(rp.get("json"), list) and rp.get("json"):
            issues.append("Unauthenticated users can list repositories, e.g. %s." %
                          ", ".join(str(r.get("name", "?")) for r in rp["json"][:5] if isinstance(r, dict)))
    if issues:
        R.add("NXRM-002", OPEN, issues, ev_lines)
    elif have_anon:
        R.add("NXRM-002", NF, "Anonymous access is disabled.", ev_lines)
    else:
        R.add("NXRM-002", NR, NO_API + " No repositories were visible anonymously.", ev_lines)

    # NXRM-003 ------------------------------------------------------------
    issues, ev_lines, comments = [], [], ""
    rp_flag = props.get("nexus.security.randompassword", jvm.get("nexus.security.randompassword", ""))
    if str(rp_flag).lower() == "false":
        issues.append("nexus.security.randompassword=false: the built-in admin account is created with the "
                      "well-known default password.")
    if have_users:
        admin = [u for u in users or [] if u.get("userId") == "admin" and str(u.get("source", "default")).lower() == "default"]
        for u in admin:
            ev_lines.append("user admin: status=%s roles=%s" % (u.get("status"), ", ".join(u.get("roles") or [])))
            if str(u.get("status", "")).lower() in ("active", "changepassword"):
                if "admin" in break_glass:
                    comments = ("'admin' is enabled as a documented break-glass account "
                                "(nexus_stig_break_glass_accounts). Verify its password is sealed/vaulted and its "
                                "use is logged and reviewed.")
                else:
                    issues.append("The shared built-in 'admin' account is enabled.")
        ev_lines.append("%d users returned by the API" % len(users or []))
    if issues:
        R.add("NXRM-003", OPEN, issues, ev_lines, comments=comments)
    elif have_users:
        R.add("NXRM-003", NF, "The built-in 'admin' account is enabled only as a documented break-glass account."
              if comments else "The built-in 'admin' account is disabled or absent.", ev_lines, comments=comments)
    else:
        R.add("NXRM-003", NR, NO_API, ev_lines)

    # NXRM-004 ------------------------------------------------------------
    pki = [r for r in realms if r in PKI_REALMS]
    idp = [r for r in realms if r in IDP_REALMS]
    if not have_realms:
        R.add("NXRM-004", NR, NO_API, realm_ev)
    elif pki:
        R.add("NXRM-004", NR, "The Remote User Token realm is active. Verify the reverse proxy requires a DoD "
              "PKI client certificate and Nexus is only reachable through the proxy.", realm_ev)
    elif idp:
        R.add("NXRM-004", NR, "SAML is active. Verify the IdP requires CAC/PIV.", realm_ev)
    else:
        R.add("NXRM-004", OPEN, "No PKI/CAC or MFA-capable realm is active; authentication is password-only.", realm_ev)

    # NXRM-005 ------------------------------------------------------------
    have_ldap, ldap = _api(ev, "ldap")
    if not have_ldap:
        R.add("NXRM-005", NR, NO_API)
    elif not ldap:
        R.add("NXRM-005", NA, "No LDAP connections are configured.")
    else:
        issues, ev_lines = [], []
        for c in ldap:
            proto = str(c.get("protocol", "")).lower()
            ev_lines.append("%s: %s://%s:%s useTrustStore=%s" % (c.get("name"), proto, c.get("host"), c.get("port"),
                                                                c.get("useTrustStore")))
            if proto != "ldaps":
                issues.append("LDAP connection '%s' uses unencrypted %s." % (c.get("name"), proto or "ldap"))
        R.verdict("NXRM-005", issues, "All LDAP connections use LDAPS.", ev_lines)

    # NXRM-006 ------------------------------------------------------------
    R.add("NXRM-006", NR, "The session timeout is stored in the 'UI: Settings' capability, which the REST API does "
          "not expose. Verify it is at most %s minutes (Nexus default: 30)." % s.get("max_session_timeout", 15))

    # NXRM-007 ------------------------------------------------------------
    R.add("NXRM-007", OPEN, "Nexus provides no mechanism to limit concurrent sessions per account.",
          comments="Mitigate at the IdP/proxy or document a risk acceptance via nexus_stig_overrides.")

    # NXRM-008 ------------------------------------------------------------
    status, details, ev_lines = sc.eval_banner(http.get("ui"), s.get("banner_regex"), running or bool(s.get("audit_url")))
    R.add("NXRM-008", status, details, ev_lines,
          comments="Nexus renders its UI in the browser; if the banner comes from the Branding capability or a "
                   "proxy splash page, verify it and record the result with nexus_stig_overrides."
          if status == OPEN else "")

    # NXRM-009 ------------------------------------------------------------
    issues, ev_lines = [], ["nexus-args=%s" % rt.get("nexus_args"),
                            "application-host=%s application-port=%s application-port-ssl=%s" %
                            (rt.get("host"), rt.get("http_port"), rt.get("https_port"))]
    ev_lines += ["java listening on %s:%s" % (l["addr"], l["port"]) for l in nx_listeners]
    proxy = [l for l in listeners if l["port"] == 443 and l["pid"] != pid and l["proc"] not in ("", "java")]
    behind_proxy = tls_mode == "proxy" or (tls_mode == "auto" and bool(proxy))
    plain = []
    if rt.get("http_enabled"):
        plain = [l for l in nx_listeners if l["port"] == rt.get("http_port")] or \
                ([] if nx_listeners else [{"addr": rt.get("host"), "port": rt.get("http_port")}])
    exposed = [l for l in plain if not sc._is_loopback(l["addr"])]
    if exposed:
        issues.append("Plaintext HTTP listener exposed on %s." % ", ".join("%s:%s" % (l["addr"], l["port"]) for l in exposed))
    if not rt.get("https_enabled"):
        if plain and not exposed and behind_proxy:
            ev_lines.append("HTTP bound to loopback; TLS terminated by a reverse proxy (%s)." %
                            (", ".join(sc._fmt_listener(l) for l in proxy) or "declared"))
        elif not exposed:
            issues.append("Nexus HTTPS is not enabled and no TLS-terminating reverse proxy was identified.")
    pp = http.get("plain_http") or {}
    if pp.get("status"):
        ev_lines.append("GET %s -> HTTP %s" % (pp.get("url"), pp.get("status")))
    if not files and not nx_listeners:
        R.add("NXRM-009", NR, "Nexus is not running and its configuration could not be read.", ev_lines)
    else:
        R.verdict("NXRM-009", issues, "Nexus is only reachable over HTTPS.", ev_lines)

    # NXRM-010 ------------------------------------------------------------
    plan = rt.get("probe") or {}
    R.add("NXRM-010", *sc.eval_tls(ev.get("tls"), "%s:%s" % (plan.get("tls_host"), plan.get("tls_port"))))

    # NXRM-011 ------------------------------------------------------------
    exe = str(proc.get("exe") or "")
    extra = []
    if exe and install and exe.startswith(install + "/"):
        extra.append("Nexus runs on its bundled JDK (%s), which does not use the RHEL FIPS provider." % exe)
    status, details, ev_lines = sc.eval_fips(host, jvm, extra)
    R.add("NXRM-011", status, details, ev_lines + ["java: %s" % (exe or "?")])

    # NXRM-012 ------------------------------------------------------------
    status, details, ev_lines = sc.eval_accounts(host, [svc])
    issues = list(details) if status == OPEN else []
    user = proc.get("user") or ""
    rc_user = sc._parse_env(files.get("nexus.rc")).get("run_as_user", "")
    ev_lines = ["process user=%s" % (user or "?"), "nexus.rc run_as_user=%s" % (rc_user or "(unset)")] + ev_lines
    if user in ("root", "0"):
        issues.append("Nexus is running as root.")
    if issues:
        R.add("NXRM-012", OPEN, issues, ev_lines)
    else:
        R.add("NXRM-012", status, details, ev_lines)

    # NXRM-013 ------------------------------------------------------------
    issues, ev_lines = [], []
    rules = [(data, 0o007), (data + "/etc/nexus.properties", 0o027),
             (data + "/etc/fabric/nexus-store.properties", 0o077), (data + "/keystores", 0o077),
             (data + "/keystores/node", 0o077), (data + "/etc/ssl/keystore.jks", 0o077)] if data else []
    rules += [(install + "/etc/ssl/keystore.jks", 0o077)] if install else []
    for path, mask in rules:
        st_ = stats.get(path)
        if not st_:
            continue
        ev_lines.append(sc._fmt_stat(st_))
        m = sc._mode(st_)
        if m is not None and m & mask:
            issues.append("%s mode %s is too permissive (must not include %04o)." % (path, st_["mode"], mask))
    dst = stats.get(data) if data else None
    if dst and dst.get("owner") not in (svc, "root"):
        issues.append("The data directory is owned by %s, not the service account." % dst.get("owner"))
    if data and stats.get(data + "/admin.password"):
        issues.append("%s/admin.password (the initial admin password) still exists." % data)
    ww = sc._lines(ev.get("world_writable"))
    if ww:
        issues.append("%d world-writable file(s) under Nexus directories, e.g. %s" % (len(ww), ", ".join(ww[:5])))
    if not dst:
        R.add("NXRM-013", NR, "Could not stat the Nexus data directory (%s)." % (data or "not found"), ev_lines)
    else:
        R.verdict("NXRM-013", issues, "Nexus configuration, credentials and keys are restricted.", ev_lines)

    # NXRM-014 ------------------------------------------------------------
    issues, ev_lines = [], []
    for path in (install, install + "/bin", install + "/lib", install + "/system", install + "/etc"):
        st_ = stats.get(path) if install else None
        if not st_:
            continue
        ev_lines.append(sc._fmt_stat(st_))
        m = sc._mode(st_)
        if st_.get("owner") == svc:
            issues.append("%s is owned by the service account %s." % (path, svc))
        if m is not None and m & 0o022:
            issues.append("%s is group/world writable (mode %s)." % (path, st_["mode"]))
    issues += sc.rpm_verify_issues(ev.get("rpm_verify"), ev_lines)
    if not ev_lines:
        R.add("NXRM-014", NR, "The Nexus installation directory was not found; verify binary protections manually.")
    else:
        R.verdict("NXRM-014", issues, "Nexus binaries are not writable by the service account.", ev_lines)

    # NXRM-015 ------------------------------------------------------------
    R.add("NXRM-015", *sc.eval_ports(host, nx_listeners, s.get("approved_ports"), "Nexus"))

    # NXRM-016 ------------------------------------------------------------
    issues, ev_lines = [], ["nexus.scripts.allowCreation=%s" % props.get("nexus.scripts.allowCreation", "(unset)")]
    if sc._truthy(props.get("nexus.scripts.allowCreation", jvm.get("nexus.scripts.allowCreation", ""))):
        issues.append("The Groovy script API is enabled (nexus.scripts.allowCreation=true).")
    have_repos, repos = _api(ev, "repositories")
    if have_repos:
        ev_lines.append("%d repositories:" % len(repos or []))
        ev_lines += ["  %s (%s %s)" % (r.get("name"), r.get("format"), r.get("type")) for r in repos or []]
    if issues:
        R.add("NXRM-016", OPEN, issues, ev_lines)
    else:
        R.add("NXRM-016", NR, "Scripting is disabled. Review the repositories and formats for mission need.", ev_lines)

    # NXRM-017 ------------------------------------------------------------
    version = ev.get("version") or ""
    status, details, ev_lines = sc.eval_updates(version, s.get("min_version"), host.get("repo_updates"), "Nexus")
    jmaj = sc._java_major(proc.get("java_version", ""))
    min_java = sc._int(s.get("min_java_major"), 17)
    ev_lines.append("Java: %s" % (" ".join(sc._lines(proc.get("java_version", ""))[:1]) or "unknown"))
    if jmaj is not None and jmaj < min_java:
        issues = (list(details) if status == OPEN else []) + \
            ["Nexus runs on Java %d; Java %d+ is required." % (jmaj, min_java)]
        R.add("NXRM-017", OPEN, issues, ev_lines)
    else:
        R.add("NXRM-017", status, details, ev_lines)

    # NXRM-018 ------------------------------------------------------------
    servers = sorted(set(str(r.get("server")) for r in http.values() if isinstance(r, dict) and r.get("server")))
    if not servers and not any(isinstance(r, dict) and r.get("status", -1) > 0 for r in http.values()):
        R.add("NXRM-018", NR, "Nexus HTTP endpoints could not be probed.")
    else:
        bad = [v for v in servers if re.search(r"\d", v)]
        R.verdict("NXRM-018", ["The Server header discloses version information (%s)." % v for v in bad],
                  "No version information is disclosed in response headers.",
                  ["Server: %s" % v for v in servers] or ["No Server header returned."])

    # NXRM-019 ------------------------------------------------------------
    audit = log_stats.get(data + "/log/audit/audit.log") if data else None
    if audit and (audit.get("size") or 0) > 0:
        R.add("NXRM-019", NF, "The Audit capability is recording events.", sc._fmt_stat(audit),
              comments="Verify the audit log covers the organization's auditable events.")
    else:
        R.add("NXRM-019", OPEN, "No audit log (%s/log/audit/audit.log) is being written; the Audit capability is "
              "not enabled." % (data or "<data>"), sc._fmt_stat(audit) if audit else "")

    # NXRM-020 ------------------------------------------------------------
    req = log_stats.get(data + "/log/request.log") if data else None
    if (rt.get("request_log") and files) or req:
        R.add("NXRM-020", NF, "HTTP request logging is enabled.",
              ["nexus-args includes jetty-requestlog.xml: %s" % rt.get("request_log")] + ([sc._fmt_stat(req)] if req else []))
    elif behind_proxy:
        R.add("NXRM-020", NR, "Nexus request logging is off, but a reverse proxy fronts Nexus; verify the proxy's "
              "access log records source, time, request and outcome.")
    else:
        R.add("NXRM-020", OPEN, "HTTP request logging is not enabled (jetty-requestlog.xml is not in nexus-args).")

    # NXRM-021 .. NXRM-024 ------------------------------------------------
    R.add("NXRM-021", *sc.eval_log_perms(ev.get("log_stats"), ["root", svc]))
    R.add("NXRM-022", *sc.eval_offload(host, [data + "/log"] if data else []))
    R.add("NXRM-023", *sc.eval_storage(host))
    R.add("NXRM-024", *sc.eval_time(host))

    return sc.apply_overrides(R.items, s.get("overrides"))


class FilterModule(object):
    def filters(self):
        return {
            "nexus_runtime": nexus_runtime,
            "nexus_version": nexus_version,
            "nexus_api_sanitize": nexus_api_sanitize,
            "nexus_stig_evaluate": nexus_stig_evaluate,
        }
