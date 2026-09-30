# -*- coding: utf-8 -*-
"""
Controller-side evaluation logic for the jenkins_stig_audit role.

The role's tasks only *collect* evidence from the target (read-only).  Every
pass/fail decision is made here, in plain Python, so the logic can be unit
tested without Ansible (see tests/test_jenkins_stig.py).

Filters exported:
  jenkins_runtime        - parse the Jenkins java command line / env files
  jenkins_audit_log_dirs - directories that hold Jenkins audit/access logs
  jenkins_stig_evaluate  - evidence dict -> list of check results
  stig_xccdf_rules       - parse a DISA SRG/STIG XCCDF (.xml or .zip)
  stig_ckl               - render a STIG Viewer .ckl checklist
  stig_csv               - render results as CSV
  stig_summary           - status / severity counts
"""
from __future__ import absolute_import, division, print_function

import csv
import io
import json
import os
import re
import time
import uuid
import xml.etree.ElementTree as ET
import zipfile
from xml.sax.saxutils import escape as _xml_escape

NF = "NotAFinding"
OPEN = "Open"
NA = "Not_Applicable"
NR = "Not_Reviewed"

STATUS_ORDER = [OPEN, NR, NF, NA]
SEV_CAT = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}

# ---------------------------------------------------------------------------
# Check catalog.  srg_ids are *base* SRG requirement IDs (SRG-APP-nnnnnn).
# They are matched against the Application Server SRG XCCDF you supply so that
# the Vuln IDs / Rule IDs / titles in the checklist always come from DISA's
# published content, never from this file.
# ---------------------------------------------------------------------------
CHECKS = [
    ("JNKS-001", "Jenkins must require authentication (a security realm is configured)",
     ["SRG-APP-000148", "SRG-APP-000033"], "high",
     "Manage Jenkins > Security: enable security and select an enterprise security realm "
     "(SAML/OIDC to the DoD IdP, or LDAP/AD). Never use 'None'."),
    ("JNKS-002", "Jenkins authorization must enforce least privilege and deny anonymous access",
     ["SRG-APP-000033", "SRG-APP-000340"], "high",
     "Use Matrix-based or Role-based authorization. Grant no permissions to 'anonymous', do not "
     "grant Overall/Administer to 'authenticated', and restrict Administer to named admins/groups. "
     "Do not use 'Anyone can do anything', 'Legacy mode', or 'Logged-in users can do anything'."),
    ("JNKS-003", "Jenkins local user self-registration must be disabled",
     ["SRG-APP-000033"], "medium",
     "Manage Jenkins > Security > Security Realm: uncheck 'Allow users to sign up'."),
    ("JNKS-004", "Jenkins must use DoD PKI (CAC/PIV) or MFA for user authentication",
     ["SRG-APP-000149", "SRG-APP-000391", "SRG-APP-000392"], "medium",
     "Federate authentication to an IdP that enforces CAC/PIV (SAML or OIDC plugin), or "
     "front Jenkins with a proxy that requires client certificates and passes identity "
     "via the reverse-proxy-auth plugin."),
    ("JNKS-005", "Account lockout and password complexity must be enforced",
     ["SRG-APP-000065", "SRG-APP-000164"], "medium",
     "Jenkins' own user database cannot enforce lockout, complexity or aging. Delegate "
     "authentication to the enterprise directory/IdP that enforces DoD policy."),
    ("JNKS-006", "Directory (LDAP/AD) authentication traffic must be encrypted and certificates validated",
     ["SRG-APP-000172", "SRG-APP-000439"], "medium",
     "Use ldaps:// server URLs (LDAP plugin) or StartTLS with JDK trust store validation "
     "(Active Directory plugin). Never use TRUST_ALL_CERTIFICATES."),
    ("JNKS-007", "Jenkins 'Remember me' persistent login must be disabled",
     ["SRG-APP-000400"], "medium",
     "Manage Jenkins > Security: check 'Disable remember me'."),
    ("JNKS-008", "Jenkins HTTP sessions must time out after the organization-defined inactivity period",
     ["SRG-APP-000295"], "medium",
     "Add --sessionTimeout=<minutes> to JENKINS_OPTS (systemd override) or JENKINS_ARGS "
     "(/etc/sysconfig/jenkins) and restart Jenkins."),
    ("JNKS-009", "Jenkins must limit concurrent sessions per account",
     ["SRG-APP-000001"], "low",
     "Jenkins has no native concurrent-session limit. Enforce at the IdP/reverse proxy or "
     "document the risk acceptance (use jenkins_stig_overrides to record it)."),
    ("JNKS-010", "The DoD Notice and Consent Banner must be displayed before login",
     ["SRG-APP-000068"], "medium",
     "Display the Standard Mandatory DoD Notice and Consent Banner on the login page (e.g. "
     "the Login Theme plugin, the IdP login page, or the reverse proxy) with explicit acknowledgment."),
    ("JNKS-011", "Jenkins must only be reachable over HTTPS (no plaintext HTTP listeners)",
     ["SRG-APP-000014", "SRG-APP-000015", "SRG-APP-000439", "SRG-APP-000172"], "high",
     "Enable HTTPS (JENKINS_HTTPS_PORT/--httpsPort with a DoD-issued certificate) and set "
     "--httpPort=-1, or bind HTTP to 127.0.0.1 behind a TLS-terminating reverse proxy. Set the "
     "Jenkins URL to https://."),
    ("JNKS-012", "Jenkins TLS endpoints must not accept SSL or TLS 1.0/1.1",
     ["SRG-APP-000014", "SRG-APP-000439"], "medium",
     "Restrict protocols to TLS 1.2+ (RHEL crypto-policy DEFAULT/FIPS, or the proxy's "
     "ssl_protocols/SSLProtocol directive)."),
    ("JNKS-013", "FIPS 140-validated cryptography must be used",
     ["SRG-APP-000179", "SRG-APP-000514"], "high",
     "Run 'fips-mode-setup --enable' and reboot; do not pass -Dcom.redhat.fips=false or "
     "-Djava.security.disableSystemPropertiesFile=true to the JVM."),
    ("JNKS-014", "Jenkins must run under a non-privileged, non-interactive service account",
     ["SRG-APP-000342"], "medium",
     "Run Jenkins as the 'jenkins' user (systemd User=jenkins) with shell /sbin/nologin, no sudo "
     "rights and no membership in wheel/docker/root groups."),
    ("JNKS-015", "JENKINS_HOME configuration and secrets must be protected from unauthorized access",
     ["SRG-APP-000380", "SRG-APP-000171"], "medium",
     "chmod 750 $JENKINS_HOME; chmod 700 $JENKINS_HOME/secrets; chmod 600 secrets/*; remove "
     "world-writable files; delete secrets/initialAdminPassword after setup."),
    ("JNKS-016", "Jenkins application binaries must be protected from modification",
     ["SRG-APP-000133"], "medium",
     "Keep jenkins.war owned by root and not writable by the jenkins account; reinstall the RPM "
     "if 'rpm -V jenkins' reports digest changes."),
    ("JNKS-017", "Builds must not run on the Jenkins controller (management/user function separation)",
     ["SRG-APP-000211"], "medium",
     "Manage Jenkins > Nodes > Built-In Node: set '# of executors' to 0 and run builds on agents. "
     "Remove secrets/slave-to-master-security-kill-switch if present."),
    ("JNKS-018", "Jenkins must only use approved (PPSM) ports and protocols",
     ["SRG-APP-000142"], "medium",
     "Set the inbound agent TCP port to a fixed registered port or disable it; disable the SSH "
     "server unless required; keep firewalld active; declare jenkins_stig_approved_ports."),
    ("JNKS-019", "Unnecessary, deprecated or unapproved plugins must be removed",
     ["SRG-APP-000141"], "medium",
     "Uninstall plugins that are not mission-required, deprecated, or disabled; maintain an "
     "approved plugin baseline (jenkins_stig_approved_plugins)."),
    ("JNKS-020", "Security-relevant updates for Jenkins core, plugins and Java must be installed",
     ["SRG-APP-000456"], "medium",
     "Update Jenkins core/plugins listed in the security advisories and run Jenkins on a "
     "supported Java release (17 or 21)."),
    ("JNKS-021", "Jenkins security protections must not be disabled via system properties or legacy settings",
     ["SRG-APP-000516"], "medium",
     "Remove the listed -D system properties from JAVA_OPTS/JENKINS_JAVA_OPTIONS, keep CSRF "
     "protection enabled, and disable legacy API token generation."),
    ("JNKS-022", "Jenkins must sanitize user-supplied markup and keep its Content-Security-Policy",
     ["SRG-APP-000251"], "medium",
     "Use 'Plain text' or 'Safe HTML' markup formatter; remove -Dhudson.model.DirectoryBrowserSupport.CSP overrides."),
    ("JNKS-023", "Jenkins must not reveal stack traces or version details to users",
     ["SRG-APP-000266", "SRG-APP-000267"], "low",
     "Remove stack-trace/diagnostic system properties; strip X-Jenkins, X-Hudson, X-Jenkins-Session "
     "and Server headers at the reverse proxy."),
    ("JNKS-024", "Jenkins must generate audit records for security-relevant events",
     ["SRG-APP-000089", "SRG-APP-000095", "SRG-APP-000096", "SRG-APP-000097",
      "SRG-APP-000098", "SRG-APP-000099", "SRG-APP-000100"], "medium",
     "Install the Audit Trail plugin and configure at least one logger (log file or syslog)."),
    ("JNKS-025", "Jenkins must log remote (HTTP) access",
     ["SRG-APP-000016"], "low",
     "Enable the Winstone access log (--accessLoggerClassName=winstone.accesslog.SimpleAccessLogger "
     "--simpleAccessLogger.file=/var/log/jenkins/access_log) or log at the reverse proxy."),
    ("JNKS-026", "Jenkins log files must be protected from unauthorized read, modification and deletion",
     ["SRG-APP-000118", "SRG-APP-000119", "SRG-APP-000120"], "medium",
     "chmod 0750 on log directories and 0640 (or stricter) on log files; owner jenkins or root."),
    ("JNKS-027", "Jenkins audit records must be off-loaded to a centralized log server",
     ["SRG-APP-000358"], "low",
     "Forward audit logs with rsyslog (imfile + omfwd/@@) or the Audit Trail syslog/Elastic logger."),
    ("JNKS-028", "Audit storage capacity must be allocated and monitored",
     ["SRG-APP-000357", "SRG-APP-000359"], "low",
     "Place logs on a dedicated filesystem sized for retention and alert the SA/ISSO at 75% usage."),
    ("JNKS-029", "Audit time stamps must come from a synchronized, authoritative time source",
     ["SRG-APP-000116", "SRG-APP-000374"], "medium",
     "Enable chronyd and synchronize to a DoD-approved time source."),
]
CHECK_META = dict((c[0], {"id": c[0], "title": c[1], "srg_ids": c[2], "severity": c[3], "fix": c[4]})
                  for c in CHECKS)

LOOPBACK = ("127.", "::1", "localhost", "[::1]", "::ffff:127.")
NOLOGIN_SHELLS = ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false")
PRIV_GROUPS = ("root", "wheel", "docker", "adm", "disk")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _xml(text):
    if not text:
        return None
    text = text.lstrip("﻿").lstrip()
    text = re.sub(r"^<\?xml[^>]*\?>", "", text)  # tolerate XML 1.1 declarations
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        return None


def _text(root, path, default=None):
    if root is None:
        return default
    el = root.find(path)
    if el is None or el.text is None:
        return default
    return el.text.strip()


def _truthy(val):
    return str(val).strip().lower() in ("true", "yes", "1", "on")


def _int(val, default=None):
    try:
        return int(str(val).strip())
    except (TypeError, ValueError):
        return default


def _is_loopback(addr):
    return bool(addr) and addr.startswith(LOOPBACK)


def _lines(val):
    if val is None:
        return []
    if isinstance(val, (list, tuple)):
        return [str(v) for v in val if str(v).strip()]
    return [l for l in str(val).splitlines() if l.strip()]


def _version_tuple(v):
    parts = re.findall(r"\d+", str(v or ""))
    return tuple(int(p) for p in parts)


def _mode(stat):
    try:
        return int(str(stat.get("mode", "")), 8)
    except ValueError:
        return None


def _fmt_stat(s):
    return "%s %s:%s %s" % (s.get("mode"), s.get("owner"), s.get("group"), s.get("path"))


def _parse_stats(lines):
    """Lines produced by: find ... -printf '%p|%u|%g|%m|%y|%T@|%s\\n'"""
    out = {}
    for line in _lines(lines):
        parts = line.split("|")
        if len(parts) < 5:
            continue
        mtime = None
        if len(parts) > 5:
            try:
                mtime = float(parts[5])
            except ValueError:
                mtime = None
        out[parts[0].rstrip("/") or "/"] = {
            "path": parts[0], "owner": parts[1], "group": parts[2],
            "mode": parts[3].zfill(4), "type": parts[4], "mtime": mtime,
        }
    return out


def _parse_env(text):
    """Parse sysconfig (KEY="v") and systemd (Environment="K=v" "K2=v2") syntax."""
    env = {}
    for raw in _lines(text):
        line = raw.strip()
        if line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("Environment="):
            body = line[len("Environment="):]
            for tok in re.findall(r'"([^"]*)"|(\S+)', body):
                item = tok[0] or tok[1]
                if "=" in item:
                    k, v = item.split("=", 1)
                    env[k.strip()] = v.strip().strip("'\"")
            continue
        m = re.match(r'^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line)
        if m:
            env[m.group(1)] = m.group(2).strip().strip("'\"")
    return env


def _args_from_env(env_text):
    env = _parse_env(env_text)
    if not env:
        return []
    args = []
    for opt_var in ("JAVA_OPTS", "JENKINS_JAVA_OPTIONS"):
        args += env.get(opt_var, "").split()
    mapping = [("JENKINS_PORT", "--httpPort"), ("JENKINS_HTTPS_PORT", "--httpsPort"),
               ("JENKINS_HTTP2_PORT", "--http2Port"),
               ("JENKINS_LISTEN_ADDRESS", "--httpListenAddress"),
               ("JENKINS_HTTPS_LISTEN_ADDRESS", "--httpsListenAddress"),
               ("JENKINS_PREFIX", "--prefix"), ("JENKINS_HTTPS_KEYSTORE", "--httpsKeyStore")]
    for var, flag in mapping:
        if env.get(var):
            args.append("%s=%s" % (flag, env[var]))
    if _truthy(env.get("JENKINS_ENABLE_ACCESS_LOG", "")):
        args.append("--accessLoggerClassName=winstone.accesslog.SimpleAccessLogger")
    for opt_var in ("JENKINS_ARGS", "JENKINS_OPTS"):
        args += env.get(opt_var, "").split()
    return args


# ---------------------------------------------------------------------------
# filter: jenkins_runtime
# ---------------------------------------------------------------------------
def jenkins_runtime(cmdline, env_text="", audit_url=""):
    """Effective Jenkins listener/session settings plus the URLs to probe."""
    args = [a for a in _lines(cmdline)]
    source = "process"
    if not args:
        args = _args_from_env(env_text)
        source = "config" if args else "defaults"
    rt = {"source": source, "http_port": 8080, "https_port": -1, "http2_port": -1,
          "http_listen": "", "https_listen": "", "prefix": "", "session_timeout": None,
          "session_eviction": None, "access_logger": "", "access_log_file": "",
          "properties": {}, "war": "", "keystore": "", "args": args, "env": _parse_env(env_text)}
    for i, a in enumerate(args):
        if a.startswith("-D"):
            k, _, v = a[2:].partition("=")
            rt["properties"][k] = v
        elif a == "-jar" and i + 1 < len(args):
            rt["war"] = args[i + 1]
        elif a.startswith("--"):
            k, _, v = a[2:].partition("=")
            if k == "httpPort":
                rt["http_port"] = _int(v, 8080)
            elif k == "httpsPort":
                rt["https_port"] = _int(v, -1)
            elif k == "http2Port":
                rt["http2_port"] = _int(v, -1)
            elif k == "httpListenAddress":
                rt["http_listen"] = v
            elif k == "httpsListenAddress":
                rt["https_listen"] = v
            elif k == "prefix":
                rt["prefix"] = "/" + v.strip("/") if v.strip("/") else ""
            elif k == "sessionTimeout":
                rt["session_timeout"] = _int(v)
            elif k == "sessionEviction":
                rt["session_eviction"] = _int(v)
            elif k == "accessLoggerClassName":
                rt["access_logger"] = v
            elif k == "simpleAccessLogger.file":
                rt["access_log_file"] = v
            elif k == "httpsKeyStore":
                rt["keystore"] = v

    def host(addr):
        if not addr or addr in ("0.0.0.0", "::", "*"):
            return "127.0.0.1"
        return "[%s]" % addr if ":" in addr and not addr.startswith("[") else addr

    plan = {"base_url": "", "tls_host": "", "tls_port": 0, "plain_url": ""}
    if audit_url:
        base = audit_url.rstrip("/")
        plan["base_url"] = base
        m = re.match(r"^https://([^/:]+|\[[^\]]+\])(?::(\d+))?", base)
        if m:
            plan["tls_host"] = m.group(1).strip("[]")
            plan["tls_port"] = int(m.group(2) or 443)
    elif rt["https_port"] and rt["https_port"] > 0:
        h = host(rt["https_listen"])
        plan["base_url"] = "https://%s:%d%s" % (h, rt["https_port"], rt["prefix"])
        plan["tls_host"] = h.strip("[]")
        plan["tls_port"] = rt["https_port"]
    elif rt["http_port"] and rt["http_port"] > 0:
        plan["base_url"] = "http://%s:%d%s" % (host(rt["http_listen"]), rt["http_port"], rt["prefix"])
    if rt["http_port"] and rt["http_port"] > 0 and plan["base_url"].startswith("https"):
        plan["plain_url"] = "http://%s:%d%s/login" % (host(rt["http_listen"]), rt["http_port"], rt["prefix"])
    rt["probe"] = plan
    return rt


# ---------------------------------------------------------------------------
# filter: jenkins_audit_log_dirs
# ---------------------------------------------------------------------------
def _audit_trail_cfg(files):
    files = files or {}
    for name in ("audit-trail.xml", "hudson.plugins.audit_trail.AuditTrailPlugin.xml"):
        root = _xml(files.get(name))
        if root is not None:
            return name, root
    return None, None


def _audit_loggers(root):
    loggers = []
    if root is None:
        return loggers
    container = root.find("loggers")
    if container is None:
        return loggers
    for el in list(container):
        tag = el.tag.replace("__", "_")
        kind = "other"
        for k in ("LogFile", "Syslog", "Console", "ElasticSearch"):
            if k in tag:
                kind = k.lower()
        loggers.append({
            "kind": kind, "class": el.tag,
            "log": _text(el, "log", ""),
            "syslog_host": _text(el, "syslogServerHostname", ""),
            "syslog_port": _text(el, "syslogServerPort", ""),
            "es_url": _text(el, "esServerUrl", "") or _text(el, "url", ""),
        })
    return loggers


def jenkins_audit_log_dirs(files, home="/var/lib/jenkins", runtime=None):
    dirs = set(["/var/log/jenkins"])
    _, root = _audit_trail_cfg(files)
    for lg in _audit_loggers(root):
        if lg["kind"] == "logfile" and lg["log"]:
            p = lg["log"]
            if not p.startswith("/"):
                p = os.path.join(home, p)
            dirs.add(os.path.dirname(p) or "/")
    if runtime and runtime.get("access_log_file"):
        p = runtime["access_log_file"]
        if not p.startswith("/"):
            p = os.path.join(home, p)
        dirs.add(os.path.dirname(p))
    return sorted(dirs)


# ---------------------------------------------------------------------------
# authentication / authorization analysis
# ---------------------------------------------------------------------------
def _realm(cfg):
    el = cfg.find("securityRealm") if cfg is not None else None
    cls = el.get("class", "") if el is not None else ""
    low = cls.lower()
    if not cls or cls.endswith("SecurityRealm$None"):
        kind = "none"
    elif "hudsonprivatesecurityrealm" in low:
        kind = "local"
    elif "active_directory" in low or "activedirectory" in low:
        kind = "ad"
    elif "ldap" in low:
        kind = "ldap"
    elif "pamsecurityrealm" in low:
        kind = "unix"
    elif "reverse_proxy_auth" in low or "reverseproxy" in low:
        kind = "proxy"
    elif any(k in low for k in ("saml", ".oic.", "oidc", "azure", "keycloak", "github", "google", "openid")):
        kind = "federated"
    else:
        kind = "other"
    return kind, cls, el


def _grants(strategy_el):
    """Return list of (sid, permission) from matrix or role-strategy config."""
    grants = []
    if strategy_el is None:
        return grants
    cls = strategy_el.get("class", "")
    if "rolestrategy" in cls.lower():
        for rm in strategy_el.iter("roleMap"):
            if rm.get("type") not in (None, "globalRoles"):
                continue
            for role in rm.iter("role"):
                perms = [p.text.strip() for p in role.iter("permission") if p.text]
                sids = [s.text.strip() for s in role.iter("sid") if s.text]
                for sid in sids:
                    for p in perms:
                        grants.append((sid, p))
        return grants
    for p in strategy_el.iter("permission"):
        if not p.text:
            continue
        parts = p.text.strip().split(":")
        if parts[0] in ("USER", "GROUP", "EITHER"):
            parts = parts[1:]
        if len(parts) >= 2:
            grants.append((":".join(parts[1:]), parts[0]))
    return grants


def _authz(cfg):
    el = cfg.find("authorizationStrategy") if cfg is not None else None
    cls = el.get("class", "") if el is not None else ""
    issues, notes = [], []
    if not cls or cls.endswith("AuthorizationStrategy$Unsecured"):
        issues.append("Authorization strategy is 'Anyone can do anything' (%s)." % (cls or "not set"))
    elif cls.endswith("LegacyAuthorizationStrategy"):
        issues.append("Authorization strategy is 'Legacy mode'.")
    elif cls.endswith("FullControlOnceLoggedInAuthorizationStrategy"):
        issues.append("Authorization strategy 'Logged-in users can do anything' makes every "
                      "authenticated user an administrator.")
        if not _truthy(_text(el, "denyAnonymousReadAccess", "false")):
            issues.append("Anonymous read access is allowed (denyAnonymousReadAccess=false).")
    elif "matrix" in cls.lower() or "rolestrategy" in cls.lower():
        grants = _grants(el)
        anon = sorted(set(p for s, p in grants if s == "anonymous"))
        auth_admin = [p for s, p in grants if s == "authenticated" and p.endswith("Hudson.Administer")]
        admins = sorted(set(s for s, p in grants if p.endswith("Hudson.Administer")))
        if anon:
            issues.append("'anonymous' is granted permissions: %s" % ", ".join(anon))
        if auth_admin:
            issues.append("'authenticated' (every logged-in user) is granted Overall/Administer.")
        notes.append("Overall/Administer granted to: %s" % (", ".join(admins) or "nobody"))
        notes.append("%d permission grants analysed." % len(grants))
    else:
        notes.append("Unrecognized authorization strategy %s - review manually." % cls)
        return cls, issues, notes, False
    return cls, issues, notes, True


# ---------------------------------------------------------------------------
# listeners / probes
# ---------------------------------------------------------------------------
def _listeners(ss_text):
    """Parse `ss -Htlnp` output into [{addr, port, proc, pid}]."""
    out = []
    for line in _lines(ss_text):
        cols = line.split()
        if len(cols) < 4:
            continue
        local = cols[3] if cols[0] in ("LISTEN", "UNCONN") else cols[2] if len(cols) > 2 else ""
        m = re.match(r"^(.*):(\d+)$", local)
        if not m:
            continue
        addr = m.group(1).strip("[]")
        addr = addr.split("%")[0]
        pm = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        out.append({"addr": addr, "port": int(m.group(2)),
                    "proc": pm.group(1) if pm else "", "pid": pm.group(2) if pm else ""})
    return out


def _tls_ok(probe):
    if not probe:
        return None
    if isinstance(probe, dict):
        out = (probe.get("stdout") or "") + (probe.get("stderr") or "")
    else:
        out = str(probe)
    return bool(re.search(r"New, (TLSv[\d.]+|SSLv3), Cipher is (?!\(NONE\))", out))


def _header(resp, name):
    if not resp:
        return None
    for key in (name.lower(), name.lower().replace("-", "_")):
        if key in resp:
            return resp[key]
    return None


def _strip_html(body):
    body = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", body or "")
    body = re.sub(r"(?s)<[^>]+>", " ", body)
    body = body.replace("&nbsp;", " ").replace("&amp;", "&")
    return re.sub(r"\s+", " ", body)


# ---------------------------------------------------------------------------
# update center
# ---------------------------------------------------------------------------
def _load_update_center(text):
    if not text:
        return None
    # Ansible templating turns a JSON-looking string into a dict before it gets here.
    if isinstance(text, dict):
        return text
    t = str(text).strip()
    if t.startswith("updateCenter.post("):
        t = t[len("updateCenter.post("):]
        t = t.rstrip().rstrip(";").rstrip()
        if t.endswith(")"):
            t = t[:-1]
    try:
        return json.loads(t)
    except ValueError:
        return None


def _warning_hits(uc, core_version, plugins):
    hits = []
    if not uc:
        return hits
    installed = dict((p["name"], p["version"]) for p in plugins)
    for w in uc.get("warnings", []) or []:
        wtype, wid = w.get("type"), w.get("id")
        if wtype == "core":
            ver = core_version
        elif wtype == "plugin":
            ver = installed.get(wid)
        else:
            continue
        if not ver:
            continue
        for rng in w.get("versions", []) or []:
            pat = rng.get("pattern")
            try:
                if pat and re.match(r"(?:%s)\Z" % pat, ver):
                    hits.append("%s %s: %s (%s)" % ("core" if wtype == "core" else wid, ver,
                                                     w.get("name") or w.get("message", ""),
                                                     w.get("url", "")))
                    break
            except re.error:
                continue
    return hits


def _java_major(text):
    m = re.search(r'version "([^"]+)"', text or "")
    if not m:
        return None
    v = m.group(1)
    if v.startswith("1."):
        return _int(v.split(".")[1])
    return _int(re.split(r"[.\-+]", v)[0])


# ---------------------------------------------------------------------------
# filter: jenkins_stig_evaluate
# ---------------------------------------------------------------------------
def jenkins_stig_evaluate(ev, settings=None):
    s = settings or {}
    ev = ev or {}
    files = ev.get("files") or {}
    cfg = _xml(files.get("config.xml"))
    home = (ev.get("home") or "/var/lib/jenkins").rstrip("/")
    running = bool(ev.get("running"))
    rt = ev.get("runtime") or jenkins_runtime([], ev.get("env_text", ""))
    props = rt.get("properties", {})
    stats = _parse_stats(ev.get("stats"))
    plugins = []
    for line in _lines(ev.get("plugins")):
        parts = line.split("|")
        if len(parts) >= 3:
            plugins.append({"name": parts[0], "version": parts[1], "disabled": _truthy(parts[2])})
    plugin_map = dict((p["name"], p) for p in plugins)
    listeners = _listeners(ev.get("listeners"))
    jpid = str((ev.get("process") or {}).get("pid") or "")
    jlisteners = [l for l in listeners if (jpid and l["pid"] == jpid) or (not jpid and l["proc"] == "java")]
    http = ev.get("http") or {}
    tls = ev.get("tls") or {}
    realm_kind, realm_cls, realm_el = _realm(cfg)
    tls_mode = s.get("tls_termination", "auto")
    results = []

    def add(cid, status, details, evidence=None, comments=""):
        meta = dict(CHECK_META[cid])
        if isinstance(details, (list, tuple)):
            details = "\n".join(details)
        if isinstance(evidence, (list, tuple)):
            evidence = "\n".join(str(e) for e in evidence)
        meta.update({"status": status, "finding_details": details or "",
                     "evidence": evidence or "", "comments": comments or "",
                     "cat": SEV_CAT.get(meta["severity"], "")})
        results.append(meta)

    cfg_missing = "config.xml could not be read from %s; run the audit with become: true." % home

    # JNKS-001 ------------------------------------------------------------
    if cfg is None:
        add("JNKS-001", NR, cfg_missing)
    else:
        use_sec = _text(cfg, "useSecurity", "true")
        if not _truthy(use_sec) or realm_kind == "none":
            add("JNKS-001", OPEN, "Jenkins security is disabled or no security realm is configured "
                "(useSecurity=%s, securityRealm=%s)." % (use_sec, realm_cls or "none"),
                "config.xml securityRealm class=%s" % realm_cls)
        else:
            add("JNKS-001", NF, "Authentication is required via security realm %s (%s)." % (realm_kind, realm_cls),
                "config.xml securityRealm class=%s" % realm_cls)

    # JNKS-002 ------------------------------------------------------------
    anon = http.get("anon_api") or {}
    if cfg is None:
        add("JNKS-002", NR, cfg_missing)
    else:
        cls, issues, notes, known = _authz(cfg)
        ev_lines = ["config.xml authorizationStrategy class=%s" % cls] + notes
        if anon.get("status"):
            ev_lines.append("Unauthenticated GET %s -> HTTP %s" % (anon.get("url", "/api/json"), anon.get("status")))
            if anon.get("status") == 200:
                issues.append("Unauthenticated request to the remote API succeeded (HTTP 200).")
        if issues:
            add("JNKS-002", OPEN, issues, ev_lines)
        elif not known:
            add("JNKS-002", NR, "Authorization strategy not recognized; review permissions manually.", ev_lines)
        else:
            add("JNKS-002", NF, "No anonymous permissions and Administer is restricted.", ev_lines)

    # JNKS-003 ------------------------------------------------------------
    if cfg is None:
        add("JNKS-003", NR, cfg_missing)
    elif realm_kind != "local":
        add("JNKS-003", NA, "Jenkins' own user database is not in use (realm: %s)." % realm_kind)
    elif _truthy(_text(realm_el, "disableSignup", "false")):
        add("JNKS-003", NF, "Self sign-up is disabled (disableSignup=true).")
    else:
        add("JNKS-003", OPEN, "Anyone can create an account: 'Allow users to sign up' is enabled.",
            "securityRealm/disableSignup=%s" % _text(realm_el, "disableSignup", "(unset)"))

    # JNKS-004 ------------------------------------------------------------
    if cfg is None:
        add("JNKS-004", NR, cfg_missing)
    elif realm_kind == "federated":
        add("JNKS-004", NR, "Authentication is federated (%s). Verify the IdP enforces DoD PKI/CAC "
            "or MFA for all Jenkins users, then record the result with jenkins_stig_overrides." % realm_cls)
    elif realm_kind == "proxy":
        add("JNKS-004", NR, "Reverse-proxy header authentication is in use. Verify the proxy requires "
            "a DoD PKI client certificate and that Jenkins is only reachable through the proxy.")
    else:
        add("JNKS-004", OPEN, "Security realm '%s' performs password-only authentication; no PKI/MFA "
            "is enforced by Jenkins." % realm_kind, "securityRealm class=%s" % realm_cls)

    # JNKS-005 ------------------------------------------------------------
    if cfg is None:
        add("JNKS-005", NR, cfg_missing)
    elif realm_kind in ("local", "none"):
        add("JNKS-005", OPEN, "Jenkins' built-in user database has no account lockout, password "
            "complexity, length or aging controls.", "securityRealm class=%s" % (realm_cls or "none"))
    else:
        add("JNKS-005", NA, "Passwords are not managed by Jenkins (realm: %s)." % realm_kind,
            comments="Lockout/complexity are enforced by the external directory/IdP; confirm this "
                     "matches the check text of your SRG release.")

    # JNKS-006 ------------------------------------------------------------
    if cfg is None:
        add("JNKS-006", NR, cfg_missing)
    elif realm_kind == "ldap":
        servers = [e.text.strip() for e in realm_el.iter("server") if e.text]
        plain = [x for x in servers if not x.lower().startswith("ldaps://")]
        if plain:
            add("JNKS-006", OPEN, "LDAP server URL(s) do not use ldaps://: %s" % ", ".join(plain),
                "servers=%s" % ", ".join(servers))
        elif servers:
            add("JNKS-006", NF, "All LDAP servers use ldaps://.", "servers=%s" % ", ".join(servers))
        else:
            add("JNKS-006", NR, "No LDAP server URL found in config.xml.")
    elif realm_kind == "ad":
        tlscfg = _text(realm_el, ".//tlsConfiguration", "")
        start_tls = _text(realm_el, ".//startTls", "")
        servers = [e.text.strip() for e in realm_el.iter("servers") if e.text]
        issues = []
        if tlscfg.upper() == "TRUST_ALL_CERTIFICATES":
            issues.append("TLS certificate validation is disabled (TRUST_ALL_CERTIFICATES).")
        if start_tls.lower() == "false" and not any(":636" in x or ":3269" in x for x in servers):
            issues.append("StartTLS is disabled and no LDAPS port (636/3269) is configured.")
        ev_lines = ["tlsConfiguration=%s" % (tlscfg or "(default)"), "startTls=%s" % (start_tls or "(default)"),
                    "servers=%s" % (", ".join(servers) or "(DNS discovery)")]
        add("JNKS-006", OPEN if issues else NF, issues or "AD traffic is protected with TLS and certificates are validated.", ev_lines)
    else:
        add("JNKS-006", NA, "No LDAP/Active Directory realm in use (realm: %s)." % realm_kind)

    # JNKS-007 ------------------------------------------------------------
    if cfg is None:
        add("JNKS-007", NR, cfg_missing)
    elif _truthy(_text(cfg, "disableRememberMe", "false")):
        add("JNKS-007", NF, "'Remember me' is disabled.", "disableRememberMe=true")
    else:
        add("JNKS-007", OPEN, "'Remember me' is enabled; a persistent login cookie is issued.",
            "disableRememberMe=%s" % _text(cfg, "disableRememberMe", "(unset)"))

    # JNKS-008 ------------------------------------------------------------
    limit = _int(s.get("max_session_timeout"), 15)
    st = rt.get("session_timeout")
    ev_lines = ["runtime source: %s" % rt.get("source"), "--sessionTimeout=%s" % st,
                "--sessionEviction=%s" % rt.get("session_eviction")]
    if rt.get("source") == "defaults":
        add("JNKS-008", NR, "Jenkins is not running and no startup configuration was found.", ev_lines)
    elif st is None:
        add("JNKS-008", OPEN, "No --sessionTimeout is configured; the servlet container default applies "
            "(organization limit: %d minutes)." % limit, ev_lines)
    elif st <= 0 or st > limit:
        add("JNKS-008", OPEN, "Session timeout is %d minutes (limit %d; 0 or less never expires)." % (st, limit), ev_lines)
    else:
        add("JNKS-008", NF, "Session timeout is %d minutes (limit %d)." % (st, limit), ev_lines)

    # JNKS-009 ------------------------------------------------------------
    add("JNKS-009", OPEN, "Jenkins provides no mechanism to limit concurrent sessions per account.",
        comments="Mitigate at the IdP/proxy or document a risk acceptance via jenkins_stig_overrides.")

    # JNKS-010 ------------------------------------------------------------
    login = http.get("login") or {}
    rx = s.get("banner_regex") or r"You are accessing a U\.S\. Government"
    if not running and not s.get("audit_url"):
        add("JNKS-010", NR, "Jenkins is not running; login page could not be inspected.")
    elif login.get("status") != 200:
        add("JNKS-010", NR, "Login page could not be retrieved (%s %s)." % (login.get("status"), login.get("msg", "")),
            "GET %s" % login.get("url", ""))
    elif re.search(rx, _strip_html(login.get("content", "")), re.I):
        add("JNKS-010", NF, "The DoD banner text is displayed on the login page.",
            "GET %s matched /%s/" % (login.get("url"), rx),
            comments="Confirm the banner requires explicit acknowledgment before login.")
    else:
        sysmsg = _text(cfg, "systemMessage", "") if cfg is not None else ""
        add("JNKS-010", OPEN, "The login page does not display the DoD Notice and Consent Banner.",
            ["GET %s did not match /%s/" % (login.get("url"), rx),
             "systemMessage (post-login only) present: %s" % bool(sysmsg)])

    # JNKS-011 ------------------------------------------------------------
    issues, ev_lines = [], []
    proxy_listener = [l for l in listeners if l["port"] == 443 and l["proc"] not in ("java", "")]
    http_port, https_port = rt.get("http_port", 8080), rt.get("https_port", -1)
    ev_lines.append("httpPort=%s httpListenAddress=%s httpsPort=%s" % (http_port, rt.get("http_listen") or "(all)", https_port))
    for l in jlisteners:
        ev_lines.append("java listening on %s:%s" % (l["addr"], l["port"]))
    plain = []
    if jlisteners:
        tls_ports = set([https_port])
        plain = [l for l in jlisteners if l["port"] not in tls_ports and l["port"] == http_port]
    elif http_port and http_port > 0:
        plain = [{"addr": rt.get("http_listen") or "0.0.0.0", "port": http_port}]
    exposed = [l for l in plain if not _is_loopback(l["addr"])]
    loop_only = [l for l in plain if _is_loopback(l["addr"])]
    behind_proxy = tls_mode == "proxy" or (tls_mode == "auto" and bool(proxy_listener))
    if exposed:
        issues.append("Plaintext HTTP listener exposed on %s." %
                      ", ".join("%s:%s" % (l["addr"], l["port"]) for l in exposed))
    if (not https_port or https_port <= 0):
        if loop_only and behind_proxy:
            ev_lines.append("HTTP bound to loopback; TLS terminated by reverse proxy (%s)." %
                            (", ".join("%s:%s" % (l["proc"], l["port"]) for l in proxy_listener) or "declared"))
        elif not exposed:
            issues.append("Jenkins HTTPS is not enabled and no TLS-terminating reverse proxy was identified.")
    loc = _xml(files.get("jenkins.model.JenkinsLocationConfiguration.xml"))
    jurl = _text(loc, "jenkinsUrl", "")
    if jurl:
        ev_lines.append("Configured Jenkins URL: %s" % jurl)
        if jurl.lower().startswith("http://"):
            issues.append("Configured Jenkins URL uses http:// (%s)." % jurl)
    pp = http.get("plain_http") or {}
    if pp.get("status"):
        ev_lines.append("GET %s -> HTTP %s" % (pp.get("url"), pp.get("status")))
    if rt.get("source") == "defaults" and not jlisteners:
        add("JNKS-011", NR, "Jenkins is not running and no startup configuration was found.", ev_lines)
    else:
        add("JNKS-011", OPEN if issues else NF, issues or "Jenkins is only reachable over HTTPS.", ev_lines)

    # JNKS-012 ------------------------------------------------------------
    if not tls:
        add("JNKS-012", NR, "No TLS endpoint was probed (HTTPS not enabled, Jenkins not running, "
            "or set jenkins_audit_url to the proxy URL).")
    else:
        acc = dict((k, _tls_ok(v)) for k, v in tls.items())
        ev_lines = ["%s handshake: %s" % (k, "accepted" if v else "refused") for k, v in sorted(acc.items())]
        ev_lines.insert(0, "endpoint %s:%s" % (rt.get("probe", {}).get("tls_host"), rt.get("probe", {}).get("tls_port")))
        weak = [k for k in ("ssl3", "tls1", "tls1_1") if acc.get(k)]
        if weak:
            add("JNKS-012", OPEN, "Endpoint accepts deprecated protocols: %s" % ", ".join(weak), ev_lines)
        elif not (acc.get("tls1_2") or acc.get("tls1_3")):
            add("JNKS-012", NR, "No TLS handshake succeeded; verify the endpoint manually.", ev_lines)
        else:
            add("JNKS-012", NF, "Only TLS 1.2 and/or 1.3 are accepted.", ev_lines)

    # JNKS-013 ------------------------------------------------------------
    fips = str(ev.get("fips_enabled", "")).strip()
    policy = str(ev.get("crypto_policy", "")).strip()
    issues = []
    if fips != "1":
        issues.append("Kernel FIPS mode is not enabled (/proc/sys/crypto/fips_enabled=%s)." % (fips or "?"))
    if not policy.upper().startswith("FIPS"):
        issues.append("System crypto policy is %s, not FIPS." % (policy or "unknown"))
    if str(props.get("com.redhat.fips", "")).lower() == "false":
        issues.append("JVM FIPS integration disabled with -Dcom.redhat.fips=false.")
    if _truthy(props.get("java.security.disableSystemPropertiesFile", "")):
        issues.append("JVM ignores system crypto policy (-Djava.security.disableSystemPropertiesFile=true).")
    add("JNKS-013", OPEN if issues else NF, issues or "FIPS mode is enabled system-wide and honored by the JVM.",
        ["fips_enabled=%s" % fips, "crypto-policy=%s" % policy])

    # JNKS-014 ------------------------------------------------------------
    proc = ev.get("process") or {}
    user = proc.get("user") or ev.get("service_user") or ""
    passwd = str(ev.get("passwd", "")).strip()
    ids = str(ev.get("id", "")).strip()
    sudo = str(ev.get("sudo", "")).strip()
    issues, ev_lines = [], ["process user=%s" % (user or "?"), "passwd: %s" % (passwd or "?"),
                            "id: %s" % (ids or "?")]
    if user in ("root", "0"):
        issues.append("Jenkins is running as root.")
    if passwd:
        pw = passwd.split(":")
        if len(pw) >= 7:
            if pw[2] == "0":
                issues.append("Service account has UID 0.")
            if pw[6] not in NOLOGIN_SHELLS:
                issues.append("Service account has an interactive login shell (%s)." % pw[6])
    groups = re.findall(r"\(([^)]+)\)", ids.split("groups=")[-1]) if "groups=" in ids else []
    bad = [g for g in groups if g in PRIV_GROUPS]
    if bad:
        issues.append("Service account is a member of privileged group(s): %s" % ", ".join(bad))
    if sudo and re.search(r"may run the following commands", sudo, re.I):
        issues.append("Service account has sudo privileges.")
        ev_lines.append("sudo -l: %s" % " | ".join(_lines(sudo)[-5:]))
    if not user and not passwd:
        add("JNKS-014", NR, "Could not determine the Jenkins service account.", ev_lines)
    else:
        add("JNKS-014", OPEN if issues else NF, issues or "Jenkins runs as an unprivileged, non-interactive account.", ev_lines)

    # JNKS-015 ------------------------------------------------------------
    svc = user or "jenkins"
    issues, ev_lines = [], []
    jh = stats.get(home)
    if not jh:
        add("JNKS-015", NR, "Could not stat JENKINS_HOME (%s)." % home)
    else:
        for path, rule in [(home, 0o007), (home + "/secrets", 0o077), (home + "/secrets/master.key", 0o077),
                           (home + "/secrets/hudson.util.Secret", 0o077), (home + "/credentials.xml", 0o027),
                           (home + "/config.xml", 0o027), (home + "/users", 0o007)]:
            st_ = stats.get(path)
            if not st_:
                continue
            ev_lines.append(_fmt_stat(st_))
            m = _mode(st_)
            if m is not None and m & rule:
                issues.append("%s mode %s is too permissive (must not include %04o)." % (path, st_["mode"], rule))
        if jh.get("owner") not in (svc, "jenkins"):
            issues.append("JENKINS_HOME is owned by %s, not the service account." % jh.get("owner"))
        if stats.get(home + "/secrets/initialAdminPassword"):
            issues.append("secrets/initialAdminPassword still exists.")
        ww = _lines(ev.get("world_writable"))
        if ww:
            issues.append("%d world-writable file(s) under JENKINS_HOME, e.g. %s" % (len(ww), ", ".join(ww[:5])))
        add("JNKS-015", OPEN if issues else NF, issues or "JENKINS_HOME and secrets are restricted.", ev_lines)

    # JNKS-016 ------------------------------------------------------------
    war = rt.get("war") or ev.get("war") or ""
    wst = stats.get(war) if war else None
    issues, ev_lines = [], []
    if wst:
        ev_lines.append(_fmt_stat(wst))
        m = _mode(wst)
        if wst.get("owner") != "root":
            issues.append("%s is owned by %s (must be root)." % (war, wst.get("owner")))
        if m is not None and m & 0o022:
            issues.append("%s is group/world writable (mode %s)." % (war, wst["mode"]))
    rpmv = _lines(ev.get("rpm_verify"))
    for line in rpmv:
        m = re.match(r"^(\S{9}|missing)\s+(?:([cdglr])\s+)?(/\S+)", line.strip())
        if not m:
            continue
        flags, kind, path = m.groups()
        ev_lines.append("rpm -V: %s" % line.strip())
        if kind == "c":
            continue
        if flags == "missing" or "5" in flags or "M" in flags or "U" in flags or "G" in flags:
            issues.append("Packaged file altered: %s (%s)" % (path, flags))
    if not wst and not rpmv and not ev.get("rpm_version"):
        add("JNKS-016", NR, "Jenkins WAR not located; verify binary protections manually.")
    else:
        add("JNKS-016", OPEN if issues else NF, issues or "Jenkins binaries are root-owned and match the RPM database.", ev_lines)

    # JNKS-017 ------------------------------------------------------------
    if cfg is None:
        add("JNKS-017", NR, cfg_missing)
    else:
        issues = []
        n = _int(_text(cfg, "numExecutors", "2"), 2)
        if n > 0:
            issues.append("Built-in node has %d executor(s); builds can run on the controller." % n)
        ks = str(files.get("secrets/slave-to-master-security-kill-switch") or "").strip().lower()
        if ks == "true":
            issues.append("Agent-to-controller access control is disabled (kill switch = true).")
        add("JNKS-017", OPEN if issues else NF, issues or "No builds run on the controller.",
            ["numExecutors=%s" % n, "agent kill-switch=%s" % (ks or "absent")])

    # JNKS-018 ------------------------------------------------------------
    issues, ev_lines = [], []
    agent_port = _int(_text(cfg, "slaveAgentPort", "-1"), -1) if cfg is not None else None
    ev_lines.append("Inbound agent TCP port: %s" % {-1: "disabled", 0: "random"}.get(agent_port, agent_port))
    if agent_port == 0:
        issues.append("Inbound agent TCP port is random; PPSM requires a fixed, registered port.")
    sshd = _xml(files.get("org.jenkinsci.main.modules.sshd.SSHD.xml"))
    sport = _int(_text(sshd, "port", "-1"), -1)
    ev_lines.append("SSH server port: %s" % {-1: "disabled", 0: "random"}.get(sport, sport))
    if sport == 0:
        issues.append("Jenkins SSH server uses a random port.")
    ports = sorted(set(l["port"] for l in jlisteners))
    ev_lines.append("Ports opened by Jenkins JVM: %s" % (", ".join(str(p) for p in ports) or "none observed"))
    approved = [int(p) for p in (s.get("approved_ports") or [])]
    if approved:
        extra = [p for p in ports if p not in approved]
        if extra:
            issues.append("Jenkins listens on unapproved port(s): %s" % ", ".join(str(p) for p in extra))
    fw = str(ev.get("firewalld_state", "")).strip()
    ev_lines.append("firewalld: %s" % (fw or "unknown"))
    if fw and fw != "running":
        issues.append("firewalld is not running; host-based port restriction is not enforced.")
    if ev.get("firewalld_config"):
        ev_lines += ["  " + l for l in _lines(ev.get("firewalld_config"))]
    if issues:
        add("JNKS-018", OPEN, issues, ev_lines)
    elif approved:
        add("JNKS-018", NF, "Jenkins only uses approved ports.", ev_lines)
    else:
        add("JNKS-018", NR, "Compare the ports below with the system's PPSM registration "
            "(or set jenkins_stig_approved_ports to automate).", ev_lines)

    # JNKS-019 ------------------------------------------------------------
    uc_text = ev.get("update_center") or ""
    uc = _load_update_center(uc_text)
    issues = []
    prohibited = [p for p in (s.get("prohibited_plugins") or []) if p in plugin_map]
    if prohibited:
        issues.append("Prohibited plugins installed: %s" % ", ".join(prohibited))
    approved_pl = s.get("approved_plugins") or []
    if approved_pl:
        extra = sorted(p for p in plugin_map if p not in approved_pl)
        if extra:
            issues.append("Plugins not in the approved baseline: %s" % ", ".join(extra))
    if uc:
        dep = sorted(p for p in plugin_map if p in (uc.get("deprecations") or {}))
        if dep:
            issues.append("Deprecated plugins installed: %s" % ", ".join(dep))
    disabled = sorted(p["name"] for p in plugins if p["disabled"])
    if disabled:
        issues.append("Disabled plugins still installed (uninstall them): %s" % ", ".join(disabled))
    inventory = ["%d plugins installed:" % len(plugins)] + \
        ["  %s %s%s" % (p["name"], p["version"], " (disabled)" if p["disabled"] else "") for p in sorted(plugins, key=lambda x: x["name"])]
    if not plugins:
        add("JNKS-019", NR, "No plugin inventory could be collected from %s/plugins." % home)
    elif issues:
        add("JNKS-019", OPEN, issues, inventory)
    elif approved_pl:
        add("JNKS-019", NF, "All installed plugins are in the approved baseline.", inventory)
    else:
        add("JNKS-019", NR, "Review the plugin inventory for mission need (or set "
            "jenkins_stig_approved_plugins to automate).", inventory)

    # JNKS-020 ------------------------------------------------------------
    issues, notes, ev_lines = [], [], []
    core = re.sub(r"-.*$", "", str(ev.get("rpm_version") or "")) or _text(cfg, "version", "")
    ev_lines.append("Jenkins core: %s" % (core or "unknown"))
    jmaj = _java_major((proc or {}).get("java_version", ""))
    ev_lines.append("Java: %s" % (" ".join(_lines((proc or {}).get("java_version", ""))[:1]) or "unknown"))
    min_java = _int(s.get("min_java_major"), 17)
    if jmaj is not None and jmaj < min_java:
        issues.append("Jenkins runs on Java %d; Java %d+ is required for supported Jenkins releases." % (jmaj, min_java))
    if uc:
        hits = _warning_hits(uc, core, plugins)
        issues += ["Security advisory applies: %s" % h for h in hits]
        latest = uc.get("plugins") or {}
        outdated = ["%s %s -> %s" % (p["name"], p["version"], latest[p["name"]].get("version"))
                    for p in plugins if p["name"] in latest and
                    _version_tuple(latest[p["name"]].get("version")) > _version_tuple(p["version"])]
        ev_lines.append("%d plugin(s) have newer releases available." % len(outdated))
        ev_lines += ["  " + o for o in outdated[:50]]
        try:
            age = float(ev.get("update_center_age_days"))
        except (TypeError, ValueError):
            age = None
        if age is not None:
            ev_lines.append("Update-center data age: %.1f days (source: %s)" % (age, ev.get("update_center_source", "")))
            if age > _int(s.get("update_center_max_age_days"), 7):
                notes.append("Update-center data is %.0f days old; advisories may be missing." % age)
    else:
        notes.append("No update-center metadata available; plugin/core advisories not evaluated "
                     "(set jenkins_stig_update_center_file for air-gapped systems).")
    ru = ev.get("repo_updates") or {}
    if ru.get("rc") == 100:
        pk = [l for l in _lines(ru.get("stdout")) if re.match(r"^\S+\.\S+\s+\S+", l)]
        issues.append("Pending RPM updates: %s" % "; ".join(pk[:10]))
    if issues:
        add("JNKS-020", OPEN, issues + notes, ev_lines)
    elif notes:
        add("JNKS-020", NR, notes, ev_lines)
    else:
        add("JNKS-020", NF, "No applicable security advisories; supported Java runtime.", ev_lines)

    # JNKS-021 ------------------------------------------------------------
    issues, ev_lines = [], []
    for item in s.get("dangerous_properties") or []:
        name, bad = (item.get("name"), item.get("value")) if isinstance(item, dict) else (item, None)
        if name in props and (bad is None or str(props[name]).lower() == str(bad).lower()):
            issues.append("-D%s=%s weakens Jenkins security." % (name, props[name]))
    if cfg is not None and cfg.find("crumbIssuer") is None:
        issues.append("No CSRF crumb issuer is configured in config.xml.")
    api = _xml(files.get("jenkins.security.apitoken.ApiTokenPropertyConfiguration.xml"))
    if api is not None:
        for k in ("creationOfLegacyTokenEnabled", "tokenGenerationOnCreationEnabled"):
            v = _text(api, k, "false")
            ev_lines.append("%s=%s" % (k, v))
            if _truthy(v):
                issues.append("Legacy API token setting %s is enabled." % k)
    if stats.get(home + "/jenkins.yaml") or rt.get("env", {}).get("CASC_JENKINS_CONFIG")             or "casc.jenkins.config" in props:
        ev_lines.append("Configuration-as-Code (jenkins.yaml) is present; findings must be fixed there too.")
    ev_lines.append("JVM system properties: %s" % (", ".join(sorted(props)) or "none"))
    add("JNKS-021", OPEN if issues else NF, issues or "No security protections are disabled.", ev_lines)

    # JNKS-022 ------------------------------------------------------------
    if cfg is None:
        add("JNKS-022", NR, cfg_missing)
    else:
        issues = []
        mf = cfg.find("markupFormatter")
        mcls = mf.get("class", "") if mf is not None else "hudson.markup.EscapedMarkupFormatter (default)"
        if re.search(r"anything|unsafe", mcls, re.I):
            issues.append("Markup formatter %s renders unsanitized HTML." % mcls)
        if "hudson.model.DirectoryBrowserSupport.CSP" in props:
            issues.append("Content-Security-Policy for user content is overridden (-Dhudson.model.DirectoryBrowserSupport.CSP=%s)."
                          % props["hudson.model.DirectoryBrowserSupport.CSP"])
        add("JNKS-022", OPEN if issues else NF, issues or "User markup is escaped/sanitized and the default CSP is in place.",
            "markupFormatter=%s" % mcls)

    # JNKS-023 ------------------------------------------------------------
    issues, ev_lines = [], []
    for p in s.get("error_disclosure_properties") or []:
        if p in props and _truthy(props[p] or "true"):
            issues.append("-D%s enables detailed error disclosure." % p)
    if login.get("status"):
        for h in ("X-Jenkins", "X-Hudson", "Server"):
            v = _header(login, h)
            if v:
                ev_lines.append("%s: %s" % (h, v))
                if h != "Server" or re.search(r"\d", str(v)):
                    issues.append("Response header %s discloses product/version information (%s)." % (h, v))
        add("JNKS-023", OPEN if issues else NF, issues or "No version or stack-trace disclosure detected.", ev_lines)
    elif issues:
        add("JNKS-023", OPEN, issues)
    else:
        add("JNKS-023", NR, "HTTP response headers could not be inspected.")

    # JNKS-024 ------------------------------------------------------------
    at = plugin_map.get("audit-trail")
    cfg_name, at_root = _audit_trail_cfg(files)
    loggers = _audit_loggers(at_root)
    ev_lines = ["audit-trail plugin: %s" % ("%s%s" % (at["version"], " (disabled)" if at["disabled"] else "") if at else "not installed"),
                "config: %s" % (cfg_name or "absent")]
    ev_lines += ["logger: %s %s" % (l["kind"], l["log"] or l["syslog_host"] or l["es_url"]) for l in loggers]
    if at_root is not None:
        ev_lines.append("pattern: %s" % _text(at_root, "pattern", "(default)"))
        ev_lines.append("logBuildCause=%s logCredentialsUsage=%s" % (_text(at_root, "logBuildCause", "?"),
                                                                    _text(at_root, "logCredentialsUsage", "?")))
    if not at or at["disabled"]:
        add("JNKS-024", OPEN, "The Audit Trail plugin is not installed/enabled; Jenkins does not record "
            "who performed security-relevant actions.", ev_lines)
    elif not loggers:
        add("JNKS-024", OPEN, "The Audit Trail plugin has no logger configured.", ev_lines)
    else:
        add("JNKS-024", NF, "Audit Trail plugin is recording events.", ev_lines,
            comments="Verify the URL pattern covers the organization's auditable events.")

    # JNKS-025 ------------------------------------------------------------
    if rt.get("access_logger"):
        add("JNKS-025", NF, "HTTP access logging is enabled (%s)." % rt["access_logger"],
            "access log file: %s" % (rt.get("access_log_file") or "(default)"))
    elif behind_proxy:
        add("JNKS-025", NR, "Jenkins access logging is off, but a reverse proxy fronts Jenkins; verify the "
            "proxy's access log records source, time, request and outcome.")
    elif rt.get("source") == "defaults":
        add("JNKS-025", NR, "Jenkins is not running and no startup configuration was found.")
    else:
        add("JNKS-025", OPEN, "HTTP access logging is not enabled.")

    # JNKS-026 ------------------------------------------------------------
    log_stats = _parse_stats(ev.get("log_stats"))
    issues, ev_lines = [], []
    for path, st_ in sorted(log_stats.items()):
        ev_lines.append(_fmt_stat(st_))
        m = _mode(st_)
        if m is None:
            continue
        if st_["owner"] not in ("root", svc, "jenkins"):
            issues.append("%s is owned by %s." % (path, st_["owner"]))
        if st_["type"] == "d" and m & 0o027:
            issues.append("Log directory %s mode %s (must be 0750 or stricter)." % (path, st_["mode"]))
        if st_["type"] == "f" and m & 0o137:
            issues.append("Log file %s mode %s (must be 0640 or stricter)." % (path, st_["mode"]))
    if not log_stats:
        add("JNKS-026", NR, "No Jenkins log files found (Jenkins may log only to journald); verify "
            "journal permissions under the OS STIG.")
    else:
        add("JNKS-026", OPEN if issues else NF, issues or "Log files and directories are restricted.", ev_lines)

    # JNKS-027 ------------------------------------------------------------
    rs = _lines(ev.get("rsyslog"))
    fwd = [l for l in rs if re.search(r"(^|\s)@@?[\w\[]|omfwd|omrelp", l)]
    imfile = [l for l in rs if "imfile" in l or "File=" in l]
    remote_loggers = [l for l in loggers if (l["kind"] == "syslog" and l["syslog_host"] and not _is_loopback(l["syslog_host"]))
                      or l["kind"] == "elasticsearch"]
    ev_lines = ["rsyslog forwarding: %s" % (" | ".join(fwd) or "none")] + \
               ["rsyslog imfile: %s" % l for l in imfile[:10]] + \
               ["audit-trail remote logger: %s %s" % (l["kind"], l["syslog_host"] or l["es_url"]) for l in remote_loggers]
    file_logs = [l["log"] for l in loggers if l["kind"] == "logfile"]
    if remote_loggers:
        add("JNKS-027", NF, "Audit Trail sends events directly to a remote collector.", ev_lines)
    elif fwd and file_logs and not any(os.path.dirname(f) in " ".join(imfile) for f in file_logs):
        add("JNKS-027", NR, "rsyslog forwards logs, but no imfile input references the Audit Trail log "
            "file(s) %s; verify they reach the central log server." % ", ".join(file_logs), ev_lines)
    elif fwd:
        add("JNKS-027", NF, "System logs are forwarded to a remote log server.", ev_lines)
    else:
        add("JNKS-027", OPEN, "No off-loading of Jenkins audit records to a central log server was found.", ev_lines)

    # JNKS-028 ------------------------------------------------------------
    add("JNKS-028", NR, "Verify log storage is sized for the retention period and the SA/ISSO is alerted at 75% capacity.",
        _lines(ev.get("disk")))

    # JNKS-029 ------------------------------------------------------------
    chrony = str(ev.get("chronyd", "")).strip()
    td = _parse_env(ev.get("timedatectl", ""))
    ev_lines = ["chronyd: %s" % (chrony or "?")] + ["%s=%s" % kv for kv in sorted(td.items())]
    issues = []
    if chrony != "active":
        issues.append("chronyd is not active.")
    if td.get("NTPSynchronized", "").lower() != "yes":
        issues.append("System clock is not synchronized (NTPSynchronized=%s)." % td.get("NTPSynchronized", "?"))
    add("JNKS-029", OPEN if issues else NF, issues or "Time is synchronized by chronyd.", ev_lines)

    # overrides -----------------------------------------------------------
    overrides = s.get("overrides") or {}
    for r in results:
        o = overrides.get(r["id"])
        if not o or o.get("status", r["status"]) not in STATUS_ORDER:
            continue
        r["original_status"] = r["status"]
        r["status"] = o.get("status", r["status"])
        r["overridden"] = True
        note = "Override (%s -> %s): %s" % (r["original_status"], r["status"], o.get("comment", "no justification given"))
        r["comments"] = (r["comments"] + "\n" + note).strip()
    return results


# ---------------------------------------------------------------------------
# XCCDF / CKL
# ---------------------------------------------------------------------------
def _strip_ns(root):
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
        for k in list(el.attrib):
            if "}" in k:
                el.attrib[k.split("}", 1)[1]] = el.attrib.pop(k)
    return root


def _read_xccdf(path):
    path = os.path.expanduser(path)
    if path.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            names = [n for n in z.namelist() if n.lower().endswith("xccdf.xml")]
            if not names:
                names = [n for n in z.namelist() if n.lower().endswith(".xml")]
            if not names:
                raise ValueError("no XCCDF xml found in %s" % path)
            return z.read(names[0]).decode("utf-8", "replace"), names[0]
    with io.open(path, encoding="utf-8") as fh:
        return fh.read(), os.path.basename(path)


def stig_xccdf_rules(path):
    text, fname = _read_xccdf(path)
    root = _strip_ns(ET.fromstring(text.encode("utf-8")))
    rel = ""
    for pt in root.findall("plain-text"):
        if pt.get("id") == "release-info":
            rel = (pt.text or "").strip()
    info = {"title": _text(root, "title", ""), "stigid": root.get("id", ""),
            "version": _text(root, "version", ""), "releaseinfo": rel,
            "description": _text(root, "description", ""), "filename": fname,
            "notice": (root.find("notice").get("id", "") if root.find("notice") is not None else ""),
            "source": (_text(root, "reference/source", "") or "STIG.DOD.MIL"),
            "classification": "UNCLASSIFIED"}
    rules = []
    for grp in root.iter("Group"):
        rule = grp.find("Rule")
        if rule is None:
            continue
        desc = _text(rule, "description", "") or ""

        def tag(t, d=desc):
            m = re.search(r"<%s>(.*?)</%s>" % (t, t), d, re.S)
            return m.group(1).strip() if m else ""

        idents = rule.findall("ident")
        rules.append({
            "vuln_num": grp.get("id", ""), "group_title": _text(grp, "title", ""),
            "rule_id": rule.get("id", ""), "severity": rule.get("severity", "medium"),
            "weight": rule.get("weight", "10.0"), "rule_ver": _text(rule, "version", ""),
            "rule_title": _text(rule, "title", ""), "vuln_discuss": tag("VulnDiscussion"),
            "ia_controls": tag("IAControls"), "false_positives": tag("FalsePositives"),
            "false_negatives": tag("FalseNegatives"), "documentable": tag("Documentable") or "false",
            "mitigations": tag("Mitigations"), "potential_impact": tag("PotentialImpacts"),
            "third_party_tools": tag("ThirdPartyTools"), "mitigation_control": tag("MitigationControl"),
            "responsibility": tag("Responsibility"), "security_override": tag("SeverityOverrideGuidance"),
            "check_content": _text(rule, "check/check-content", ""),
            "check_ref": (rule.find("check/check-content-ref").get("name", "") if rule.find("check/check-content-ref") is not None else ""),
            "fix_text": _text(rule, "fixtext", ""),
            "target_key": _text(rule, "reference/identifier", ""),
            "ccis": [i.text.strip() for i in idents if i.text and i.text.strip().startswith("CCI-")],
            "legacy": [i.text.strip() for i in idents if i.text and "legacy" in (i.get("system") or "")],
        })
    return {"info": info, "rules": rules}


def _srg_base(rule):
    m = re.search(r"SRG-APP-\d{6}", "%s %s" % (rule.get("group_title", ""), rule.get("rule_ver", "")))
    return m.group(0) if m else None


def stig_bind(results, xccdf, rule_map=None):
    """Bind check results to XCCDF rules. Returns {vuln_num: [result ids]} plus ambiguity info.

    A check binds to a rule when (a) jenkins_stig_rule_map lists the rule's Vuln ID, full SRG ID
    or Rule ID for that check, or (b) the check's base SRG ID matches exactly one rule.
    When a base SRG ID matches several rules the evidence is attached as a comment only.
    """
    rule_map = rule_map or {}
    by_base = {}
    for r in xccdf["rules"]:
        by_base.setdefault(_srg_base(r), []).append(r)
    bound, related, ambiguous, unmatched = {}, {}, {}, {}
    for res in results:
        explicit = rule_map.get(res["id"]) or []
        if explicit:
            for r in xccdf["rules"]:
                if any(x in (r["vuln_num"], r["rule_id"], r["group_title"], r["rule_ver"]) for x in explicit):
                    bound.setdefault(r["vuln_num"], []).append(res["id"])
            continue
        for base in res["srg_ids"]:
            cands = by_base.get(base, [])
            if len(cands) == 1:
                bound.setdefault(cands[0]["vuln_num"], []).append(res["id"])
            elif len(cands) > 1:
                ambiguous.setdefault(res["id"], []).extend(c["vuln_num"] for c in cands)
                for c in cands:
                    related.setdefault(c["vuln_num"], []).append(res["id"])
            else:
                unmatched.setdefault(res["id"], []).append(base)
    return {"bound": bound, "related": related, "ambiguous": ambiguous, "unmatched": unmatched}


def stig_vuln_map(results, xccdf, rule_map=None):
    """Per check, the XCCDF rules it maps to: {check_id: [{vuln_num, rule_ver, rule_title, bound}]}.

    Uses stig_bind, so the report shows the same binding the .ckl gets. bound=False marks a
    candidate from an ambiguous base SRG ID (resolve it with jenkins_stig_rule_map).
    """
    binding = stig_bind(results, xccdf, rule_map)
    rules = dict((r["vuln_num"], r) for r in xccdf["rules"])
    out = dict((res["id"], []) for res in results)
    for groups, bound in ((binding["bound"], True), (binding["related"], False)):
        for vuln in sorted(groups):
            for cid in groups[vuln]:
                if not any(e["vuln_num"] == vuln for e in out[cid]):
                    r = rules[vuln]
                    out[cid].append({"vuln_num": vuln, "rule_ver": r["rule_ver"],
                                     "rule_title": r["rule_title"], "bound": bound})
    return out


def _aggregate(statuses):
    if OPEN in statuses:
        return OPEN
    if NR in statuses:
        return NR
    if NF in statuses:
        return NF
    return NA if statuses else NR


def stig_ckl(results, xccdf, asset=None, rule_map=None):
    asset = asset or {}
    info = xccdf["info"]
    idx = dict((r["id"], r) for r in results)
    binding = stig_bind(results, xccdf, rule_map)
    e = lambda v: _xml_escape(str(v if v is not None else ""))
    out = ['<?xml version="1.0" encoding="UTF-8"?>', "<!--DISA STIG Viewer :: 2.18-->", "<CHECKLIST>", "\t<ASSET>"]
    for tag, key, default in [("ROLE", "role", "None"), ("ASSET_TYPE", "asset_type", "Computing"),
                              ("MARKING", "marking", "CUI"), ("HOST_NAME", "host_name", ""),
                              ("HOST_IP", "host_ip", ""), ("HOST_MAC", "host_mac", ""),
                              ("HOST_FQDN", "host_fqdn", ""), ("TARGET_COMMENT", "target_comment", ""),
                              ("TECH_AREA", "tech_area", "Application Review"), ("TARGET_KEY", "target_key", ""),
                              ("WEB_OR_DATABASE", "web_or_database", "false"), ("WEB_DB_SITE", "web_db_site", ""),
                              ("WEB_DB_INSTANCE", "web_db_instance", "")]:
        val = asset.get(key, default)
        if tag == "TARGET_KEY" and not val and xccdf["rules"]:
            val = xccdf["rules"][0]["target_key"]
        out.append("\t\t<%s>%s</%s>" % (tag, e(val), tag))
    out += ["\t</ASSET>", "\t<STIGS>", "\t\t<iSTIG>", "\t\t\t<STIG_INFO>"]
    for k in ("version", "classification", "customname", "stigid", "description", "filename",
              "releaseinfo", "title", "uuid", "notice", "source"):
        v = str(uuid.uuid4()) if k == "uuid" else info.get(k, "")
        if v:
            out.append("\t\t\t\t<SI_DATA><SID_NAME>%s</SID_NAME><SID_DATA>%s</SID_DATA></SI_DATA>" % (k, e(v)))
        else:
            out.append("\t\t\t\t<SI_DATA><SID_NAME>%s</SID_NAME></SI_DATA>" % k)
    out.append("\t\t\t</STIG_INFO>")
    stig_ref = "%s :: Version %s, %s" % (info.get("title"), info.get("version"), info.get("releaseinfo"))
    for r in xccdf["rules"]:
        data = [("Vuln_Num", r["vuln_num"]), ("Severity", r["severity"]), ("Group_Title", r["group_title"]),
                ("Rule_ID", r["rule_id"]), ("Rule_Ver", r["rule_ver"]), ("Rule_Title", r["rule_title"]),
                ("Vuln_Discuss", r["vuln_discuss"]), ("IA_Controls", r["ia_controls"]),
                ("Check_Content", r["check_content"]), ("Fix_Text", r["fix_text"]),
                ("False_Positives", r["false_positives"]), ("False_Negatives", r["false_negatives"]),
                ("Documentable", r["documentable"]), ("Mitigations", r["mitigations"]),
                ("Potential_Impact", r["potential_impact"]), ("Third_Party_Tools", r["third_party_tools"]),
                ("Mitigation_Control", r["mitigation_control"]), ("Responsibility", r["responsibility"]),
                ("Security_Override_Guidance", r["security_override"]), ("Check_Content_Ref", r["check_ref"]),
                ("Weight", r["weight"]), ("Class", "Unclass"), ("STIGRef", stig_ref),
                ("TargetKey", r["target_key"]), ("STIG_UUID", str(uuid.uuid4()))]
        data += [("LEGACY_ID", l) for l in r["legacy"]] or [("LEGACY_ID", "")]
        data += [("CCI_REF", c) for c in r["ccis"]]
        out.append("\t\t\t<VULN>")
        for k, v in data:
            out.append("\t\t\t\t<STIG_DATA><VULN_ATTRIBUTE>%s</VULN_ATTRIBUTE><ATTRIBUTE_DATA>%s</ATTRIBUTE_DATA></STIG_DATA>" % (k, e(v)))
        ids = binding["bound"].get(r["vuln_num"], [])
        rel = [i for i in binding["related"].get(r["vuln_num"], []) if i not in ids]
        if ids:
            status = _aggregate([idx[i]["status"] for i in ids])
            details = "\n\n".join("[%s] %s: %s\n%s\nEvidence:\n%s" % (i, idx[i]["status"], idx[i]["title"],
                                                                     idx[i]["finding_details"], idx[i]["evidence"])
                                  for i in ids)
            comments = "\n".join("[%s] %s" % (i, idx[i]["comments"]) for i in ids if idx[i]["comments"])
        else:
            status, details, comments = NR, "", ""
        if rel:
            comments = (comments + "\nRelated automated evidence (manual determination required): " +
                        "; ".join("%s=%s" % (i, idx[i]["status"]) for i in rel)).strip()
        comments = (comments + "\nAssessed by jenkins_stig_audit (Ansible) on %s." % asset.get("collected_at", "")).strip() if ids or rel else comments
        out.append("\t\t\t\t<STATUS>%s</STATUS>" % status)
        out.append("\t\t\t\t<FINDING_DETAILS>%s</FINDING_DETAILS>" % e(details))
        out.append("\t\t\t\t<COMMENTS>%s</COMMENTS>" % e(comments))
        out.append("\t\t\t\t<SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>")
        out.append("\t\t\t\t<SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>")
        out.append("\t\t\t</VULN>")
    out += ["\t\t</iSTIG>", "\t</STIGS>", "</CHECKLIST>", ""]
    return "\n".join(out)


def stig_csv(results):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Check", "Severity", "Status", "SRG IDs", "Title", "Finding Details", "Evidence", "Fix", "Comments"])
    for r in results:
        w.writerow([r["id"], r["cat"], r["status"], " ".join(r["srg_ids"]), r["title"],
                    r["finding_details"], r["evidence"], r["fix"], r["comments"]])
    return buf.getvalue()


def stig_summary(results):
    out = {"total": len(results), "by_status": dict((k, 0) for k in STATUS_ORDER), "open_by_severity": {"high": 0, "medium": 0, "low": 0}}
    for r in results:
        out["by_status"][r["status"]] = out["by_status"].get(r["status"], 0) + 1
        if r["status"] == OPEN:
            out["open_by_severity"][r["severity"]] = out["open_by_severity"].get(r["severity"], 0) + 1
    return out


def file_age_days(path, now=None):
    """Age in days of a controller-side file (used for jenkins_stig_update_center_file)."""
    try:
        return ((now or time.time()) - os.path.getmtime(os.path.expanduser(path))) / 86400.0
    except OSError:
        return None


class FilterModule(object):
    def filters(self):
        return {
            "jenkins_runtime": jenkins_runtime,
            "jenkins_audit_log_dirs": jenkins_audit_log_dirs,
            "jenkins_stig_evaluate": jenkins_stig_evaluate,
            "stig_xccdf_rules": stig_xccdf_rules,
            "stig_bind": stig_bind,
            "stig_vuln_map": stig_vuln_map,
            "stig_ckl": stig_ckl,
            "stig_csv": stig_csv,
            "stig_summary": stig_summary,
            "file_age_days": file_age_days,
        }
