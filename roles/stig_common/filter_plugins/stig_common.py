# -*- coding: utf-8 -*-
"""
Shared controller-side logic for the gitlab_stig_audit and nexus_stig_audit roles.

The product filter plugins import this module for their helpers and host-level
checks, and Ansible loads it as a filter plugin for the report/checklist filters.
Everything is plain Python so it can be unit tested without Ansible.

Filters exported:
  stig_xccdf_rules - parse a DISA SRG/STIG XCCDF (.xml or .zip)
  stig_bind        - bind check results to XCCDF rules by SRG ID
  stig_vuln_map    - per check, the Vuln IDs it maps to (HTML report)
  stig_ckl         - render a STIG Viewer .ckl checklist
  stig_csv         - render results as CSV
  stig_summary     - status / severity counts
  file_age_days    - age of a controller-side file
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

LOOPBACK = ("127.", "::1", "localhost", "[::1]", "::ffff:127.")
NOLOGIN_SHELLS = ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false")
PRIV_GROUPS = ("root", "wheel", "docker", "adm", "disk")
DEFAULT_BANNER = r"You are accessing a U\.S\. Government"


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
    return bool(addr) and str(addr).startswith(LOOPBACK)


def _lines(val):
    if val is None:
        return []
    if isinstance(val, (list, tuple)):
        return [str(v) for v in val if str(v).strip()]
    return [l for l in str(val).splitlines() if l.strip()]


def _names(val):
    """Account names from a list or comma/space-separated string, lower-cased (for break-glass lists)."""
    if isinstance(val, str):
        val = re.split(r"[,\s]+", val)
    return set(str(v).strip().lower() for v in (val or []) if str(v).strip())


def _version_tuple(v):
    return tuple(int(p) for p in re.findall(r"\d+", str(v or "")))


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
        mtime = size = None
        if len(parts) > 5:
            try:
                mtime = float(parts[5])
            except ValueError:
                mtime = None
        if len(parts) > 6:
            size = _int(parts[6])
        out[parts[0].rstrip("/") or "/"] = {
            "path": parts[0], "owner": parts[1], "group": parts[2],
            "mode": parts[3].zfill(4), "type": parts[4], "mtime": mtime, "size": size,
        }
    return out


def _parse_env(text):
    """Parse KEY=value lines (sysconfig, systemd Environment=, timedatectl show, .properties)."""
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
        m = re.match(r'^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(.*)$', line)
        if m:
            env[m.group(1)] = m.group(2).strip().strip("'\"")
    return env


def _jvm_properties(args):
    props = {}
    for a in _lines(args):
        if a.startswith("-D"):
            k, _, v = a[2:].partition("=")
            props[k] = v
    return props


def _listeners(ss_text):
    """Parse `ss -tlnp` output into [{addr, port, proc, pid}]."""
    out = []
    for line in _lines(ss_text):
        cols = line.split()
        if len(cols) < 4:
            continue
        local = cols[3] if cols[0] in ("LISTEN", "UNCONN") else cols[2] if len(cols) > 2 else ""
        m = re.match(r"^(.*):(\d+)$", local)
        if not m:
            continue
        addr = m.group(1).strip("[]").split("%")[0]
        pm = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        out.append({"addr": addr, "port": int(m.group(2)),
                    "proc": pm.group(1) if pm else "", "pid": pm.group(2) if pm else ""})
    return out


def _fmt_listener(l):
    return "%s %s:%s" % (l.get("proc") or "?", l["addr"], l["port"])


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


def _java_major(text):
    m = re.search(r'version "([^"]+)"', text or "")
    if not m:
        return None
    v = m.group(1)
    if v.startswith("1."):
        return _int(v.split(".")[1])
    return _int(re.split(r"[.\-+]", v)[0])


_SECRET = r"(?:pass(?:word|phrase)?|passwd|secret|token|private_key|credentials?)"
_REDACT = [
    # Ruby / JSON / quoted YAML:  x_password'] = "v"   'password' => 'v'   "secret": "v"   password: 'v'
    (re.compile(r"""(%s[\w'"\]]*\s*(?:=>|=|:)\s*)("[^"]*"|'[^']*')""" % _SECRET, re.I), r"\1'********'"),
    # unquoted YAML / .properties values (booleans and numbers are kept: they are settings, not secrets)
    (re.compile(r"""^(\s*-?\s*[\w.\-]*%s[\w.\-]*\s*[:=]\s*)(?!['"]|(?:true|false|yes|no|\d+)\s*$)(\S.*)$""" % _SECRET,
                re.I | re.M), r"\1'********'"),
    # Jetty XML: <Set name="KeyStorePassword">v</Set>, <Property name="...password" default="v"/>
    (re.compile(r"""(<Set\s+name="[^"]*Password"[^>]*>)[^<]*""", re.I), r"\1********"),
    (re.compile(r"""(name="[^"]*password"[^>]*default=")[^"]*""", re.I), r"\1********"),
    # credentials inside URLs: jdbc:...?password=v, scheme://user:v@host
    (re.compile(r"""([?&;]password=)[^&;\s"']*""", re.I), r"\1********"),
    (re.compile(r"""(\w://[^/:@\s"']+:)[^@/\s"']+(@)"""), r"\1********\2"),
]


def stig_redact(text, strip_comments=False):
    """Mask secret values in config text before it is stored as evidence."""
    text = str(text or "")
    if strip_comments:
        text = "\n".join(l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#"))
    for rx, rep in _REDACT:
        text = rx.sub(rep, text)
    return text


def _json(text):
    if isinstance(text, (dict, list)):
        return text
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# result collection
# ---------------------------------------------------------------------------
def catalog(checks):
    """[(id, title, srg_ids, severity, fix)] -> {id: meta}"""
    return dict((c[0], {"id": c[0], "title": c[1], "srg_ids": c[2], "severity": c[3], "fix": c[4]})
                for c in checks)


class Results(object):
    """Accumulates check results in catalog order."""

    def __init__(self, meta):
        self.meta = meta
        self.items = []

    def add(self, cid, status, details, evidence=None, comments=""):
        r = dict(self.meta[cid])
        if isinstance(details, (list, tuple)):
            details = "\n".join(details)
        if isinstance(evidence, (list, tuple)):
            evidence = "\n".join(str(e) for e in evidence)
        r.update({"status": status, "finding_details": details or "", "evidence": evidence or "",
                  "comments": comments or "", "cat": SEV_CAT.get(r["severity"], "")})
        self.items.append(r)

    def verdict(self, cid, issues, ok_text, evidence=None, comments=""):
        self.add(cid, OPEN if issues else NF, issues or ok_text, evidence, comments)


def apply_overrides(results, overrides):
    for r in results:
        o = (overrides or {}).get(r["id"])
        if not o or o.get("status", r["status"]) not in STATUS_ORDER:
            continue
        r["original_status"] = r["status"]
        r["status"] = o.get("status", r["status"])
        r["overridden"] = True
        note = "Override (%s -> %s): %s" % (r["original_status"], r["status"], o.get("comment", "no justification given"))
        r["comments"] = (r["comments"] + "\n" + note).strip()
    return results


# ---------------------------------------------------------------------------
# host-level checks shared by the products.  Each returns (status, details, evidence).
# `host` is the dict built by roles/stig_common/tasks/host.yml.
# ---------------------------------------------------------------------------
def eval_tls(tls, endpoint):
    if not tls:
        return NR, "No TLS endpoint was probed (HTTPS not enabled, the service is not running, or " \
                   "the audit URL is not set to the proxy URL).", []
    acc = dict((k, _tls_ok(v)) for k, v in tls.items())
    ev = ["endpoint %s" % endpoint] + \
         ["%s handshake: %s" % (k, "accepted" if v else "refused") for k, v in sorted(acc.items())]
    weak = [k for k in ("ssl3", "tls1", "tls1_1") if acc.get(k)]
    if weak:
        return OPEN, "Endpoint accepts deprecated protocols: %s" % ", ".join(weak), ev
    if not (acc.get("tls1_2") or acc.get("tls1_3")):
        return NR, "No TLS handshake succeeded; verify the endpoint manually.", ev
    return NF, "Only TLS 1.2 and/or 1.3 are accepted.", ev


def eval_fips(host, props=None, extra_issues=None):
    host = host or {}
    props = props or {}
    fips = str(host.get("fips_enabled", "")).strip()
    policy = str(host.get("crypto_policy", "")).strip()
    issues = []
    if fips != "1":
        issues.append("Kernel FIPS mode is not enabled (/proc/sys/crypto/fips_enabled=%s)." % (fips or "?"))
    if not policy.upper().startswith("FIPS"):
        issues.append("System crypto policy is %s, not FIPS." % (policy or "unknown"))
    if str(props.get("com.redhat.fips", "")).lower() == "false":
        issues.append("JVM FIPS integration disabled with -Dcom.redhat.fips=false.")
    if _truthy(props.get("java.security.disableSystemPropertiesFile", "")):
        issues.append("JVM ignores system crypto policy (-Djava.security.disableSystemPropertiesFile=true).")
    issues += extra_issues or []
    ev = ["fips_enabled=%s" % fips, "crypto-policy=%s" % policy]
    return (OPEN if issues else NF), (issues or "FIPS mode is enabled system-wide and honored by the service."), ev


def eval_accounts(host, users, shell_ok=None):
    """Service accounts must not be root/UID 0, privileged-group members or sudoers, and
    must have a non-interactive shell unless listed in shell_ok (with the reason)."""
    accounts = (host or {}).get("accounts") or {}
    shell_ok = shell_ok or {}
    issues, ev, seen = [], [], 0
    for user in users:
        a = accounts.get(user) or {}
        passwd = str(a.get("passwd", "")).strip()
        ids = str(a.get("id", "")).strip()
        sudo = str(a.get("sudo", "")).strip()
        if not passwd:
            continue
        seen += 1
        ev += ["passwd: %s" % passwd, "id: %s" % (ids or "?")]
        pw = passwd.split(":")
        if len(pw) >= 7:
            if pw[2] == "0":
                issues.append("%s has UID 0." % user)
            if pw[6] not in NOLOGIN_SHELLS:
                if user in shell_ok:
                    ev.append("%s shell %s is required: %s" % (user, pw[6], shell_ok[user]))
                else:
                    issues.append("%s has an interactive login shell (%s)." % (user, pw[6]))
        groups = re.findall(r"\(([^)]+)\)", ids.split("groups=")[-1]) if "groups=" in ids else []
        bad = [g for g in groups if g in PRIV_GROUPS]
        if bad:
            issues.append("%s is a member of privileged group(s): %s" % (user, ", ".join(bad)))
        if re.search(r"may run the following commands", sudo, re.I):
            issues.append("%s has sudo privileges." % user)
            ev.append("sudo -l -U %s: %s" % (user, " | ".join(_lines(sudo)[-5:])))
    if not seen:
        return NR, "Could not read the service account(s): %s" % ", ".join(users), ev
    return (OPEN if issues else NF), (issues or "Service accounts are unprivileged and non-interactive."), ev


def eval_ports(host, product_listeners, approved, product="The service"):
    issues, ev = [], []
    ev += ["listening: %s" % _fmt_listener(l) for l in sorted(product_listeners, key=lambda x: x["port"])]
    if not product_listeners:
        ev.append("No listening sockets attributed to the product were observed.")
    approved = [int(p) for p in (approved or [])]
    exposed = sorted(set(l["port"] for l in product_listeners if not _is_loopback(l["addr"])))
    if approved:
        extra = [p for p in exposed if p not in approved]
        if extra:
            issues.append("%s listens on unapproved port(s): %s" % (product, ", ".join(str(p) for p in extra)))
    fw = str((host or {}).get("firewalld_state", "")).strip()
    ev.append("firewalld: %s" % (fw or "unknown"))
    if fw and fw != "running":
        issues.append("firewalld is not running; host-based port restriction is not enforced.")
    ev += ["  " + l for l in _lines((host or {}).get("firewalld_config"))]
    if issues:
        return OPEN, issues, ev
    if approved:
        return NF, "%s only exposes approved ports (%s)." % (product, ", ".join(str(p) for p in exposed) or "none"), ev
    return NR, "Compare the non-loopback ports (%s) with the system's PPSM registration (or set the " \
               "approved_ports variable to automate)." % (", ".join(str(p) for p in exposed) or "none"), ev


def eval_log_perms(log_stats, owners, traverse_dirs=()):
    """Log directories must be 0750 or stricter (traverse_dirs, which service users must pass
    through, only must not be group/world writable) and files 0640 or stricter.  A file's
    group/other bits only count when its directory lets that class of user in."""
    stats = _parse_stats(log_stats)
    issues, ev = [], []
    for path, st_ in sorted(stats.items()):
        ev.append(_fmt_stat(st_))
        m = _mode(st_)
        if m is None or st_["type"] not in ("d", "f"):
            continue
        if st_["owner"] not in owners:
            issues.append("%s is owned by %s." % (path, st_["owner"]))
        if st_["type"] == "d":
            if m & (0o022 if path in traverse_dirs else 0o027):
                issues.append("Log directory %s mode %s is too permissive." % (path, st_["mode"]))
            continue
        pm = _mode(stats.get(os.path.dirname(path)) or {})
        if pm is not None:
            if not pm & 0o001:
                m &= ~0o007
            if not pm & 0o010:
                m &= ~0o070
        if m & 0o137:
            issues.append("Log file %s mode %s (must be 0640 or stricter)." % (path, st_["mode"]))
    if not stats:
        return NR, "No log files were found; verify log protection manually.", ev
    return (OPEN if issues else NF), (_cap(issues) or "Log files and directories are restricted."), _cap(ev, 40)


def rpm_verify_issues(text, ev_lines, owner_changes=()):
    """`rpm -V` output -> issues for altered packaged files (config, doc and ghost files ignored).
    owner_changes: paths the product's installer re-owns by design; a user/group-only change there is
    expected.  Appends the relevant lines to ev_lines."""
    issues = []
    for line in _lines(text):
        m = re.match(r"^(\S{9}|missing)\s+(?:([cdglr])\s+)?(/\S+)", line.strip())
        if not m:
            continue
        flags, kind, path = m.groups()
        if kind in ("c", "d", "g"):
            continue
        if path in owner_changes and flags != "missing" and not any(f in flags for f in "5SM"):
            ev_lines.append("rpm -V: %s (expected: re-owned by the installer)" % line.strip())
            continue
        ev_lines.append("rpm -V: %s" % line.strip())
        if flags == "missing" or any(f in flags for f in "5MUG"):
            issues.append("Packaged file altered: %s (%s)" % (path, flags))
    return _cap(issues)


def _cap(issues, n=20):
    return issues[:n] + ["... and %d more" % (len(issues) - n)] if len(issues) > n else issues


def eval_offload(host, log_dirs, remote=None):
    """remote: evidence strings for product-native remote log shipping (already verified)."""
    rs = _lines((host or {}).get("rsyslog"))
    fwd = [l for l in rs if re.search(r"(^|\s)@@?[\w\[]|omfwd|omrelp", l)]
    # input(type="imfile" File="...") or legacy $InputFileName; not imjournal's StateFile=
    imfile = [l for l in rs if "imfile" in l or re.search(r"(^|[^\w])File\s*=|\$InputFileName", l)]
    ev = ["rsyslog forwarding: %s" % (" | ".join(fwd) or "none")] + \
         ["rsyslog imfile: %s" % l for l in imfile[:10]] + ["native: %s" % r for r in remote or []]
    if remote:
        return NF, "Logs are shipped directly to a remote collector.", ev
    covered = [d for d in log_dirs if any(d in l for l in imfile)]
    if fwd and not covered:
        return NR, "rsyslog forwards system logs, but no imfile input reads %s; verify the product's " \
                   "logs reach the central log server." % ", ".join(log_dirs), ev
    if fwd:
        return NF, "Product logs are read by rsyslog and forwarded to a remote log server.", ev
    return OPEN, "No off-loading of audit records to a central log server was found.", ev


def eval_storage(host):
    return NR, "Verify log storage is sized for the retention period and the SA/ISSO is alerted at 75% " \
               "capacity.", _lines((host or {}).get("disk"))


def eval_time(host):
    host = host or {}
    chrony = str(host.get("chronyd", "")).strip()
    td = _parse_env(host.get("timedatectl", ""))
    ev = ["chronyd: %s" % (chrony or "?")] + ["%s=%s" % kv for kv in sorted(td.items())]
    issues = []
    if chrony != "active":
        issues.append("chronyd is not active.")
    if td.get("NTPSynchronized", "").lower() != "yes":
        issues.append("System clock is not synchronized (NTPSynchronized=%s)." % td.get("NTPSynchronized", "?"))
    return (OPEN if issues else NF), (issues or "Time is synchronized by chronyd."), ev


def eval_banner(page, regex, reachable=True):
    """page: collated uri result for the login page."""
    page = page or {}
    rx = regex or DEFAULT_BANNER
    if not reachable:
        return NR, "The service is not running; the login page could not be inspected.", []
    if page.get("status") != 200:
        return NR, "Login page could not be retrieved (%s %s)." % (page.get("status"), page.get("msg", "")), \
            ["GET %s" % page.get("url", "")]
    if re.search(rx, _strip_html(page.get("content", "")), re.I):
        return NF, "The DoD banner text is displayed on the login page.", ["GET %s matched /%s/" % (page.get("url"), rx)]
    return OPEN, "The login page does not display the DoD Notice and Consent Banner.", \
        ["GET %s did not match /%s/" % (page.get("url"), rx)]


def eval_updates(version, min_version, repo_updates, product):
    issues, ev = [], ["%s version: %s" % (product, version or "unknown")]
    if min_version:
        ev.append("Organization minimum: %s" % min_version)
        if version and _version_tuple(version) < _version_tuple(min_version):
            issues.append("%s %s is older than the required minimum %s." % (product, version, min_version))
    ru = repo_updates or {}
    if ru.get("rc") == 100:
        pk = [l for l in _lines(ru.get("stdout")) if re.match(r"^\S+\.\S+\s+\S+", l)]
        issues.append("Pending RPM updates: %s" % "; ".join(pk[:10]))
        ev += pk[:10]
    elif ru:
        ev.append("dnf check-update: no pending updates")
    if issues:
        return OPEN, issues, ev
    if min_version and version:
        return NF, "%s %s meets the organization minimum." % (product, version), ev
    return NR, "Compare the version with the vendor's current security releases (or set the min_version " \
               "variable to automate).", ev


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

    A check binds to a rule when (a) the rule map, or the result's own vuln_ids (product STIG
    checks), lists the rule's Vuln ID, full SRG ID or Rule ID, or (b) the check's base SRG ID
    matches exactly one rule.
    When a base SRG ID matches several rules the evidence is attached as a comment only.
    """
    rule_map = rule_map or {}
    by_base = {}
    for r in xccdf["rules"]:
        by_base.setdefault(_srg_base(r), []).append(r)
    bound, related, ambiguous, unmatched = {}, {}, {}, {}
    for res in results:
        explicit = rule_map.get(res["id"]) or res.get("vuln_ids") or []
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
    candidate from an ambiguous base SRG ID (resolve it with the rule map).
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
    tool = asset.get("tool", "stig_common")
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
        if ids or rel:
            comments = (comments + "\nAssessed by %s (Ansible) on %s." % (tool, asset.get("collected_at", ""))).strip()
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
    out = {"total": len(results), "by_status": dict((k, 0) for k in STATUS_ORDER),
           "open_by_severity": {"high": 0, "medium": 0, "low": 0}}
    for r in results:
        out["by_status"][r["status"]] = out["by_status"].get(r["status"], 0) + 1
        if r["status"] == OPEN:
            out["open_by_severity"][r["severity"]] = out["open_by_severity"].get(r["severity"], 0) + 1
    return out


def file_age_days(path, now=None):
    """Age in days of a controller-side file."""
    try:
        return ((now or time.time()) - os.path.getmtime(os.path.expanduser(path))) / 86400.0
    except OSError:
        return None


class FilterModule(object):
    def filters(self):
        return {
            "stig_xccdf_rules": stig_xccdf_rules,
            "stig_bind": stig_bind,
            "stig_vuln_map": stig_vuln_map,
            "stig_ckl": stig_ckl,
            "stig_csv": stig_csv,
            "stig_summary": stig_summary,
            "file_age_days": file_age_days,
            "stig_redact": stig_redact,
        }
