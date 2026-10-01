# -*- coding: utf-8 -*-
"""
Controller-side evaluation logic for the postgres_stig_audit role: the DISA Crunchy
Data Postgres 16 STIG (V1R3) on RHEL.

Unlike the SRG-based audits, this is a product STIG, so there is one result per STIG
rule, identified by its STIG ID (CD16-00-xxxxxx) and bound to its Vuln ID.  Rule
titles and DISA's fix text come from files/crunchy_pg16_stig_index.json.

DISA's check procedures for several audit rules perform a test action (CREATE ROLE,
a failed login, ...).  This audit is read-only, so for those rules it verifies the
configuration that makes PostgreSQL record the event and shows how many such
records the latest log already holds.

Filters exported:
  pg_pick_postmaster  - choose the PostgreSQL 16 postmaster from a process list
  pg_paths            - config/log/SSL file locations from settings or postgresql.conf
  postgres_stig_evaluate - evidence dict -> list of check results
"""
from __future__ import absolute_import, division, print_function

import io
import json
import os
import re
import shlex
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "..", "stig_common", "filter_plugins"))
import stig_common as sc  # noqa: E402

NF, OPEN, NA, NR = sc.NF, sc.OPEN, sc.NA, sc.NR

with io.open(os.path.join(_HERE, "..", "files", "crunchy_pg16_stig_index.json"), encoding="utf-8") as _fh:
    INDEX = json.load(_fh)
CHECKS = [(r["rule_ver"], r["rule_title"], [r["group_title"]], r["severity"], r["fix"]) for r in INDEX["rules"]]
CHECK_META = sc.catalog(CHECKS)
for _r in INDEX["rules"]:
    CHECK_META[_r["rule_ver"]]["vuln_ids"] = [_r["vuln_num"]]

AUDIT_CLASSES = ("read", "write", "function", "role", "ddl", "misc", "misc_set")
OK_LEVELS = ("debug5", "debug4", "debug3", "debug2", "debug1", "info", "notice", "warning", "error")
EXTERNAL_AUTH = ("gss", "sspi", "ldap", "cert")
# Defaults applied when settings come from postgresql.conf instead of the live server.
DEFAULTS = {
    "port": "5432", "listen_addresses": "localhost", "max_connections": "100", "ssl": "off",
    "password_encryption": "scram-sha-256", "shared_preload_libraries": "", "log_destination": "stderr",
    "logging_collector": "off", "log_directory": "log", "log_file_mode": "0600", "log_line_prefix": "%m [%p] ",
    "log_connections": "off", "log_disconnections": "off", "log_hostname": "off", "log_min_messages": "warning",
    "log_min_error_statement": "error", "client_min_messages": "notice", "statement_timeout": "0",
    "tcp_keepalives_idle": "0", "tcp_keepalives_interval": "0", "tcp_keepalives_count": "0",
    "syslog_facility": "local0", "pgaudit.log": "none", "pgaudit.log_catalog": "on",
    "ssl_cert_file": "server.crt", "ssl_key_file": "server.key", "ssl_ca_file": "", "ssl_crl_file": "",
    "idle_session_timeout": "0", "idle_in_transaction_session_timeout": "0",
}
TEST_NOTE = ("DISA's procedure performs a test action (e.g. a denied statement or failed login). This read-only "
             "audit verified the logging configuration that records it instead; perform the test during the "
             "assessment if required.")


# ---------------------------------------------------------------------------
# parsing helpers
# ---------------------------------------------------------------------------
def _on(v):
    return str(v or "").strip().lower() in ("on", "true", "yes", "1")


def _csv(v):
    return [t.strip().strip("'\"").lower() for t in str(v or "").split(",") if t.strip()]


def parse_conf(text):
    """postgresql.conf / postgresql.auto.conf -> {name: value} (last assignment wins)."""
    out = {}
    for raw in sc._lines(text):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_][\w.]*)\s*(?:=\s*|\s+)(.*)$", line)
        if not m:
            continue
        val = m.group(2).strip()
        if val.startswith("'"):
            q = re.match(r"^'((?:[^']|'')*)'", val)
            val = q.group(1).replace("''", "'") if q else val.strip("'")
        else:
            val = val.split("#", 1)[0].strip()
        out[m.group(1).lower()] = val
    return out


def parse_hba(text):
    """pg_hba.conf text -> rules shaped like the pg_hba_file_rules view."""
    rules = []
    for n, raw in enumerate(str(text or "").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("include"):
            continue
        try:
            tok = shlex.split(line)
        except ValueError:
            tok = line.split()
        if len(tok) < 4 or tok[0] not in ("local", "host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc"):
            continue
        r = {"line": n, "type": tok[0], "database": tok[1].split(","), "user": tok[2].split(","),
             "address": None, "netmask": None}
        rest = tok[3:]
        if tok[0] != "local":
            r["address"], rest = rest[0], rest[1:]
            if rest and "/" not in r["address"] and re.match(r"^[\d.:a-fA-F]+$", rest[0] or "") and \
                    re.match(r"^[\d.:a-fA-F]+$", r["address"]):
                r["netmask"], rest = rest[0], rest[1:]
        if not rest:
            continue
        r["method"], r["options"] = rest[0], rest[1:]
        rules.append(r)
    return rules


def _sql(v):
    if isinstance(v, dict):
        return v
    return sc._json(str(v or "").strip()) or {}


def pg_pick_postmaster(lines, bindir="/usr/pgsql-16/bin", pgdata=""):
    """Lines 'pid|exe|cmdline' of postmaster processes -> {pid, exe, pgdata} for PostgreSQL 16."""
    cands = []
    for line in sc._lines(lines):
        parts = line.split("|", 2)
        if len(parts) < 3:
            continue
        pid, exe, cmd = parts
        m = re.search(r"\s-D\s+(\S+)", " " + cmd)
        cands.append({"pid": pid.strip(), "exe": exe.strip(), "pgdata": m.group(1).rstrip("/") if m else ""})
    for c in cands:
        if pgdata and c["pgdata"] == pgdata.rstrip("/"):
            return c
    for c in cands:
        if bindir and c["exe"].startswith(bindir.rstrip("/") + "/"):
            return c
    return {"pid": "", "exe": "", "pgdata": ""}


def _settings(sqlres, conf_text="", auto_text=""):
    """(settings, source).  Live pg_settings when available, else the config files plus defaults."""
    live = sqlres.get("settings") or {}
    if live:
        return dict((k, (v or {}).get("setting", "") if isinstance(v, dict) else v) for k, v in live.items()), "live"
    if not conf_text and not auto_text:
        return {}, "none"
    s = dict(DEFAULTS)
    s.update(parse_conf(conf_text))
    s.update(parse_conf(auto_text))
    return s, "file"


def pg_paths(sql_result, pgdata, conf_text="", auto_text=""):
    """Absolute paths of the config, log and SSL files."""
    sqlres = _sql(sql_result)
    s, _ = _settings(sqlres, conf_text, auto_text)
    data = (s.get("data_directory") or pgdata or "").rstrip("/")

    def resolve(v):
        v = str(v or "").strip()
        if not v:
            return ""
        return v if v.startswith("/") else "%s/%s" % (data, v)

    out = {"data_directory": data,
           "config_file": s.get("config_file") or "%s/postgresql.conf" % data,
           "hba_file": s.get("hba_file") or "%s/pg_hba.conf" % data,
           "ident_file": s.get("ident_file") or "%s/pg_ident.conf" % data,
           "auto_file": "%s/postgresql.auto.conf" % data,
           "log_dir": resolve(s.get("log_directory", "log"))}
    for k in ("ssl_cert_file", "ssl_key_file", "ssl_ca_file", "ssl_crl_file"):
        out[k] = resolve(s.get(k, DEFAULTS.get(k, "")))
    return out


def _pgaudit_classes(v):
    classes = set()
    for tok in _csv(v):
        neg = tok.startswith("-")
        tok = tok.lstrip("-")
        items = set(AUDIT_CLASSES) if tok == "all" else ({tok} if tok in AUDIT_CLASSES else set())
        classes = classes - items if neg else classes | items
    return classes


# ---------------------------------------------------------------------------
# evaluation context
# ---------------------------------------------------------------------------
class Ctx(object):
    def __init__(self, ev, s):
        self.ev, self.s = ev, s
        self.host = ev.get("system") or {}
        self.sql = _sql(ev.get("sql"))
        files = ev.get("files") or {}
        self.S, self.source = _settings(self.sql, files.get("postgresql.conf"), files.get("postgresql.auto.conf"))
        self.file_settings = self.sql.get("file_settings") or {}
        if self.source == "file":
            self.file_settings = dict((k, v) for k, v in self.S.items())
        self.hba = self.sql.get("hba") or parse_hba(files.get("pg_hba.conf"))
        self.hba_source = "pg_hba_file_rules" if self.sql.get("hba") else ("pg_hba.conf" if self.hba else "none")
        self.roles = self.sql.get("roles") or []
        self.passwords = self.sql.get("passwords") or []
        self.ident = self.sql.get("ident") or []
        self.dbs = [sc._json(d) if not isinstance(d, dict) else d for d in (ev.get("dbs") or [])]
        self.dbs = [d for d in self.dbs if isinstance(d, dict)]
        self.pg_user = s.get("pg_user") or "postgres"
        self.paths = ev.get("paths") or pg_paths(self.sql, ev.get("pgdata", ""), files.get("postgresql.conf"),
                                                 files.get("postgresql.auto.conf"))
        self.pgdata = (self.paths.get("data_directory") or ev.get("pgdata") or "").rstrip("/")
        self.install = (ev.get("install_dir") or "/usr/pgsql-16").rstrip("/")
        self.pgdata_top = sc._parse_stats(ev.get("pgdata_stats"))
        self.pgdata_bad = sc._lines(ev.get("pgdata_violations"))
        self.log_stats = sc._parse_stats(ev.get("log_stats"))
        self.file_stats = sc._parse_stats(ev.get("file_stats"))
        self.install_stats = sc._parse_stats(ev.get("install_stats"))
        self.install_bad = sc._lines(ev.get("install_violations"))
        self.counts = dict((l.split("|", 1)[0], sc._int(l.split("|", 1)[1], 0)) for l in sc._lines(ev.get("log_counts"))
                           if "|" in l)
        self.latest_log = ev.get("latest_log") or ""

    # -- settings -----------------------------------------------------------
    def get(self, name):
        return str(self.S.get(name, DEFAULTS.get(name, "")) if self.S else "")

    def need_settings(self):
        if not self.S:
            return (NR, "PostgreSQL settings could not be read (server not running or not reachable with psql, and "
                        "postgresql.conf was not found).", [])
        return None

    def setting_ev(self, *names):
        return ["%s = %s" % (n, self.get(n) if self.get(n) != "" else "''") for n in names] + \
               ["(settings source: %s)" % self.source]

    # -- pgaudit / logging ----------------------------------------------------
    def pgaudit_loaded(self):
        return "pgaudit" in _csv(self.get("shared_preload_libraries"))

    def pgaudit(self, classes=(), catalog=False):
        issues = []
        if not self.pgaudit_loaded():
            issues.append("pgaudit is not in shared_preload_libraries.")
        have = _pgaudit_classes(self.get("pgaudit.log"))
        missing = [c for c in classes if c not in have]
        if missing:
            issues.append("pgaudit.log (%s) does not include: %s." % (self.get("pgaudit.log") or "none", ", ".join(missing)))
        if catalog and not _on(self.get("pgaudit.log_catalog")):
            issues.append("pgaudit.log_catalog is off.")
        return issues, self.setting_ev("shared_preload_libraries", "pgaudit.log", "pgaudit.log_catalog")

    def logging(self):
        """Is logging enabled such that errors, denials and connection failures are recorded?"""
        issues = []
        dest = _csv(self.get("log_destination"))
        file_dest = [d for d in dest if d in ("stderr", "csvlog", "jsonlog")]
        if "syslog" not in dest and not (file_dest and _on(self.get("logging_collector"))):
            issues.append("Logging is not enabled: log_destination=%s with logging_collector=%s." %
                          (self.get("log_destination"), self.get("logging_collector")))
        if self.get("log_min_messages").lower() not in OK_LEVELS:
            issues.append("log_min_messages=%s suppresses ERROR messages." % self.get("log_min_messages"))
        if self.get("log_min_error_statement").lower() not in OK_LEVELS:
            issues.append("log_min_error_statement=%s does not log the failing statement." %
                          self.get("log_min_error_statement"))
        return issues, self.setting_ev("log_destination", "logging_collector", "log_directory",
                                       "log_min_messages", "log_min_error_statement")

    def log_evidence(self):
        if not self.counts:
            return []
        return ["latest log %s: %s" % (self.latest_log, ", ".join("%s=%s" % kv for kv in sorted(self.counts.items())))]

    def prefix(self, tokens):
        p = self.get("log_line_prefix")
        missing = [t for t in tokens if t not in p]
        return (["log_line_prefix '%s' does not contain %s." % (p, " ".join(missing))] if missing else []), \
            ["log_line_prefix = '%s'" % p]

    def conn(self, connections=True, disconnections=True):
        issues = []
        if connections and not _on(self.get("log_connections")):
            issues.append("log_connections is off.")
        if disconnections and not _on(self.get("log_disconnections")):
            issues.append("log_disconnections is off.")
        return issues, self.setting_ev("log_connections", "log_disconnections")

    def log_perms(self, check_owner=True):
        """log_file_mode 0600 and the log files match it."""
        issues, ev = [], ["log_file_mode = %s" % self.get("log_file_mode"), "log directory: %s" % self.paths.get("log_dir")]
        if sc._int(self.get("log_file_mode"), None) is not None and int(self.get("log_file_mode"), 8) != 0o600:
            issues.append("log_file_mode is %s, not 0600." % self.get("log_file_mode"))
        files = [st for st in self.log_stats.values() if st["type"] == "f"]
        for st in sorted(files, key=lambda x: x["path"])[:40]:
            ev.append(sc._fmt_stat(st))
        bad_mode = [st["path"] for st in files if (sc._mode(st) or 0) & 0o177]
        bad_owner = [st["path"] for st in files if st["owner"] != self.pg_user]
        if bad_mode:
            issues.append("%d log file(s) are not 0600, e.g. %s" % (len(bad_mode), ", ".join(bad_mode[:5])))
        if check_owner and bad_owner:
            issues.append("%d log file(s) are not owned by %s, e.g. %s" % (len(bad_owner), self.pg_user, ", ".join(bad_owner[:5])))
        return issues, ev

    # -- roles / files --------------------------------------------------------
    def superusers(self):
        return sorted(r["name"] for r in self.roles if r.get("super"))

    def unapproved_superusers(self):
        approved = self.s.get("approved_superusers") or [self.pg_user]
        return [r for r in self.superusers() if r not in approved]

    def roles_ev(self):
        out = []
        for r in self.roles:
            attrs = [a for a, k in (("Superuser", "super"), ("Create role", "createrole"), ("Create DB", "createdb"),
                                    ("Replication", "replication"), ("Bypass RLS", "bypassrls")) if r.get(k)]
            out.append("role %s%s: %s connlimit=%s" % (r["name"], "" if r.get("login") else " (nologin)",
                                                       ", ".join(attrs) or "-", r.get("connlimit")))
        return out or ["roles not read (no SQL access)"]

    def hba_ev(self):
        return ["%s line %s: %s %s %s %s %s %s" % (self.hba_source, r.get("line"), r.get("type"),
                                                  ",".join(r.get("database") or []), ",".join(r.get("user") or []),
                                                  r.get("address") or "", r.get("method"), " ".join(r.get("options") or []))
                for r in self.hba]

    def pgdata_issues(self, others_only=False):
        """Ownership/permission problems in PGDATA ('find' violations: not owned by the db owner or group/other bits)."""
        issues = []
        top = self.pgdata_top.get(self.pgdata)
        if top:
            if top["owner"] != self.pg_user or top["group"] != self.pg_user:
                issues.append("PGDATA %s is owned by %s:%s." % (self.pgdata, top["owner"], top["group"]))
        bad = sc._parse_stats(self.pgdata_bad)
        for path, st in sorted(bad.items()):
            m = sc._mode(st) or 0
            if st["owner"] != self.pg_user:
                issues.append("%s is owned by %s." % (path, st["owner"]))
            elif (m & 0o007) or (not others_only and m & 0o070):
                issues.append("%s mode %s grants access beyond the owner." % (path, st["mode"]))
        return sc._cap(issues), [sc._fmt_stat(st) for st in sorted(self.pgdata_top.values(), key=lambda x: x["path"])[:40]]

    def install_issues(self, root_group=True):
        issues = []
        for path, st in sorted(sc._parse_stats(self.install_bad).items()):
            m = sc._mode(st) or 0
            if st["owner"] != "root" or (root_group and st["group"] != "root"):
                issues.append("%s is owned by %s:%s (must be root:root)." % (path, st["owner"], st["group"]))
            if m & 0o022:
                issues.append("%s mode %s is group/world writable." % (path, st["mode"]))
        return sc._cap(issues), [sc._fmt_stat(st) for st in sorted(self.install_stats.values(), key=lambda x: x["path"])]

    def extensions(self):
        out = {}
        for d in self.dbs:
            for e in d.get("extensions") or []:
                if e.get("name") != "plpgsql":
                    out.setdefault(e["name"], []).append(d.get("db"))
        return out

    def ssl(self):
        return _on(self.get("ssl"))


# ---------------------------------------------------------------------------
# rule handlers: each returns (status, details, evidence[, comments])
# ---------------------------------------------------------------------------
def _v(issues, ok, ev, comments=""):
    return (OPEN if issues else NF), (issues or ok), ev, comments


def _settings_rule(fn):
    def wrapper(c, *a, **kw):
        return c.need_settings() or fn(c, *a, **kw)
    return wrapper


@_settings_rule
def h_pgaudit(c, classes=(), catalog=False, test=False, na_unless=None):
    if na_unless and c.s.get(na_unless) is False:
        return NA, "Category tracking is not required (postgres_stig_%s: false)." % na_unless, []
    issues, ev = c.pgaudit(classes, catalog)
    if not classes and c.pgaudit_loaded() and _pgaudit_classes(c.get("pgaudit.log")) == set():
        issues.append("pgaudit is loaded but pgaudit.log is 'none'; no session audit classes are logged.")
    ok = "pgaudit is loaded and logs %s." % (", ".join(classes) if classes else c.get("pgaudit.log"))
    return _v(issues, ok, ev + c.log_evidence(), TEST_NOTE if test else "")


@_settings_rule
def h_denials(c, pgaudit=False, conf_perms=False):
    issues, ev = c.logging()
    if pgaudit:
        i2, e2 = c.pgaudit()
        issues += i2
        ev += e2
    if conf_perms:
        i3, e3 = _conf_perm_issues(c, mode_mask=0o077)
        issues += i3
        ev += e3
    return _v(issues, "Logging is enabled, so errors and denials are recorded.", ev + c.log_evidence(), TEST_NOTE)


@_settings_rule
def h_prefix(c, tokens, pgaudit=False, conn=False):
    issues, ev = c.prefix(tokens)
    if pgaudit:
        issues += c.pgaudit()[0]
        ev += c.setting_ev("shared_preload_libraries")
    if conn:
        i2, e2 = c.conn()
        issues += i2
        ev += e2
    return _v(issues, "log_line_prefix contains %s." % " ".join(tokens), ev)


@_settings_rule
def h_source(c):
    issues, ev = [], c.setting_ev("log_line_prefix", "log_hostname")
    if "%r" not in c.get("log_line_prefix") and "%h" not in c.get("log_line_prefix"):
        issues.append("log_line_prefix records no client host (%r or %h).")
    return _v(issues, "The client host and port are recorded with each event.", ev,
              "Confirm the recorded source information meets the organization's needs.")


@_settings_rule
def h_conn(c, connections=True, disconnections=True, logging=False, pgaudit=False, tokens=()):
    issues, ev = c.conn(connections, disconnections)
    if logging:
        i2, e2 = c.logging()
        issues += i2
        ev += e2
    if pgaudit:
        issues += c.pgaudit()[0]
        ev += c.setting_ev("shared_preload_libraries")
    if tokens:
        i3, e3 = c.prefix(tokens)
        issues += i3
        ev += e3
    return _v(issues, "Connections%s are logged." % (" and disconnections" if disconnections else ""),
              ev + c.log_evidence())


@_settings_rule
def h_session_start(c):
    issues, ev = c.pgaudit()
    dest = _csv(c.get("log_destination"))
    if "stderr" not in dest and "syslog" not in dest:
        issues.append("log_destination (%s) includes neither stderr nor syslog." % c.get("log_destination"))
    return _v(issues, "pgaudit is preloaded and logs go to %s." % c.get("log_destination"), ev + c.setting_ev("log_destination"))


@_settings_rule
def h_logperms(c, owner=True, client_min=False):
    dest = _csv(c.get("log_destination"))
    if not any(d in ("stderr", "csvlog", "jsonlog") for d in dest):
        return NR, "PostgreSQL logs only to %s; verify the syslog files are owned by root with 0600 permissions." %             c.get("log_destination"), c.setting_ev("log_destination", "logging_collector")
    issues, ev = c.log_perms(owner)
    if client_min and c.get("client_min_messages").lower() != "error":
        issues.append("client_min_messages is %s, not error." % c.get("client_min_messages"))
    if not _on(c.get("logging_collector")):
        ev.append("logging_collector is off, so stderr is not written to log files (see the logging rules).")
    elif not c.log_stats:
        issues.append("No log files were found in %s." % c.paths.get("log_dir"))
    return _v(issues, "Log files are owned by %s with mode 0600." % c.pg_user, ev)


@_settings_rule
def h_client_min(c):
    v = c.get("client_min_messages").lower()
    return _v([] if v == "error" else ["client_min_messages is %s, not error." % v],
              "client_min_messages = error.", c.setting_ev("client_min_messages"))


@_settings_rule
def h_ssl(c, classified=False):
    if classified and c.s.get("classified") is False:
        return NA, "PostgreSQL is deployed in an unclassified environment (postgres_stig_classified: false).", []
    issues = [] if c.ssl() else ["ssl is off."]
    comments = "Also confirm the server is protected by NSA-approved encrypting devices." if classified else ""
    if classified and not issues:
        return NR, "ssl is on; verify NSA-approved cryptography protects classified data.", c.setting_ev("ssl"), comments
    return _v(issues, "ssl is on.", c.setting_ev("ssl", "ssl_min_protocol_version"), comments)


def h_fips(c, openssl=False):
    fips = str(c.host.get("fips_enabled", "")).strip()
    issues = [] if fips == "1" else ["Kernel FIPS mode is not enabled (fips_enabled=%s)." % (fips or "?")]
    ev = ["fips_enabled=%s" % (fips or "?"), "crypto-policy=%s" % c.host.get("crypto_policy", "?")]
    if openssl:
        text = str(c.ev.get("openssl") or "")
        ev += ["openssl: %s" % l for l in sc._lines(text)[:12]]
        fips_provider = re.search(r"(?ims)^\s*fips\s*$.*?status:\s*active", text) or re.search(r"FIPS", text.split("\n")[0])
        if text and not fips_provider:
            issues.append("OpenSSL does not report an active FIPS provider/module.")
        if not text:
            issues.append("The OpenSSL version/providers could not be read.")
    if fips == "":
        return NR, "FIPS status could not be read.", ev
    return _v(issues, "FIPS mode is enabled%s." % (" and OpenSSL uses its FIPS provider" if openssl else ""), ev)


def h_pgdata(c, superusers=False, log_dir=False, pgaudit_files=False, install=False, others_only=False):
    if not c.pgdata_top:
        return NR, "PGDATA (%s) could not be read; run the audit with become: true." % (c.pgdata or "?"), []
    issues, ev = c.pgdata_issues(others_only)
    if log_dir:
        ld = c.log_stats.get(c.paths.get("log_dir", "").rstrip("/"))
        if ld:
            ev.append(sc._fmt_stat(ld))
            if ld["owner"] != c.pg_user:
                issues.append("The log directory %s is owned by %s." % (ld["path"], ld["owner"]))
    if pgaudit_files:
        pa = [st for p, st in c.install_stats.items() if "pgaudit" in os.path.basename(p)]
        ev += [sc._fmt_stat(st) for st in pa]
        issues += ["%s is owned by %s (must be root)." % (st["path"], st["owner"]) for st in pa if st["owner"] != "root"]
        if not pa:
            issues.append("pgaudit is not installed under %s/share/extension." % c.install)
    if install:
        i2, e2 = c.install_issues()
        issues += i2
        ev += e2
    if superusers:
        if not c.roles:
            return NR, "Roles could not be read (no SQL access); review superusers manually.", ev
        bad = c.unapproved_superusers()
        if bad:
            issues.append("Roles with SUPERUSER that are not approved: %s" % ", ".join(bad))
        ev.append("superusers: %s" % ", ".join(c.superusers()))
    return _v(issues, "Files are owned by %s and restricted%s." % (c.pg_user, "; superusers are approved" if superusers else ""), ev)


def _conf_perm_issues(c, mode_mask=0o177):
    issues, ev = [], []
    path = c.paths.get("config_file")
    st = c.file_stats.get(path)
    if not st:
        return ["%s could not be read." % path], ev
    ev.append(sc._fmt_stat(st))
    if st["owner"] != c.pg_user:
        issues.append("%s is owned by %s." % (path, st["owner"]))
    if (sc._mode(st) or 0) & mode_mask:
        issues.append("%s mode %s (must be 0600)." % (path, st["mode"]))
    return issues, ev


@_settings_rule
def h_conf_perms(c):
    issues, ev = _conf_perm_issues(c)
    if int(c.get("log_file_mode") or "0600", 8) != 0o600:
        issues.append("log_file_mode is %s, not 0600." % c.get("log_file_mode"))
    return _v(issues, "postgresql.conf is owned by %s with mode 0600 and logs are created 0600." % c.pg_user,
              ev + c.setting_ev("log_file_mode"))


def h_modify(c):
    """Files in PGDATA owned by the db owner and not writable by others; software owned by root, not writable."""
    if not c.install_stats and not c.pgdata_top:
        return NR, "Neither %s nor PGDATA could be read." % c.install, []
    issues, ev = c.install_issues(root_group=False)
    for path, st in sorted(sc._parse_stats(c.pgdata_bad).items()):
        if st["owner"] != c.pg_user:
            issues.append("%s is owned by %s." % (path, st["owner"]))
        elif (sc._mode(st) or 0) & 0o022:
            issues.append("%s mode %s is group/world writable." % (path, st["mode"]))
    return _v(sc._cap(issues), "PostgreSQL software is owned by root and PGDATA by %s; neither is writable by others."
              % c.pg_user, ev)


def h_software_dir(c):
    lines = sc._lines(c.ev.get("install_owners"))
    if not lines:
        return NR, "Ownership of the files in %s could not be determined." % c.install, []
    unowned = [l for l in lines if "not owned by any package" in l]
    owners = [l.split()[-1] for l in lines if "not owned" not in l]
    other = sorted(set(o for o in owners if not re.search(r"postgres|pgaudit|pgsql|pg\d|crunchy|set_user|pgbackrest|postgis|timescale", o, re.I)))
    issues = []
    if other:
        issues.append("Files in %s belong to non-PostgreSQL packages: %s" % (c.install, ", ".join(other)))
    if unowned:
        issues.append("%d file(s) in %s are not owned by any package, e.g. %s" %
                      (len(unowned), c.install, ", ".join(l.replace("file ", "").replace(" is not owned by any package", "") for l in unowned[:5])))
    return _v(issues, "%s holds only files from PostgreSQL packages." % c.install, lines[:40])


def h_connlimit(c):
    if not c.roles:
        return NR, "Roles could not be read (no SQL access).", []
    issues, ev = [], c.setting_ev("max_connections")
    unlimited = [r["name"] for r in c.roles if r.get("login") and sc._int(r.get("connlimit"), -1) == -1]
    if unlimited:
        issues.append("Login roles with unlimited connections (rolconnlimit = -1): %s" % ", ".join(unlimited))
    limit = c.s.get("max_connections")
    if limit and sc._int(c.get("max_connections"), 0) > sc._int(limit, 0):
        issues.append("max_connections is %s (documented maximum %s)." % (c.get("max_connections"), limit))
    ev += ["%s connlimit=%s" % (r["name"], r.get("connlimit")) for r in c.roles if r.get("login")]
    if issues:
        return OPEN, issues, ev
    if limit:
        return NF, "Every login role has a connection limit and max_connections is within the documented maximum.", ev
    return NR, "Every login role has a connection limit; compare max_connections and the limits with the documented "\
               "values (or set postgres_stig_max_connections).", ev


def _hba_exempt(c, r):
    text = "%s %s %s %s %s" % (r.get("type"), ",".join(r.get("database") or []), ",".join(r.get("user") or []),
                               r.get("address") or "", r.get("method"))
    return any(re.search(p, text) for p in c.s.get("hba_exceptions") or [])


def h_hba_external(c):
    if not c.hba:
        return NR, "pg_hba.conf could not be read.", []
    other = [r for r in c.hba if r.get("method") not in EXTERNAL_AUTH and not _hba_exempt(c, r)]
    issues = ["pg_hba.conf line %s uses '%s' (%s %s %s), not gss/sspi/ldap/cert." %
              (r.get("line"), r.get("method"), r.get("type"), ",".join(r.get("database") or []), ",".join(r.get("user") or []))
              for r in other]
    return _v(sc._cap(issues), "All pg_hba.conf entries use organization-level authentication (gss, sspi, ldap, cert) "
              "or are documented exceptions.", c.hba_ev(),
              "Document approved exceptions (e.g. local peer for the postgres account) with postgres_stig_hba_exceptions."
              if issues else "")


def h_hba_weak(c):
    if not c.hba:
        return NR, "pg_hba.conf could not be read.", []
    bad = [r for r in c.hba if r.get("method") in ("password", "md5")]
    return _v(["pg_hba.conf line %s uses '%s'." % (r.get("line"), r.get("method")) for r in bad],
              "No pg_hba.conf entry uses password or md5.", c.hba_ev())


def h_unique_auth(c):
    if not c.hba:
        return NR, "pg_hba.conf could not be read.", c.roles_ev()
    trust = [r for r in c.hba if r.get("method") == "trust"]
    if trust:
        return OPEN, ["pg_hba.conf line %s uses 'trust' (no authentication)." % r.get("line") for r in trust], c.hba_ev()
    return NR, "No entry uses 'trust'. Verify every role belongs to one individual or service and that shared "\
               "accounts are reached only after individual authentication.", c.roles_ev() + c.hba_ev()


@_settings_rule
def h_password_hash(c):
    issues, ev = [], c.setting_ev("password_encryption")
    if c.get("password_encryption").lower() != "scram-sha-256":
        issues.append("password_encryption is %s, not scram-sha-256." % c.get("password_encryption"))
    weak = [p["name"] for p in c.passwords if p.get("kind") in ("md5", "plaintext")]
    if weak:
        issues.append("Roles with passwords not stored as SCRAM-SHA-256: %s" % ", ".join(weak))
    ev += ["%s: %s" % (p["name"], p.get("kind")) for p in c.passwords]
    if not c.passwords and c.source != "live":
        ev.append("Stored passwords could not be inspected (no SQL access).")
    return _v(issues, "Passwords are stored as salted SCRAM-SHA-256 hashes.", ev)


@_settings_rule
def h_crl_cert(c):
    issues, ev = [], c.setting_ev("ssl", "ssl_crl_file")
    crl = c.paths.get("ssl_crl_file")
    if not c.get("ssl_crl_file"):
        issues.append("ssl_crl_file is not set.")
    elif not c.file_stats.get(crl):
        issues.append("The CRL file %s does not exist." % crl)
    ssl_rules = [r for r in c.hba if r.get("type") == "hostssl"]
    good = [r for r in ssl_rules if r.get("method") == "cert" and
            any(o in ("clientcert=verify-ca", "clientcert=verify-full") for o in r.get("options") or [])]
    if not good:
        issues.append("No hostssl entry uses cert authentication with clientcert=verify-ca.")
    return _v(issues, "A CRL is configured and hostssl entries validate client certificates.", ev + c.hba_ev())


@_settings_rule
def h_ssl_key(c):
    key = c.paths.get("ssl_key_file")
    if not c.ssl():
        return NA, "SSL is off; no private key is in use (see CD16-00-004900).", c.setting_ev("ssl")
    st = c.file_stats.get(key)
    if not st:
        return OPEN, "The SSL private key %s was not found." % key, c.setting_ev("ssl_key_file")
    issues, ev = [], [sc._fmt_stat(st)]
    if st["owner"] not in (c.pg_user, "root"):
        issues.append("%s is owned by %s." % (key, st["owner"]))
    if (sc._mode(st) or 0) & 0o077:
        issues.append("%s mode %s allows group/other access." % (key, st["mode"]))
    d = c.file_stats.get(os.path.dirname(key))
    if d:
        ev.append(sc._fmt_stat(d))
        if (sc._mode(d) or 0) & 0o022:
            issues.append("The key directory %s is group/world writable." % d["path"])
    return _v(issues, "The private key is readable only by its owner.", ev)


def h_ident(c):
    cert = [r for r in c.hba if r.get("method") == "cert" or
            any(o.startswith("clientcert=") for o in r.get("options") or [])]
    if not c.hba:
        return NR, "pg_hba.conf could not be read.", []
    if not cert:
        return NA, "PKI (certificate) authentication is not used.", c.hba_ev()
    maps = ["map %s: %s -> %s" % (m.get("map"), m.get("system"), m.get("user")) for m in c.ident]
    return NR, "Certificate authentication is used. Verify each certificate CN matches its role or is mapped in "\
               "pg_ident.conf.", c.hba_ev() + (maps or ["pg_ident.conf has no mappings"])


@_settings_rule
def h_admin_attrs(c):
    if not c.roles:
        return NR, "Roles could not be read (no SQL access).", []
    admins = c.s.get("approved_admins") or [c.pg_user]
    bad = []
    for r in c.roles:
        if r["name"] in admins:
            continue
        attrs = [a for a, k in (("Superuser", "super"), ("Create role", "createrole"), ("Create DB", "createdb"),
                                ("Bypass RLS", "bypassrls")) if r.get(k)]
        if attrs:
            bad.append("%s has %s" % (r["name"], ", ".join(attrs)))
    return _v(["Non-administrative role %s." % b for b in bad],
              "Only approved administrative roles (%s) have administrative attributes." % ", ".join(admins), c.roles_ev())


def h_keepalives(c):
    if not c.S:
        return c.need_settings()
    vals = {}
    for k in ("tcp_keepalives_idle", "tcp_keepalives_interval", "tcp_keepalives_count", "statement_timeout"):
        v = c.file_settings.get(k) if k.startswith("tcp_") else c.get(k)
        vals[k] = v if v not in (None, "") else "0"
    zero = [k for k, v in vals.items() if re.match(r"^0\D*$", str(v).strip())]
    return _v(["%s is 0 (not set)." % k for k in sorted(zero)], "Keepalives and statement_timeout are set.",
              ["%s = %s" % kv for kv in sorted(vals.items())] + ["(tcp_keepalives_* read from the configuration files, "
                                                                 "because a Unix-socket session always shows 0)"])


def h_extensions(c, superusers=False):
    if not c.dbs:
        return NR, "Extensions could not be read (no SQL access).", []
    exts = c.extensions()
    approved = c.s.get("approved_extensions") or []
    ev = ["%s (%s)" % (n, ", ".join(sorted(set(dbs)))) for n, dbs in sorted(exts.items())] or ["no extensions besides plpgsql"]
    issues = []
    if superusers and c.roles:
        bad = c.unapproved_superusers()
        if bad:
            issues.append("Roles with SUPERUSER that are not approved: %s" % ", ".join(bad))
        ev.append("superusers: %s" % ", ".join(c.superusers()))
    if approved:
        extra = sorted(n for n in exts if n not in approved)
        if extra:
            issues.append("Extensions not in the approved list: %s" % ", ".join(extra))
    if issues:
        return OPEN, issues, ev
    if approved or not exts:
        return NF, "Only approved extensions are installed.", ev
    return NR, "Compare the installed extensions with the approved list (or set postgres_stig_approved_extensions).", ev


def h_packages(c, multiple=False):
    pk = sc._lines(c.ev.get("packages"))
    if not pk:
        return NR, "No PostgreSQL packages were found with rpm.", []
    if multiple:
        majors = sorted(set(m.group(1) for p in pk for m in [re.match(r"^postgresql(\d+)", p)] if m))
        if len(majors) > 1:
            return OPEN, "Packages for several PostgreSQL major versions are installed: %s. Remove the unused ones." % \
                ", ".join(majors), pk
        return NF, "Only one PostgreSQL major version is installed.", pk
    approved = c.s.get("approved_packages") or []
    names = [p.split("|")[0] for p in pk]
    if approved:
        extra = [n for n in names if n not in approved]
        return _v(["Packages not in the approved list: %s" % ", ".join(extra)] if extra else [],
                  "Only approved PostgreSQL packages are installed.", pk)
    return NR, "Review the installed PostgreSQL packages for need (or set postgres_stig_approved_packages).", pk


def h_updates(c):
    version = c.ev.get("version") or ""
    st, details, ev = sc.eval_updates(version, c.s.get("min_version"), c.host.get("repo_updates"), "PostgreSQL")
    ev.append("PostgreSQL 16 is supported by the PostgreSQL community until November 2028.")
    return st, details, ev


@_settings_rule
def h_ports(c, listen=True):
    approved = [sc._int(p) for p in c.s.get("approved_ports") or []]
    port = sc._int(c.get("port"))
    ev = c.setting_ev("port", "listen_addresses") if listen else c.setting_ev("port")
    if not approved:
        return NR, "Compare port %s%s with the PPSM CAL (or set postgres_stig_approved_ports)." % \
            (port, " and listen_addresses '%s'" % c.get("listen_addresses") if listen else ""), ev
    return _v([] if port in approved else ["Port %s is not an approved port (%s)." % (port, ", ".join(map(str, approved)))],
              "PostgreSQL uses approved port %s." % port, ev)


def h_untrusted_pl(c):
    if not c.dbs:
        return NR, "Languages could not be read (no SQL access).", []
    langs = {}
    for d in c.dbs:
        for l in d.get("untrusted_languages") or []:
            langs.setdefault(l, []).append(d.get("db"))
    approved = c.s.get("approved_extensions") or []
    bad = sorted(l for l in langs if l not in approved)
    ev = ["%s in %s" % (l, ", ".join(dbs)) for l, dbs in sorted(langs.items())] or ["no untrusted procedural languages"]
    if bad:
        return OPEN, "Untrusted procedural languages are installed without approval: %s" % ", ".join(bad), ev
    return NR, "No unapproved untrusted procedural language is installed. Verify privileged functionality is protected "\
               "as documented.", ev


def h_secdef(c):
    if not c.dbs:
        return NR, "Functions could not be read (no SQL access).", []
    fns = ["%s: %s" % (d.get("db"), f) for d in c.dbs for f in d.get("secdef") or []]
    approved = c.s.get("approved_security_definer") or []
    if not fns:
        return NF, "No SECURITY DEFINER functions exist outside the system schemas.", []
    extra = [f for f in fns if not any(re.search(p, f) for p in approved)]
    if approved and not extra:
        return NF, "All SECURITY DEFINER functions are approved.", fns
    return NR, "%d SECURITY DEFINER function(s) found; verify each is documented and approved (or list them in "\
               "postgres_stig_approved_security_definer)." % len(extra), fns[:60]


def h_public_create(c, superusers=False):
    if not c.dbs:
        return NR, "Schema privileges could not be read (no SQL access).", []
    issues, ev = [], []
    for d in c.dbs:
        for sch in d.get("schemas") or []:
            ev.append("%s.%s owner=%s acl=%s" % (d.get("db"), sch.get("name"), sch.get("owner"), sch.get("acl") or "(default)"))
            if sch.get("public_create"):
                issues.append("PUBLIC can CREATE in schema %s.%s." % (d.get("db"), sch.get("name")))
    if superusers and c.roles:
        bad = c.unapproved_superusers()
        if bad:
            issues.append("Roles with SUPERUSER that are not approved: %s" % ", ".join(bad))
        ev.append("superusers: %s" % ", ".join(c.superusers()))
    for db in c.sql.get("databases") or []:
        ev.append("database %s acl=%s" % (db.get("name"), db.get("acl") or "(default)"))
    if issues:
        return OPEN, sc._cap(issues), ev
    return NR, "PUBLIC cannot create objects in any schema. Verify the remaining CREATE grants are documented and "\
               "approved.", ev


def h_owners(c):
    if not c.dbs:
        return NR, "Object owners could not be read (no SQL access).", []
    owners = sorted(set(o for d in c.dbs for k in ("object_owners", "function_owners") for o in d.get(k) or []))
    ev = ["object owners: %s" % (", ".join(owners) or "none")] + \
         ["%s schemas: %s" % (d.get("db"), ", ".join("%s(%s)" % (s.get("name"), s.get("owner")) for s in d.get("schemas") or []))
          for d in c.dbs]
    approved = c.s.get("approved_owners") or []
    if approved:
        bad = [o for o in owners if o not in approved]
        return _v(["Objects are owned by roles not authorized for ownership: %s" % ", ".join(bad)] if bad else [],
                  "All objects are owned by authorized roles.", ev)
    return NR, "Compare the object owners with the roles authorized to own objects (or set postgres_stig_approved_owners).", ev


@_settings_rule
def h_syslog(c, facility=False):
    issues, ev = [], c.setting_ev("log_destination", "syslog_facility", "syslog_ident")
    if "syslog" not in _csv(c.get("log_destination")):
        issues.append("log_destination (%s) does not include syslog." % c.get("log_destination"))
    want = c.s.get("syslog_facility")
    if facility and want and c.get("syslog_facility").lower() != str(want).lower():
        issues.append("syslog_facility is %s (expected %s)." % (c.get("syslog_facility"), want))
    rs = sc._lines(c.host.get("rsyslog"))
    fwd = [l for l in rs if re.search(r"(^|\s)@@?[\w\[]|omfwd|omrelp", l)]
    ev.append("rsyslog forwarding: %s" % (" | ".join(fwd) or "none"))
    if facility and not issues and not fwd:
        issues.append("PostgreSQL logs to syslog, but rsyslog forwards nothing to a central log server.")
    return _v(issues, "Audit records go to syslog%s." % (" and are forwarded to the central log server" if facility else ""), ev)


@_settings_rule
def h_timezone(c):
    want = c.s.get("log_timezone") or "UTC"
    v = c.get("log_timezone")
    return _v([] if v.lower() == str(want).lower() else ["log_timezone is %s (expected %s)." % (v, want)],
              "log_timezone = %s." % v, c.setting_ev("log_timezone"))


@_settings_rule
def h_dod_cert(c):
    if not c.ssl():
        return OPEN, "ssl is off; no DoD certificate is in use.", c.setting_ev("ssl")
    cert = str(c.ev.get("cert_info") or "")
    ev = c.setting_ev("ssl_cert_file", "ssl_ca_file") + sc._lines(cert)[:20]
    if not cert:
        return NR, "The server certificate could not be read; verify it and the CA file are DoD-issued.", ev
    rx = c.s.get("dod_issuer_regex") or r"O\s*=\s*U\.S\. Government.*OU\s*=\s*DoD"
    issuer = next((l for l in sc._lines(cert) if l.lower().startswith("issuer")), "")
    if not re.search(rx, issuer):
        return OPEN, "The server certificate is not issued by a DoD CA (%s)." % issuer, ev
    return NF, "The server certificate is issued by a DoD CA.", ev, "Verify ssl_ca_file contains only DoD CAs."


def h_labels(c, key="security_labeling_required"):
    want = c.s.get(key)
    rls = ["%s: %s table(s) with row-level security" % (d.get("db"), d.get("rls_tables")) for d in c.dbs]
    if want is False:
        return NF, "Security labeling is not required (postgres_stig_%s: false)." % key, rls
    return NR, "Verify the required security labels are enforced with row-level security policies as documented.", rls


def h_manual(c, text, evidence=None):
    ev = []
    for e in evidence or []:
        if e == "roles":
            ev += c.roles_ev()
        elif e == "hba":
            ev += c.hba_ev()
        elif e == "disk":
            ev += sc._lines(c.host.get("disk"))
        elif e == "account":
            a = (c.host.get("accounts") or {}).get(c.pg_user) or {}
            ev += ["passwd: %s" % a.get("passwd", "?"), "id: %s" % a.get("id", "?")] + \
                  (["sudo: %s" % " | ".join(sc._lines(a.get("sudo"))[-5:])] if a.get("sudo") else [])
        elif e == "pgcrypto":
            ev.append("pgcrypto available: %s" % c.sql.get("pgcrypto_available", "unknown"))
        elif e == "rotation" and c.S:
            ev += c.setting_ev("log_rotation_age", "log_rotation_size", "log_truncate_on_rotation", "log_filename")
        elif e == "timeouts" and c.S:
            ev += c.setting_ev("idle_session_timeout", "idle_in_transaction_session_timeout")
    return NR, text, ev


def _audit_rule(classes, catalog=False, test=False, na_unless=None):
    return lambda c: h_pgaudit(c, classes, catalog, test, na_unless)


FOUR = ("role", "read", "write", "ddl")
RULES = {
    "CD16-00-000100": h_connlimit,
    "CD16-00-000200": h_hba_external,
    "CD16-00-000300": lambda c: h_manual(c, "Compare role privileges (\\du, \\dp) and pg_hba.conf entries with the "
                                            "documented permissions for each group role.", ["roles", "hba"]),
    "CD16-00-000400": lambda c: h_prefix(c, ("%m", "%a", "%u", "%d", "%r", "%p"), pgaudit=True),
    "CD16-00-000500": _audit_rule((), test=True),
    "CD16-00-000600": lambda c: h_pgdata(c, superusers=True),
    "CD16-00-000700": _audit_rule(("read",), catalog=True, test=True),
    "CD16-00-000800": h_denials,
    "CD16-00-000900": h_session_start,
    "CD16-00-001000": lambda c: h_conn(c, tokens=()),
    "CD16-00-001100": lambda c: h_prefix(c, ("%m",)),
    "CD16-00-001200": lambda c: h_prefix(c, ("%m", "%u", "%d", "%s")),
    "CD16-00-001300": h_source,
    "CD16-00-001400": lambda c: h_denials(c, pgaudit=True),
    "CD16-00-001500": lambda c: h_prefix(c, ("%m", "%u", "%d", "%p", "%r", "%a")),
    "CD16-00-001600": lambda c: h_manual(c, "Verify the organization-defined additional audit information is configured "
                                            "and present in the audit records."),
    "CD16-00-001700": lambda c: h_manual(c, "Verify procedures exist and are followed for monitoring audit space and "
                                            "off-loading audit records (Not_Applicable if availability takes precedence).",
                                         ["disk"]),
    "CD16-00-001800": lambda c: h_manual(c, "Verify the log volume is monitored and rotation removes or overwrites the "
                                            "oldest logs (Not_Applicable if availability takes precedence).",
                                         ["disk", "rotation"]),
    "CD16-00-002000": h_logperms,
    "CD16-00-002100": h_logperms,
    "CD16-00-002200": h_logperms,
    "CD16-00-002300": lambda c: h_pgdata(c, superusers=True, log_dir=True, pgaudit_files=True),
    "CD16-00-002400": h_conf_perms,
    "CD16-00-002500": lambda c: h_pgdata(c, install=True, others_only=True),
    "CD16-00-002600": h_modify,
    "CD16-00-002700": lambda c: h_manual(c, "Verify access to the PostgreSQL installation account is restricted to the "
                                            "minimum personnel and its use is tracked.", ["account"]),
    "CD16-00-002800": h_software_dir,
    "CD16-00-002900": h_owners,
    "CD16-00-003000": lambda c: h_manual(c, "Verify object privileges (\\dp *.*) match the documentation; PGDATA "
                                            "permissions are evaluated in CD16-00-005600.", ["roles"]),
    "CD16-00-003200": h_extensions,
    "CD16-00-003300": h_packages,
    "CD16-00-003400": lambda c: h_extensions(c, superusers=True),
    "CD16-00-003500": h_ports,
    "CD16-00-003600": h_unique_auth,
    "CD16-00-003800": h_password_hash,
    "CD16-00-003900": h_hba_weak,
    "CD16-00-004000": h_crl_cert,
    "CD16-00-004100": h_ssl_key,
    "CD16-00-004200": h_ident,
    "CD16-00-004400": lambda c: h_fips(c, openssl=True),
    "CD16-00-004500": lambda c: h_manual(c, "Verify non-organizational users are uniquely identified by their roles "
                                            "per the documentation.", ["roles"]),
    "CD16-00-004600": h_admin_attrs,
    "CD16-00-004700": h_keepalives,
    "CD16-00-004900": h_ssl,
    "CD16-00-005200": lambda c: h_manual(c, "Verify data at rest is encrypted where the AO requires it (pgcrypto or "
                                            "disk/filesystem encryption).", ["pgcrypto"]),
    "CD16-00-005300": lambda c: h_manual(c, "Verify security objects are kept in separate schemas and only DBAs have "
                                            "undocumented access to pg_catalog/information_schema."),
    "CD16-00-005400": lambda c: h_manual(c, "Review the procedures and scripts that move production data and confirm "
                                            "they follow the data-transfer policy."),
    "CD16-00-005600": h_pgdata,
    "CD16-00-005700": lambda c: h_manual(c, "Review database code, constraints and application use of prepared "
                                            "statements for input validation."),
    "CD16-00-005800": lambda c: h_manual(c, "Review database and application code for unnecessary dynamic code execution."),
    "CD16-00-005900": lambda c: h_manual(c, "Review dynamic code execution for code-injection protections."),
    "CD16-00-006000": h_client_min,
    "CD16-00-006100": lambda c: h_logperms(c, client_min=True),
    "CD16-00-006200": lambda c: h_manual(c, "Verify PostgreSQL terminates sessions under the organization-defined "
                                            "conditions (or that the documentation says none are required).", ["timeouts"]),
    "CD16-00-006400": h_labels,
    "CD16-00-006500": h_labels,
    "CD16-00-006600": h_labels,
    "CD16-00-006700": lambda c: h_manual(c, "Verify the documented discretionary access control is implemented; object "
                                            "owners are evaluated in CD16-00-002900.", ["roles"]),
    "CD16-00-006800": h_untrusted_pl,
    "CD16-00-006900": h_secdef,
    "CD16-00-007000": h_syslog,
    "CD16-00-007200": lambda c: h_manual(c, "Verify PostgreSQL has not run out of audit log space since storage was "
                                            "last allocated.", ["disk"]),
    "CD16-00-007300": lambda c: h_manual(c, "Verify a tool alerts support staff when the log volume reaches 75%.", ["disk"]),
    "CD16-00-007400": lambda c: h_manual(c, "Verify a real-time alert is sent when auditing fails."),
    "CD16-00-007500": h_timezone,
    "CD16-00-007600": lambda c: h_prefix(c, ("%m",)),
    "CD16-00-007700": h_public_create,
    "CD16-00-007800": lambda c: h_public_create(c, superusers=True),
    "CD16-00-007900": lambda c: h_denials(c, conf_perms=True),
    "CD16-00-008000": lambda c: h_ports(c, listen=False),
    "CD16-00-008100": lambda c: h_manual(c, "Verify reauthentication is forced (pg_terminate_backend) in the "
                                            "organization-defined situations."),
    "CD16-00-008300": lambda c: h_ssl(c, classified=True),
    "CD16-00-008400": h_dod_cert,
    "CD16-00-008500": lambda c: h_manual(c, "Verify organization-defined data at rest (at least PII and classified) is "
                                            "cryptographically protected from modification.", ["pgcrypto"]),
    "CD16-00-008600": lambda c: h_manual(c, "Verify organization-defined data at rest is cryptographically protected "
                                            "from disclosure.", ["pgcrypto"]),
    "CD16-00-008800": h_ssl,
    "CD16-00-008900": h_ssl,
    "CD16-00-009000": h_denials,
    "CD16-00-009100": lambda c: h_packages(c, multiple=True),
    "CD16-00-009200": h_updates,
    "CD16-00-009300": h_updates,
    "CD16-00-009400": _audit_rule(FOUR),
    "CD16-00-009500": h_denials,
    "CD16-00-009600": _audit_rule(("ddl", "write", "role")),
    "CD16-00-009700": _audit_rule(("ddl", "write", "role")),
    "CD16-00-009800": _audit_rule(("role",), test=True),
    "CD16-00-009900": h_denials,
    "CD16-00-010000": _audit_rule(("role",)),
    "CD16-00-010100": h_denials,
    "CD16-00-010200": _audit_rule(FOUR, catalog=True),
    "CD16-00-010300": h_denials,
    "CD16-00-010400": _audit_rule(FOUR, na_unless="categories_required"),
    "CD16-00-010500": _audit_rule(FOUR),
    "CD16-00-010600": _audit_rule(FOUR),
    "CD16-00-010700": h_denials,
    "CD16-00-010800": _audit_rule(("ddl",), test=True),
    "CD16-00-010900": _audit_rule(FOUR),
    "CD16-00-011000": _audit_rule(FOUR),
    "CD16-00-011100": _audit_rule(FOUR),
    "CD16-00-011200": lambda c: h_conn(c, disconnections=False),
    "CD16-00-011300": lambda c: h_conn(c, disconnections=False, logging=True),
    "CD16-00-011400": _audit_rule(FOUR),
    "CD16-00-011500": h_denials,
    "CD16-00-011600": h_conn,
    "CD16-00-011700": lambda c: h_conn(c, tokens=("%m", "%u", "%d", "%c")),
    "CD16-00-011800": _audit_rule(FOUR),
    "CD16-00-011900": lambda c: h_denials(c, pgaudit=True),
    "CD16-00-012000": lambda c: h_conn(c, pgaudit=True),
    "CD16-00-012200": h_fips,
    "CD16-00-012300": h_fips,
    "CD16-00-012400": lambda c: h_syslog(c, facility=True),
}


# ---------------------------------------------------------------------------
# filter: postgres_stig_evaluate
# ---------------------------------------------------------------------------
def postgres_stig_evaluate(ev, settings=None):
    s = settings or {}
    c = Ctx(ev or {}, s)
    R = sc.Results(CHECK_META)
    for cid, _, _, _, _ in CHECKS:
        handler = RULES.get(cid)
        if handler is None:
            R.add(cid, NR, "Not evaluated automatically; follow the STIG check procedure.")
            continue
        out = handler(c)
        R.add(cid, out[0], out[1], out[2] if len(out) > 2 else None, out[3] if len(out) > 3 else "")
    return sc.apply_overrides(R.items, s.get("overrides"))


class FilterModule(object):
    def filters(self):
        return {
            "pg_pick_postmaster": pg_pick_postmaster,
            "pg_paths": pg_paths,
            "postgres_stig_evaluate": postgres_stig_evaluate,
        }
