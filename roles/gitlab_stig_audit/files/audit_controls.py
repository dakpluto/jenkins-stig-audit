"""Read-only target collector. Emit identifiers only, never free-form event details."""
import json
import sys
import os
import glob
import stat
import subprocess

out = {"samples": "", "external": {}, "errors": []}
try:
    with open(sys.argv[1], "rb") as stream:
        stream.seek(0, 2)
        size = stream.tell()
        stream.seek(max(0, size - 262144))
        if size > 262144:
            stream.readline()
        lines = stream.read(262144).decode("utf-8", "replace").splitlines()[-200:]
    rows = []
    for line in lines:
        try:
            row = json.loads(line)
            details = row.get("details") or {}
            rows.append({key: row[key] for key in
                         ("author_id", "user_id", "created_at", "time", "target_id", "event_type") if key in row})
            rows[-1]["event_type"] = row.get("event_type") or details.get("event_type")
        except (ValueError, TypeError, AttributeError):
            continue
    out["samples"] = "\n".join(json.dumps(row) for row in rows)
except OSError as exc:
    out["errors"].append("audit sample: " + str(exc))
if sys.argv[2]:
    try:
        with open(sys.argv[2], "rb") as stream:
            payload = stream.read(1048577)
        if len(payload) > 1048576:
            raise ValueError("external evidence exceeds 1 MiB")
        doc = json.loads(payload.decode("utf-8"))
        if not isinstance(doc, dict):
            raise ValueError("external evidence must be an object")
        out["external"] = doc
    except (OSError, ValueError) as exc:
        out["errors"].append("external evidence: " + str(exc))
# Log tool metadata: discovery is bounded and does not read tool/config contents.
# Imports are conditional so this collector can also be exercised on a Windows controller.
if len(sys.argv) > 3:
    import pwd
    import grp
    install = sys.argv[3]
    data = sys.argv[5] if len(sys.argv) > 5 else "/var/opt/gitlab"
    candidates = [install + suffix for suffix in (
        "/embedded/bin/svlogd", "/embedded/sbin/logrotate", "/embedded/bin/logrotate",
        "/bin/gitlab-ctl", "/embedded/bin/chpst")]
    candidates += ["/usr/sbin/rsyslogd", "/usr/sbin/syslog-ng", "/usr/bin/journalctl",
                   "/etc/rsyslog.conf", "/etc/syslog-ng/syslog-ng.conf", "/etc/systemd/journald.conf"]
    paths = {path for path in candidates if os.path.lexists(path)}
    # Discover the active Omnibus service log controls, rotations and installed agents.
    for pattern in (install + "/service/*/log/run", install + "/service/*/log/config",
                    data + "/logrotate/logrotate.conf", data + "/logrotate/logrotate.d/*",
                    "/etc/rsyslog.d/*.conf", "/etc/systemd/journald.conf.d/*.conf",
                    "/etc/logrotate.d/gitlab*", "/opt/splunkforwarder/bin/splunk",
                    "/usr/bin/filebeat", "/usr/bin/fluent-bit", "/opt/fluent-bit/bin/fluent-bit"):
        for index, path in enumerate(glob.iglob(pattern)):
            if index >= 128:
                out["errors"].append("Tool discovery truncated: " + pattern)
                break
            paths.add(path)
    try:
        extra = json.loads(sys.argv[4]) if len(sys.argv) > 4 else []
        if not isinstance(extra, list) or any(not isinstance(path, str) or not os.path.isabs(path) for path in extra):
            raise ValueError("additional log tool paths must be absolute strings")
        paths.update(extra)
    except (ValueError, TypeError) as exc:
        out["errors"].append("Tool paths: " + str(exc))
    metadata = {"paths": {}, "truncated": len(paths) > 128 or any("truncated" in e for e in out["errors"])}
    acl_paths = set()
    for path in sorted(paths)[:128]:
        entry = {"exists": os.path.lexists(path), "nodes": []}
        metadata["paths"][path] = entry
        if not entry["exists"]:
            continue
        # Include lexical ancestors and real ancestors: both directory chains matter.
        targets = set()
        for initial in (path, os.path.realpath(path)):
            current = initial
            while True:
                targets.add(current)
                targets.add(os.path.realpath(current))
                parent = os.path.dirname(current)
                if parent == current:
                    break
                current = parent
        try:
            for target in sorted(targets):
                info = os.stat(target)
                entry["nodes"].append(dict(path=target, owner=pwd.getpwuid(info.st_uid).pw_name,
                    group=grp.getgrgid(info.st_gid).gr_name, mode=format(stat.S_IMODE(info.st_mode), "04o"),
                    kind="directory" if stat.S_ISDIR(info.st_mode) else "file"))
                acl_paths.add(target)
        except (OSError, KeyError) as exc:
            entry["error"] = str(exc)
    try:
        # ACLs are evidence for review; the evaluator does not assume POSIX modes
        # exclude named ACL grants or privileged sudo/configuration management access.
        if acl_paths:
            acl = subprocess.run(["getfacl", "-p", "--absolute-names", "--"] + sorted(acl_paths),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            metadata["acl_text"] = acl.stdout[:262144].decode("utf-8", "replace")
            metadata["acl_complete"] = acl.returncode == 0 and len(acl.stdout) <= 262144
        else:
            metadata["acl_complete"] = False
    except (OSError, subprocess.TimeoutExpired) as exc:
        metadata["acl_complete"] = False
        out["errors"].append("Tool ACL collection: " + str(exc))
    out["log_tools"] = metadata
print(json.dumps(out))
