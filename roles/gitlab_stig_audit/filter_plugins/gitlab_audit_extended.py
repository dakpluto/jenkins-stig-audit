"""Evidence-based checks for privileged recording and logging tool protection.

Local POSIX metadata proves specific exposure, not the absence of ACL/sudo bypasses.
External facts must be recent and reference independently reviewable observations.
"""
import math
from datetime import datetime

import stig_common as sc


def timestamp(value):
    try:
        value = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return value.timestamp() if value.tzinfo else None
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def mapping(value):
    return value if isinstance(value, dict) else {}


def names(value):
    return value if isinstance(value, list) and all(isinstance(x, str) and x for x in value) else []


def number(value):
    try:
        result = float(value)
        return result if not isinstance(value, bool) and math.isfinite(result) else None
    except (ValueError, TypeError, OverflowError):
        return None


def evaluate_extended(results, ev, policy):
    raw = ev.get("audit_control_evidence")
    doc = mapping(raw if isinstance(raw, dict) else sc._json(raw or "{}"))
    now, observed = timestamp(ev.get("collected_at")), timestamp(doc.get("observed_at"))
    age = number(policy.get("evidence_max_age_hours", 24))
    valid = (now is not None and observed is not None and age is not None and age > 0 and
             0 <= now - observed <= age * 3600 and isinstance(doc.get("reference"), str) and bool(doc["reference"].strip()))
    evidence = ["External reference: %s; observed_at: %s" % (doc.get("reference", "missing"), doc.get("observed_at", "missing"))]
    evidence.extend(ev.get("audit_collection_errors") or [])
    if not valid:
        doc = {}

    def recent(value):
        value = timestamp(value)
        return now is not None and value is not None and age is not None and age > 0 and 0 <= now - value <= age * 3600

    def fact(section, key, missing, problems):
        if section.get(key) is False:
            problems.append("%s=false" % key)
        elif section.get(key) is not True:
            missing.append("Missing verified %s" % key)

    def finish(cid, missing, problems, success, detail=None):
        results.add(cid, sc.OPEN if problems else sc.NR if missing else sc.NF,
                    "; ".join(problems + missing) if problems or missing else success,
                    evidence + (detail or []))

    missing, problems = [], []
    paths = mapping(policy.get("privileged_access_paths"))
    observations = mapping(mapping(doc.get("privileged_recording")).get("paths"))
    if not paths:
        missing.append("Define privileged_access_paths with full_command or individual_identity mode")
    for path, mode in paths.items():
        item = mapping(observations.get(path))
        for key in ("coverage_verified", "configuration_verified"):
            fact(item, key, missing, problems)
        records = item.get("records") if isinstance(item.get("records"), list) else []
        qualifying = []
        for record in records:
            record = mapping(record)
            if not record.get("source") or not recent(record.get("time")):
                continue
            if mode == "full_command":
                # Full text stays in the referenced source; collect a verified observation,
                # never duplicate command arguments that can contain credentials.
                good = (record.get("full_text_verified") is True and bool(record.get("command_record_reference")) and
                        bool(record.get("actor")))
            elif mode == "individual_identity":
                good = (record.get("individual_identity_verified") is True and bool(record.get("individual")) and
                        bool(record.get("account")) and record["individual"] != record["account"])
            else:
                good = False
            if good:
                qualifying.append(record)
        if mode not in ("full_command", "individual_identity"):
            missing.append("Invalid privileged recording mode for %s" % path)
        elif not qualifying:
            missing.append("No recent verified %s record for %s" % (mode, path))
        if item.get("recording_gap") is True:
            problems.append("Privileged recording gap on %s" % path)
    finish("GLAB-035", missing, problems, "All declared privileged access paths have verified configuration, coverage and representative recording.")

    tools = mapping(ev.get("log_tools"))
    inventory = mapping(tools.get("paths"))
    required = names(policy.get("required_log_tools"))
    approved_owners = names(policy.get("approved_log_tool_writers", ["root"]))
    approved_groups = names(policy.get("approved_log_tool_groups", ["root"]))
    section = mapping(doc.get("log_tool_protection"))
    for cid, operation in (("GLAB-036", "access"), ("GLAB-037", "modification"), ("GLAB-038", "deletion")):
        missing, problems, detail = [], [], []
        if tools.get("truncated"):
            missing.append("Log tool discovery was truncated")
        if tools.get("acl_complete") is not True:
            missing.append("Complete local ACL evidence is unavailable")
        if not required:
            missing.append("Define required_log_tools from the reviewed tool inventory")
        if not approved_owners or not approved_groups:
            missing.append("Define approved log tool writers and groups")
        fact(section, "inventory_complete", missing, problems)
        fact(section, "effective_access_reviewed", missing, problems)
        # Effective review includes ACLs, groups, sudo, service identities and deployment tooling.
        # Mode checks alone cannot establish approved access or defeat privileged bypasses.
        for path in sorted(set(required) | set(inventory)):
            entry = mapping(inventory.get(path))
            if not entry or entry.get("error") or entry.get("truncated"):
                missing.append("Incomplete local metadata for %s" % path)
                continue
            if entry.get("exists") is False:
                if path in required:
                    problems.append("Required log tool is absent: %s" % path)
                continue
            nodes = entry.get("nodes") if isinstance(entry.get("nodes"), list) else []
            if not nodes:
                missing.append("No resolved target/ancestor metadata for %s" % path)
            for node in nodes:
                node = mapping(node)
                try:
                    mode = int(str(node["mode"]), 8)
                    owner, group, name = node["owner"], node["group"], node["path"]
                except (KeyError, TypeError, ValueError):
                    missing.append("Malformed tool metadata for %s" % path)
                    continue
                detail.append("%s owner=%s group=%s mode=%04o" % (name, owner, group, mode))
                if operation == "access":
                    continue  # approved read/execute policy is tool-specific
                is_dir = node.get("kind") == "directory"
                if operation == "deletion" and not is_dir:
                    continue
                if owner not in approved_owners:
                    problems.append("Unapproved owner can replace/change %s: %s" % (name, owner))
                if mode & 0o020 and group not in approved_groups:
                    problems.append("Unapproved group can write %s: %s" % (name, group))
                if mode & 0o002:
                    # Sticky directories require an effective ownership/ACL review; don't
                    # assume every child can be removed by every writer.
                    if is_dir and mode & 0o1000:
                        missing.append("Sticky writable ancestor requires effective review: %s" % name)
                    else:
                        problems.append("World-writable log tool or ancestor: %s" % name)
            item = mapping(mapping(section.get("paths")).get(path))
            fact(item, operation + "_restricted", missing, problems)
        if not inventory:
            missing.append("No local log tool discovery evidence")
        finish(cid, missing, problems, "Log tools are protected against unauthorized %s." % operation, sorted(set(detail)))

    missing, problems = [], []
    sources = names(policy.get("backup_log_sources"))
    backups = mapping(doc.get("log_backup"))
    if not sources:
        missing.append("Define backup_log_sources")
    for source in sources:
        item = mapping(mapping(backups.get("sources")).get(source))
        for key in ("coverage_verified", "separate_destination_verified", "history_verified"):
            fact(item, key, missing, problems)
        if not item.get("destination_reference"):
            missing.append("Missing separate backup destination reference for %s" % source)
        interval = number(item.get("schedule_interval_hours"))
        gap = number(item.get("maximum_success_gap_hours"))
        for label, value in (("schedule interval", interval), ("observed maximum successful backup gap", gap)):
            if value is None or value <= 0:
                missing.append("Missing valid %s for %s" % (label, source))
            elif value > 168:
                problems.append("%s exceeds seven days for %s" % (label, source))
        completed = timestamp(item.get("last_success_at"))
        if completed is None or now is None or completed > now:
            missing.append("Missing valid last successful backup time for %s" % source)
        elif now - completed > 168 * 3600:
            problems.append("Last successful backup is older than seven days for %s" % source)
    finish("GLAB-039", missing, problems, "Required logs have verified separate backups, successful history and intervals no greater than seven days.")

    missing, problems = [], []
    sources = names(policy.get("integrity_log_sources"))
    integrity = mapping(doc.get("log_integrity"))
    if not sources:
        missing.append("Define integrity_log_sources")
    for source in sources:
        item = mapping(mapping(integrity.get("sources")).get(source))
        if item.get("mechanism") not in ("digital_signature", "hmac", "authenticated_storage", "protected_hash_manifest"):
            missing.append("No supported cryptographic integrity mechanism for %s" % source)
        for key in ("coverage_verified", "mechanism_approved", "verification_material_protected", "verification_success"):
            fact(item, key, missing, problems)
        if not item.get("configuration_reference") or not item.get("verification_reference"):
            missing.append("Missing cryptographic configuration/verification references for %s" % source)
        if not recent(item.get("last_verified_at")):
            missing.append("No recent integrity verification for %s" % source)
        if item.get("tampering_detected") is True:
            problems.append("Integrity verification detected log tampering for %s" % source)
    finish("GLAB-040", missing, problems, "Required logs have approved cryptographic integrity protection, protected verification material and recent successful verification.")


class FilterModule(object):
    """The sibling GitLab filter calls this helper; expose no standalone filters."""
    def filters(self):
        return {}
