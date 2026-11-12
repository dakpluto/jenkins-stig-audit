"""Storage, input/error handling and log tool cryptographic integrity checks."""
import re

import stig_common as sc
from gitlab_audit_extended import mapping, names, number, timestamp


def evaluate_data_controls(results, ev, policy):
    raw = ev.get("audit_control_evidence")
    doc = mapping(raw if isinstance(raw, dict) else sc._json(raw or "{}"))
    now, observed = timestamp(ev.get("collected_at")), timestamp(doc.get("observed_at"))
    age = number(policy.get("evidence_max_age_hours", 24))
    valid = (isinstance(doc.get("reference"), str) and bool(doc["reference"].strip()) and now is not None and
             observed is not None and age is not None and age > 0 and 0 <= now - observed <= age * 3600)
    root = mapping(doc.get("data_controls")) if valid else {}
    evidence = ["Data control evidence reference: %s; observed_at: %s" % (doc.get("reference", "missing"), doc.get("observed_at", "missing"))]

    def recent(value):
        value = timestamp(value)
        return value is not None and now is not None and age is not None and age > 0 and 0 <= now - value <= age * 3600

    def fact(item, key, missing, problems, label):
        if item.get(key) is False:
            problems.append("%s: %s=false" % (label, key))
        elif item.get(key) is not True:
            missing.append("%s: missing verified %s" % (label, key))

    def finish(cid, missing, problems, success, detail=None):
        results.add(cid, sc.OPEN if problems else sc.NR if missing else sc.NF,
                    "; ".join(problems + missing) if problems or missing else success, evidence + (detail or []))

    def inventory(section_key, policy_key):
        section = mapping(root.get(section_key))
        required = names(policy.get(policy_key))
        missing, problems = [], []
        fact(section, "inventory_complete", missing, problems, section_key)
        if not required:
            missing.append("Define %s" % policy_key)
        return section, required, missing, problems

    section, locations, missing, problems = inventory("at_rest", "storage_locations")
    for location in locations:
        item = mapping(mapping(section.get("locations")).get(location))
        for key in ("confidentiality_verified", "integrity_verified", "effective_access_verified"):
            fact(item, key, missing, problems, location)
        for key in ("storage_reference", "configuration_reference", "verification_reference"):
            if not item.get(key):
                missing.append("%s: missing %s" % (location, key))
    finish("GLAB-050", missing, problems, "All inventoried information at rest has verified confidentiality, integrity and effective access protection.")

    section, copies, missing, problems = inventory("offline", "offline_copies")
    absent = (not copies and section.get("inventory_complete") is True and section.get("none_present") is True and
              bool(section.get("scope_reference")) and not section.get("copies"))
    if absent:
        results.add("GLAB-051", sc.NA, "Reviewed inventory establishes no offline information: %s" % section["scope_reference"], evidence)
    else:
        if copies and section.get("none_present") is True:
            missing.append("Offline absence claim contradicts configured copies")
        for copy in copies:
            item = mapping(mapping(section.get("copies")).get(copy))
            for key in ("encryption_verified", "cryptographic_integrity_verified", "key_protection_verified", "coverage_verified"):
                fact(item, key, missing, problems, copy)
            for key in ("mechanism_reference", "verification_reference", "key_management_reference"):
                if not item.get(key):
                    missing.append("%s: missing %s" % (copy, key))
        finish("GLAB-051", missing, problems, "All inventoried offline information has verified cryptographic confidentiality/integrity and protected keys.")

    section, inputs, missing, problems = inventory("input_validation", "management_inputs")
    version_ok = bool(ev.get("version")) and section.get("gitlab_version") == ev.get("version")
    if not version_ok or not section.get("implementation_reference"):
        missing.append("Need management input implementation review for the installed GitLab version")
    for name in inputs:
        item = mapping(mapping(section.get("inputs")).get(name))
        if item.get("exception") is True:
            if not item.get("organization_approval_reference") or not item.get("exception_scope_reference"):
                missing.append("%s: exception requires organization approval and precise scope" % name)
            continue
        for key in ("server_validation_verified", "type_format_verified", "bounds_verified", "unexpected_parameters_verified", "invalid_input_rejected"):
            fact(item, key, missing, problems, name)
        if not recent(item.get("tested_at")) or not item.get("test_reference"):
            missing.append("%s: missing recent management input rejection tests" % name)
    finish("GLAB-052", missing, problems, "Inventoried management inputs enforce reviewed server-side validation, with only explicitly approved exceptions.")

    inspection = mapping(ev.get("error_inspection"))
    local_events = inspection.get("events") if isinstance(inspection.get("events"), list) else []
    section, conditions, missing, problems = inventory("error_identification", "error_conditions")
    for condition in conditions:
        item = mapping(mapping(section.get("conditions")).get(condition))
        fact(item, "recognition_verified", missing, problems, condition)
        if not item.get("configuration_reference"):
            missing.append("%s: missing error recognition configuration/implementation reference" % condition)
        records = item.get("records") if isinstance(item.get("records"), list) else []
        observed = any(isinstance(record, dict) and recent(record.get("time")) and record.get("source") for record in records)
        observed = observed or any(isinstance(record, dict) and record.get("condition") == condition and recent(record.get("time")) and record.get("source") for record in local_events)
        if not observed:
            missing.append("%s: no recent identifiable error record (bounded sample absence is inconclusive)" % condition)
    finish("GLAB-053", missing, problems, "All required security-relevant error conditions are recognized and supported by recent identifiable records.")

    section, outputs, missing, problems = inventory("error_sanitization", "error_outputs")
    if section.get("gitlab_version") != ev.get("version") or not ev.get("version") or not section.get("implementation_reference"):
        missing.append("Need sanitization implementation review for the installed GitLab version")
    for output in outputs:
        item = mapping(mapping(section.get("outputs")).get(output))
        for key in ("sanitization_verified", "corrective_information_verified", "sensitive_disclosure_prevented"):
            fact(item, key, missing, problems, output)
        if not recent(item.get("tested_at")) or not item.get("test_reference"):
            missing.append("%s: missing recent error-output test reference" % output)
    detail = []
    sources = mapping(inspection.get("sources"))
    for source, data in sources.items():
        data = mapping(data)
        # Never include matching text or secret values in the report.
        detail.append("Error source %s: sampled_lines=%s; candidate_categories=%s; exact_canary_found=%s" %
                      (source, data.get("sampled_lines", 0), ",".join(names(data.get("candidate_categories"))), data.get("canary_found", False)))
        if data.get("canary_found") is True:
            problems.append("Configured non-secret error test canary was found in %s" % source)
        if data.get("candidate_categories") and section.get("sample_candidates_reviewed") is not True:
            missing.append("Potential sensitive-error indicators require review at source: %s" % source)
    finish("GLAB-054", missing, problems, "Error outputs provide useful corrective information with verified sanitization and no demonstrated sensitive disclosure.", detail)

    section, required, missing, problems = inventory("tool_integrity", "required_log_tools")
    for key in ("baseline_authenticated", "baseline_independently_protected", "baseline_approved"):
        fact(section, key, missing, problems, "tool_integrity")
    trusted = all(section.get(key) is True for key in ("baseline_authenticated", "baseline_independently_protected", "baseline_approved"))
    if not section.get("baseline_reference"):
        missing.append("Missing approved cryptographic baseline reference")
        trusted = False
    tools = mapping(ev.get("log_tools"))
    actual = mapping(tools.get("paths"))
    baseline = mapping(section.get("paths"))
    if tools.get("truncated"):
        missing.append("Local log tool discovery was truncated")
    if not actual:
        missing.append("No local log tool discovery evidence")
    detail = []
    for path in sorted(set(required) | set(actual)):
        entry = mapping(actual.get(path))
        if entry.get("exists") is False and path in required:
            problems.append("Required log tool absent: %s" % path)
            continue
        digest = entry.get("sha256")
        expected = mapping(baseline.get(path)).get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", digest) or entry.get("hash_error") or entry.get("error"):
            missing.append("Missing complete local SHA-256 measurement for %s" % path)
            continue
        if not isinstance(expected, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", expected):
            missing.append("Missing trusted baseline SHA-256 for %s" % path)
            continue
        if trusted:
            matched = digest.lower() == expected.lower()
            detail.append("%s: approved baseline digest %s" % (path, "matches" if matched else "MISMATCH"))
            if not matched:
                problems.append("Cryptographic baseline mismatch: %s" % path)
    finish("GLAB-055", missing, problems, "All inventoried log tools match the authenticated, independently protected approved SHA-256 baseline.", detail)


class FilterModule(object):
    def filters(self):
        return {}
