"""Audit lifecycle, key assurance, full MFA and maintenance segregation checks."""
import re
import stig_common as sc
from gitlab_audit_extended import mapping, names, number, timestamp

CHECKS = [('GLAB-088',
  'The application server must generate log records when successful/unsuccessful attempts to modify '
  'privileges occur.',
  ['SRG-APP-000495'],
  'medium',
  'Verify complete applicable scope, effective controls and current referenced evidence for V-204824.'),
 ('GLAB-089',
  'The application server must generate log records when successful/unsuccessful attempts to delete '
  'privileges occur.',
  ['SRG-APP-000499'],
  'medium',
  'Verify complete applicable scope, effective controls and current referenced evidence for V-204825.'),
 ('GLAB-090',
  'The application server must generate log records for privileged activities.',
  ['SRG-APP-000504'],
  'medium',
  'Verify complete applicable scope, effective controls and current referenced evidence for V-204827.'),
 ('GLAB-091',
  'The application must generate log records showing starting and ending times for user access to the '
  'application server management interface.',
  ['SRG-APP-000505'],
  'medium',
  'Verify complete applicable scope, effective controls and current referenced evidence for V-204828.'),
 ('GLAB-092',
  'The application server must generate log records when concurrent logons from different workstations occur '
  'to the application server management interface.',
  ['SRG-APP-000506'],
  'medium',
  'Verify complete applicable scope, effective controls and current referenced evidence for V-204829.'),
 ('GLAB-093',
  'Application servers must use NIST-approved or NSA-approved key management technology and processes.',
  ['SRG-APP-000514'],
  'medium',
  'Verify complete applicable scope, effective controls and current referenced evidence for V-204831.'),
 ('GLAB-094',
  'The application server must use DoW or CNSS-approved PKI Class 3 or Class 4 certificates.',
  ['SRG-APP-000514'],
  'medium',
  'Verify complete applicable scope, effective controls and current referenced evidence for V-204832.'),
 ('GLAB-095',
  'The application server must, at a minimum, transfer the logs of interconnected systems in real time, and '
  'transfer the logs of standalone systems weekly.',
  ['SRG-APP-000515'],
  'high',
  'Verify complete applicable scope, effective controls and current referenced evidence for V-204833.'),
 ('GLAB-096',
  'The application server must implement NSA-approved cryptography to protect classified information in '
  'accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and '
  'standards.',
  ['SRG-APP-000416'],
  'medium',
  'Verify complete applicable scope, effective controls and current referenced evidence for V-240925.'),
 ('GLAB-097',
  'The application server must alert organization-defined personnel or roles upon detection of unauthorized '
  'access, modification, or deletion of audit information.',
  ['SRG-APP-000795'],
  'medium',
  'Verify complete applicable scope, effective controls and current referenced evidence for V-263550.'),
 ('GLAB-098',
  'The application server must implement multifactor authentication for local; network; and/or remote access '
  'to privileged accounts; and/or nonprivileged accounts such that the device meets organization-defined '
  'strength of mechanism requirements.',
  ['SRG-APP-000825'],
  'medium',
  'Verify complete applicable scope, effective controls and current referenced evidence for V-263552.'),
 ('GLAB-099',
  'The application server must protect nonlocal maintenance sessions by separating the maintenance session '
  'from other network sessions with the system by logically separated communications paths.',
  ['SRG-APP-000880'],
  'medium',
  'Verify complete applicable scope, effective controls and current referenced evidence for V-263553.'),
 ('GLAB-100',
  'The application server must include only approved trust anchors in trust stores or certificate stores '
  'managed by the organization.',
  ['SRG-APP-000910'],
  'medium',
  'Verify complete applicable scope, effective controls and current referenced evidence for V-263554.'),
 ('GLAB-101',
  'The application server must provide protected storage for cryptographic keys with organization-defined '
  'safeguards and/or hardware protected key store.',
  ['SRG-APP-000915'],
  'medium',
  'Verify complete applicable scope, effective controls and current referenced evidence for V-263555.')]

VULN_IDS = {'GLAB-088': 'V-204824',
 'GLAB-089': 'V-204825',
 'GLAB-090': 'V-204827',
 'GLAB-091': 'V-204828',
 'GLAB-092': 'V-204829',
 'GLAB-093': 'V-204831',
 'GLAB-094': 'V-204832',
 'GLAB-095': 'V-204833',
 'GLAB-096': 'V-240925',
 'GLAB-097': 'V-263550',
 'GLAB-098': 'V-263552',
 'GLAB-099': 'V-263553',
 'GLAB-100': 'V-263554',
 'GLAB-101': 'V-263555'}


def evaluate_assurance_controls(results, ev, policy):
    raw = ev.get("audit_control_evidence")
    doc = mapping(raw if isinstance(raw, dict) else sc._json(raw or "{}"))
    now, observed = timestamp(ev.get("collected_at")), timestamp(doc.get("observed_at"))
    age = number(policy.get("evidence_max_age_hours", 24))
    valid = (isinstance(doc.get("reference"), str) and bool(doc["reference"].strip()) and now is not None and
             observed is not None and age is not None and age > 0 and 0 <= now - observed <= age * 3600)
    root = mapping(doc.get("assurance_controls")) if valid else {}
    local = mapping(ev.get("infrastructure"))
    evidence = ["Assurance reference: %s; observed_at: %s" % (doc.get("reference", "missing"), doc.get("observed_at", "missing"))]
    pending, applicability = {}, {}

    def recent(value):
        value = timestamp(value)
        return value is not None and now is not None and age is not None and age > 0 and 0 <= now - value <= age * 3600

    def fact(item, key, missing, problems, label):
        if item.get(key) is False:
            problems.append("%s: %s=false" % (label, key))
        elif item.get(key) is not True:
            missing.append("%s: missing verified %s" % (label, key))

    def scope(key, policy_key):
        section, required = mapping(root.get(key)), names(policy.get(policy_key))
        missing, problems = [], []
        fact(section, "inventory_complete", missing, problems, key)
        if not required:
            missing.append("Define %s" % policy_key)
        return section, required, missing, problems

    def tested(item, missing, label):
        if not recent(item.get("tested_at")) or not item.get("test_reference") or not item.get("configuration_reference"):
            missing.append("%s: need current test and effective configuration references" % label)

    def records(item):
        return [mapping(r) for r in item.get("records", [])] if isinstance(item.get("records"), list) else []

    for cid, key, policy_key in (("GLAB-088", "privilege_modification", "privilege_modification_operations"),
                                 ("GLAB-089", "privilege_deletion", "privilege_deletion_operations")):
        section, operations, missing, problems = scope(key, policy_key)
        if section.get("gitlab_version") != ev.get("version") or not ev.get("version"):
            missing.append("Privilege-operation coverage must match installed GitLab version")
        for operation in operations:
            item = mapping(mapping(section.get("items")).get(operation))
            fact(item, "coverage_verified", missing, problems, operation)
            tested(item, missing, operation)
            for outcome in ("success", "failure"):
                if not any(r.get("operation") == operation and r.get("outcome") == outcome and r.get("actor") and r.get("target") and r.get("source") and recent(r.get("time")) and r.get("individual_attribution_verified") is True for r in records(item)):
                    missing.append("%s: no current attributable %s record" % (operation, outcome))
        pending[cid] = (missing, problems)

    # Same role/operation evidence, independent V-ID and independent override behavior.
    privileged = next((r for r in results.items if r["id"] == "GLAB-063"), None)

    for cid, concurrent in (("GLAB-091", False), ("GLAB-092", True)):
        key = "concurrent_management_logons" if concurrent else "management_session_times"
        section, interfaces, missing, problems = scope(key, "management_interfaces")
        for interface in interfaces:
            item = mapping(mapping(section.get("items")).get(interface))
            tested(item, missing, interface)
            fact(item, "logging_coverage_verified", missing, problems, interface)
            good = False
            if not concurrent:
                methods = names(policy.get("session_termination_methods", ["logout"]))
                if "logout" not in methods:
                    missing.append("Management session termination coverage must include logout")
                for method in methods:
                    matched = False
                    for r in records(item):
                        start, end = timestamp(r.get("started_at")), timestamp(r.get("ended_at"))
                        if r.get("termination_method") != method or not r.get("actor") or not r.get("session_reference") or not r.get("start_source") or not r.get("end_source") or r.get("correlation_verified") is not True or start is None or end is None or not recent(r.get("ended_at")):
                            continue
                        if end < start:
                            problems.append("%s: recorded session end precedes start" % interface)
                        else:
                            matched = True
                    if not matched:
                        missing.append("%s: missing correlated management start/end records for %s" % (interface, method))
            else:
                fact(item, "distinct_workstations_verified", missing, problems, interface)
                fact(item, "concurrency_recorded", missing, problems, interface)
                for pair in records(item):
                    sessions = pair.get("sessions")
                    if not isinstance(sessions, list) or len(sessions) != 2 or not pair.get("concurrency_reference"):
                        continue
                    left, right = map(mapping, sessions)
                    times = [timestamp(r.get(k)) for r in (left, right) for k in ("started_at", "ended_at")]
                    if any(t is None for t in times) or not all(r.get("source") and r.get("workstation_reference") and r.get("actor") and recent(r.get("ended_at")) for r in (left, right)):
                        continue
                    a,b,c,d = times
                    if a <= b and c <= d and max(a,c) < min(b,d) and left["workstation_reference"] != right["workstation_reference"] and left["actor"] == right["actor"]:
                        good = True
                if not good:
                    missing.append("%s: no correlated overlapping same-user management sessions from verified distinct workstations" % interface)
        pending[cid] = (missing, problems)

    section, scopes, missing, problems = scope("key_management", "key_management_scopes")
    for name in scopes:
        item = mapping(mapping(section.get("items")).get(name))
        tested(item, missing, name)
        for flag in ("approved_technology_verified", "generation_distribution_verified", "access_storage_verified", "rotation_revocation_verified", "backup_destruction_verified"):
            fact(item, flag, missing, problems, name)
        if not item.get("approval_reference") or not item.get("lifecycle_policy_reference"):
            missing.append("%s: missing key-management approval and lifecycle policy references" % name)
    pending["GLAB-093"] = (missing, problems)

    section = mapping(root.get("certificate_class"))
    requirements = mapping(policy.get("certificate_policy_requirements"))
    missing, problems = [], []
    fact(section, "inventory_complete", missing, problems, "certificate_class")
    if not requirements:
        missing.append("Define certificate_policy_requirements with approved class and policy OIDs")
    for name, requirement in requirements.items():
        requirement = mapping(requirement)
        item = mapping(mapping(section.get("items")).get(name))
        tested(item, missing, name)
        if type(requirement.get("class")) is not int or requirement["class"] not in (3,4) or not names(requirement.get("policy_oids")) or not requirement.get("approval_reference"):
            missing.append("%s: missing approved Class 3/4 certificate policy requirements" % name)
        for flag in ("approving_authority_verified", "certificate_class_verified", "chain_verified", "intended_usage_verified"):
            fact(item, flag, missing, problems, name)
        sample = mapping(mapping(local.get("public_certificates")).get(name))
        if sample.get("complete") is not True:
            missing.append("%s: incomplete public-certificate measurement" % name)
        else:
            if item.get("certificate_fingerprint") != sample.get("fingerprint"):
                missing.append("%s: approval review does not identify the currently measured certificate" % name)
            actual_oids = names(sample.get("policy_oids"))
            if names(requirement.get("policy_oids")) and not set(actual_oids).intersection(requirement["policy_oids"]):
                problems.append("%s: certificate has no required approved policy OID" % name)
            end = timestamp(sample.get("not_after"))
            start = timestamp(sample.get("not_before"))
            if now is None or end is None or start is None:
                missing.append("%s: certificate validity metadata unavailable" % name)
            elif not start <= now <= end:
                problems.append("%s: certificate is outside its validity interval" % name)
    pending["GLAB-094"] = (missing, problems)

    section, sources, missing, problems = scope("log_transfer", "log_transfer_sources")
    for source in sources:
        item = mapping(mapping(section.get("items")).get(source))
        tested(item, missing, source)
        for flag in ("coverage_verified", "destination_receipt_verified", "history_verified"):
            fact(item, flag, missing, problems, source)
        if not item.get("destination_reference") or not item.get("connectivity_scope_reference"):
            missing.append("%s: identify destination and connectivity scope" % source)
        if item.get("interconnected") is True:
            fact(item, "real_time_verified", missing, problems, source)
            lag, limit = number(item.get("maximum_delivery_lag_seconds")), number(policy.get("log_transfer_real_time_limit_seconds"))
            if lag is None or lag < 0 or limit is None or limit <= 0:
                missing.append("%s: need measured delivery lag and approved real-time delivery limit" % source)
            elif lag > limit:
                problems.append("%s: transfer lag exceeds approved real-time limit" % source)
        elif item.get("interconnected") is False:
            for key in ("transfer_interval_hours", "maximum_success_gap_hours"):
                value = number(item.get(key))
                if value is None or value <= 0:
                    missing.append("%s: missing valid %s" % (source,key))
                elif value > 168:
                    problems.append("%s: %s exceeds one week" % (source,key))
            receipt = timestamp(item.get("last_receipt_at"))
            if receipt is None or now is None or receipt > now:
                missing.append("%s: invalid last destination receipt time" % source)
            elif now - receipt > 168 * 3600:
                problems.append("%s: last destination receipt is older than one week" % source)
        else:
            missing.append("%s: declare interconnected/standalone status" % source)
    pending["GLAB-095"] = (missing, problems)

    section, paths, missing, problems = scope("classified_crypto", "classified_crypto_paths")
    if section.get("classified_information_present") is False and section.get("scope_reference") and not paths and not section.get("items"):
        applicability["GLAB-096"] = "Documented scope excludes classified information: %s" % section["scope_reference"] if section.get("inventory_complete") is True else None
    if not applicability.get("GLAB-096"):
        if section.get("classified_information_present") is not True:
            missing.append("Establish classified-information applicability")
        for path in paths:
            item = mapping(mapping(section.get("items")).get(path))
            tested(item, missing, path)
            for flag in ("nsa_approval_verified", "approved_configuration_verified", "operational_environment_verified", "scope_coverage_verified"):
                fact(item, flag, missing, problems, path)
            if not item.get("nsa_approval_reference"):
                missing.append("%s: no NSA cryptographic approval reference" % path)
        pending["GLAB-096"] = (missing, problems)

    section, scopes, missing, problems = scope("audit_information_alerts", "audit_information_scopes")
    if not section.get("recipient_policy_reference"):
        missing.append("Missing organization-defined audit alert recipient policy")
    for name in scopes:
        item = mapping(mapping(section.get("items")).get(name))
        for event in ("access", "modification", "deletion"):
            observation = mapping(mapping(item.get("events")).get(event))
            tested(observation, missing, "%s/%s" % (name,event))
            for flag in ("unauthorized_event_detected", "delivery_verified", "recipient_roles_verified"):
                fact(observation, flag, missing, problems, "%s/%s" % (name,event))
    pending["GLAB-097"] = (missing, problems)

    section = mapping(root.get("mfa_strength"))
    matrix = mapping(policy.get("mfa_access_matrix"))
    missing, problems = [], []
    fact(section, "inventory_complete", missing, problems, "mfa_strength")
    if not matrix or not section.get("strength_policy_reference"):
        missing.append("Define required account/access-path MFA matrix and strength policy")
    for account, paths in matrix.items():
        if not names(paths):
            missing.append("%s: define required access paths" % account)
            continue
        for path in paths:
            item = mapping(mapping(mapping(section.get("accounts")).get(account)).get(path))
            tested(item, missing, "%s/%s" % (account,path))
            for flag in ("multiple_factors_verified", "mechanism_strength_verified", "enrollment_enforced", "bypass_prevented", "recovery_exceptions_reviewed"):
                fact(item, flag, missing, problems, "%s/%s" % (account,path))
    pending["GLAB-098"] = (missing, problems)

    section, paths, missing, problems = scope("maintenance_separation", "maintenance_paths")
    if not paths and section.get("inventory_complete") is True and section.get("none_present") is True and section.get("scope_reference") and not section.get("items"):
        applicability["GLAB-099"] = "Documented scope has no nonlocal maintenance sessions: %s" % section["scope_reference"]
    else:
        for path in paths:
            item = mapping(mapping(section.get("items")).get(path))
            tested(item, missing, path)
            for flag in ("logical_separation_verified", "routes_controls_verified", "other_session_separation_verified", "bypass_prevented"):
                fact(item, flag, missing, problems, path)
            if not item.get("topology_reference"):
                missing.append("%s: missing maintenance communications topology reference" % path)
        pending["GLAB-099"] = (missing, problems)

    section, stores, missing, problems = scope("organization_trust", "organization_trust_stores")
    for store in stores:
        item = mapping(mapping(section.get("items")).get(store))
        tested(item, missing, store)
        for flag in ("effective_inventory_verified", "overrides_reviewed", "approval_verified"):
            fact(item, flag, missing, problems, store)
        approved = names(mapping(policy.get("approved_trust_anchors")).get(store))
        normalize = lambda value: re.sub(r"[:\s]", "", value.lower())
        approved = [normalize(value) for value in approved]
        if not approved or any(not re.fullmatch(r"[a-f0-9]{64}", value) for value in approved):
            missing.append("%s: define valid approved trust-anchor fingerprints" % store)
            approved = []
        sample = mapping(mapping(local.get("trust_bundles")).get(store))
        fingerprints = names(sample.get("fingerprints")) if sample.get("complete") is True else names(item.get("fingerprints"))
        if sample and sample.get("complete") is not True:
            missing.append("%s: incomplete local trust bundle inventory" % store)
        if not fingerprints:
            missing.append("%s: no measured effective trust anchors" % store)
        for fingerprint in fingerprints:
            value = normalize(fingerprint)
            if not re.fullmatch(r"[a-f0-9]{64}", value):
                missing.append("%s: malformed measured fingerprint" % store)
            elif approved and value not in approved:
                problems.append("%s: unapproved trust anchor" % store)
    pending["GLAB-100"] = (missing, problems)

    section, stores, missing, problems = scope("key_storage", "cryptographic_key_stores")
    if not section.get("safeguard_policy_reference"):
        missing.append("Missing organization-defined key storage safeguard policy")
    for store in stores:
        item = mapping(mapping(section.get("items")).get(store))
        tested(item, missing, store)
        for flag in ("safeguards_verified", "effective_access_verified", "backup_protection_verified"):
            fact(item, flag, missing, problems, store)
        if item.get("hardware_required") is True:
            fact(item, "hardware_protection_verified", missing, problems, store)
        elif item.get("hardware_required") is not False:
            missing.append("%s: establish hardware-storage applicability" % store)
        if item.get("storage_type") == "file":
            sample = mapping(mapping(local.get("key_storage")).get(store))
            if sample.get("exists") is False:
                problems.append("%s: required key storage path is absent" % store)
            if sample.get("complete") is not True:
                missing.append("%s: incomplete key-path metadata" % store)
            if sample.get("world_readable") is True or sample.get("world_writable") is True:
                problems.append("%s: key storage is exposed to world read/write access" % store)
        elif item.get("storage_type") not in ("kms", "hsm", "vault") or not item.get("provider_reference"):
            missing.append("%s: identify key storage backend and provider evidence" % store)
    pending["GLAB-101"] = (missing, problems)

    for cid in VULN_IDS:
        if cid == "GLAB-090":
            results.add(cid, privileged["status"] if privileged else sc.NR,
                        privileged["finding_details"] if privileged else "Missing privileged role/operation coverage evaluation (GLAB-063).",
                        privileged["evidence"] if privileged else evidence)
        elif applicability.get(cid):
            results.add(cid, sc.NA, applicability[cid], evidence)
        else:
            missing, problems = pending[cid]
            if cid in ("GLAB-094", "GLAB-100", "GLAB-101"):
                collection_key = {"GLAB-094":"public_certificates", "GLAB-100":"trust_bundles", "GLAB-101":"key_storage"}[cid]
                if any(error.startswith(collection_key + ":") for error in names(local.get("errors"))):
                    missing.append("Incomplete local collection for %s" % collection_key)
            results.add(cid, sc.OPEN if problems else sc.NR if missing else sc.NF,
                        "; ".join(problems + missing) if problems or missing else "Complete current evidence supports %s." % VULN_IDS[cid], evidence)


class FilterModule(object):
    def filters(self):
        return {}
