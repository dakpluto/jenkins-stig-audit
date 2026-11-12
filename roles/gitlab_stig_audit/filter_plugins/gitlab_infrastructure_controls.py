"""Infrastructure, federation and communication requirements; read-only evidence evaluation."""
import re
import stig_common as sc
from gitlab_audit_extended import mapping, names, number, timestamp

CHECKS = [('GLAB-064',
  'The application server must provide an immediate warning to the SA and ISSO, at a minimum, when allocated '
  'log record storage volume reaches 75% of maximum log record storage capacity.',
  ['SRG-APP-000359'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204790.'),
 ('GLAB-065',
  'The application server must provide an immediate real-time alert to authorized users of all log failure '
  'events requiring real-time alerts.',
  ['SRG-APP-000360'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204791.'),
 ('GLAB-066',
  'The application server must compare internal application server clocks at least every 24 hours with an '
  'authoritative time source.',
  ['SRG-APP-000371'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204792.'),
 ('GLAB-067',
  'The application server must synchronize internal application server clocks to an authoritative time '
  'source when the time difference is greater than the organization-defined time period.',
  ['SRG-APP-000372'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204793.'),
 ('GLAB-068',
  'The application server must record time stamps for log records that meet a granularity of one second for '
  'a minimum degree of precision.',
  ['SRG-APP-000375'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204795.'),
 ('GLAB-069',
  'The application server must log the enforcement actions used to restrict access associated with changes '
  'to the application server.',
  ['SRG-APP-000381'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204797.'),
 ('GLAB-070',
  'The application server must require users to reauthenticate when organization-defined circumstances or '
  'situations require reauthentication.',
  ['SRG-APP-000389'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204798.'),
 ('GLAB-071',
  'The application server, for PKI-based authentication, must implement a local cache of revocation data to '
  'support path discovery and validation in case of the inability to access revocation information via the '
  'network.',
  ['SRG-APP-000401'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204805.'),
 ('GLAB-072',
  'The application server must accept Personal Identity Verification (PIV) credentials from other federal '
  'agencies to access the management interface.',
  ['SRG-APP-000402'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204806.'),
 ('GLAB-073',
  'The application server must electronically verify Personal Identity Verification (PIV) credentials from '
  'other federal agencies to access the management interface.',
  ['SRG-APP-000403'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204807.'),
 ('GLAB-074',
  'The application server must accept Federal Identity, Credential, and Access Management (FICAM)-approved '
  'third-party credentials.',
  ['SRG-APP-000404'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204808.'),
 ('GLAB-075',
  'The application server must conform to Federal Identity, Credential, and Access Management (FICAM)-issued '
  'profiles.',
  ['SRG-APP-000405'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204809.'),
 ('GLAB-076',
  'The application server must only allow the use of DoW PKI-established certificate authorities for '
  'verification of the establishment of protected sessions.',
  ['SRG-APP-000427'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204811.'),
 ('GLAB-077',
  'The application server must implement cryptographic mechanisms to prevent unauthorized modification of '
  'organization-defined information at rest on organization-defined information system components.',
  ['SRG-APP-000428'],
  'high',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204812.'),
 ('GLAB-078',
  'The application must implement cryptographic mechanisms to prevent unauthorized disclosure of '
  'organization-defined information at rest on organization-defined information system components.',
  ['SRG-APP-000429'],
  'high',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204813.'),
 ('GLAB-079',
  'The application server, when a MAC I system, must be in a high-availability (HA) cluster.',
  ['SRG-APP-000435'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204814.'),
 ('GLAB-080',
  'The application server must protect against or limit the effects of all types of Denial of Service (DoS) '
  'attacks by employing organization-defined security safeguards.',
  ['SRG-APP-000435'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204815.'),
 ('GLAB-081',
  'The application server must protect the confidentiality and integrity of transmitted information through '
  'the use of an approved TLS version.',
  ['SRG-APP-000439'],
  'high',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204816.'),
 ('GLAB-082',
  'The application server must remove all export ciphers to protect the confidentiality and integrity of '
  'transmitted information.',
  ['SRG-APP-000439'],
  'high',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204817.'),
 ('GLAB-083',
  'The application server must employ approved cryptographic mechanisms to prevent unauthorized disclosure '
  'of information and/or detect changes to information during transmission.',
  ['SRG-APP-000440'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204818.'),
 ('GLAB-084',
  'The application server must maintain the confidentiality and integrity of information during preparation '
  'for transmission.',
  ['SRG-APP-000441'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204819.'),
 ('GLAB-085',
  'The application server must maintain the confidentiality and integrity of information during reception.',
  ['SRG-APP-000442'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204820.'),
 ('GLAB-086',
  'The application server must behave in a predictable and documented manner that reflects organizational '
  'and system objectives when invalid inputs are received.',
  ['SRG-APP-000447'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204821.'),
 ('GLAB-087',
  'The application server must remove organization-defined software components after updated versions have '
  'been installed.',
  ['SRG-APP-000454'],
  'medium',
  'Verify complete scope, effective configuration and current referenced runtime/test evidence for '
  'V-204822.')]

VULN_IDS = {'GLAB-064': 'V-204790',
 'GLAB-065': 'V-204791',
 'GLAB-066': 'V-204792',
 'GLAB-067': 'V-204793',
 'GLAB-068': 'V-204795',
 'GLAB-069': 'V-204797',
 'GLAB-070': 'V-204798',
 'GLAB-071': 'V-204805',
 'GLAB-072': 'V-204806',
 'GLAB-073': 'V-204807',
 'GLAB-074': 'V-204808',
 'GLAB-075': 'V-204809',
 'GLAB-076': 'V-204811',
 'GLAB-077': 'V-204812',
 'GLAB-078': 'V-204813',
 'GLAB-079': 'V-204814',
 'GLAB-080': 'V-204815',
 'GLAB-081': 'V-204816',
 'GLAB-082': 'V-204817',
 'GLAB-083': 'V-204818',
 'GLAB-084': 'V-204819',
 'GLAB-085': 'V-204820',
 'GLAB-086': 'V-204821',
 'GLAB-087': 'V-204822'}


def evaluate_infrastructure_controls(results, ev, policy):
    first_result = len(results.items)
    raw = ev.get("audit_control_evidence")
    doc = mapping(raw if isinstance(raw, dict) else sc._json(raw or "{}"))
    now, observed = timestamp(ev.get("collected_at")), timestamp(doc.get("observed_at"))
    age = number(policy.get("evidence_max_age_hours", 24))
    valid = (isinstance(doc.get("reference"), str) and bool(doc["reference"].strip()) and now is not None and
             observed is not None and age is not None and age > 0 and 0 <= now - observed <= age * 3600)
    root = mapping(doc.get("infrastructure_controls")) if valid else {}
    local = mapping(ev.get("infrastructure"))
    evidence = ["Infrastructure reference: %s; observed_at: %s" % (doc.get("reference", "missing"), doc.get("observed_at", "missing"))]
    evidence.extend(names(local.get("errors")))

    def recent(value):
        value = timestamp(value)
        return value is not None and now is not None and age is not None and age > 0 and 0 <= now - value <= age * 3600

    def fact(item, key, missing, problems, label):
        if item.get(key) is False:
            problems.append("%s: %s=false" % (label, key))
        elif item.get(key) is not True:
            missing.append("%s: missing verified %s" % (label, key))

    def finish(cid, missing, problems, detail=None):
        results.add(cid, sc.OPEN if problems else sc.NR if missing else sc.NF,
                    "; ".join(problems + missing) if problems or missing else "Complete scope, effective configuration and current verification support %s." % VULN_IDS[cid],
                    evidence + (detail or []))

    def scope(section_key, policy_key):
        section = mapping(root.get(section_key))
        required = names(policy.get(policy_key))
        missing, problems = [], []
        fact(section, "inventory_complete", missing, problems, section_key)
        if not required:
            missing.append("Define %s" % policy_key)
        return section, required, missing, problems

    def tested(item, label, missing):
        if not recent(item.get("tested_at")) or not item.get("test_reference"):
            missing.append("%s: need current test/observation and reference" % label)
        if not item.get("configuration_reference"):
            missing.append("%s: missing effective configuration/implementation reference" % label)

    # Declarative controls retain individual coverage and negative-test requirements.
    specifications = [
        ("GLAB-065", "failure_alerts", "logging_failure_events", ("detection_verified", "delivery_verified", "real_time_verified", "recipients_authorized")),
        ("GLAB-069", "enforcement_logging", "enforcement_actions", ("change_correlated", "enforcement_recorded", "individual_attribution_verified")),
        ("GLAB-070", "reauthentication", "reauthentication_triggers", ("trigger_exercised", "fresh_authentication_verified", "bypass_prevented")),
        ("GLAB-072", "piv_acceptance", "federal_piv_issuers", ("trust_approved", "identity_mapping_verified", "successful_authentication_verified")),
        ("GLAB-073", "piv_verification", "federal_piv_issuers", ("chain_verified", "validity_verified", "revocation_verified", "usage_verified", "identity_mapping_verified", "invalid_credentials_rejected")),
        ("GLAB-074", "third_party_credentials", "third_party_credential_providers", ("provider_approved", "credential_approved", "successful_authentication_verified", "invalid_credentials_rejected")),
        ("GLAB-075", "ficam_profiles", "ficam_profiles", ("profile_version_identified", "conformance_verified", "assurance_verified", "trust_verified", "claims_verified")),
        ("GLAB-077", "at_rest_integrity", "integrity_components", ("scope_coverage_verified", "cryptographic_integrity_verified", "verification_material_protected", "verification_success")),
        ("GLAB-078", "at_rest_confidentiality", "confidentiality_components", ("scope_coverage_verified", "encryption_verified", "key_management_verified", "approved_mechanism_verified")),
        ("GLAB-080", "dos_protection", "dos_safeguards", ("threat_coverage_verified", "safeguard_enabled", "effective_limits_verified", "bypass_prevented")),
        ("GLAB-081", "tls_versions", "tls_connections", ("approved_protocols_only", "certificate_validation_verified", "connection_coverage_verified")),
        ("GLAB-082", "export_ciphers", "tls_connections", ("effective_cipher_policy_verified", "export_ciphers_disabled", "capable_enumeration_verified")),
        ("GLAB-083", "transmission_crypto", "tls_connections", ("approved_algorithms_verified", "validated_modules_verified", "peer_validation_verified", "connection_coverage_verified")),
        ("GLAB-084", "transmission_preparation", "preparation_paths", ("confidentiality_verified", "integrity_verified", "staging_queues_ipc_reviewed", "boundary_coverage_verified")),
        ("GLAB-085", "reception", "reception_paths", ("confidentiality_verified", "integrity_verified", "decrypted_handoffs_reviewed", "boundary_coverage_verified")),
        ("GLAB-086", "invalid_input_behavior", "invalid_input_cases", ("expected_behavior_documented", "expected_behavior_observed", "no_unintended_state_change", "continued_operation_verified")),
    ]
    pending = {}
    for cid, key, policy_key, flags in specifications:
        section, required, missing, problems = scope(key, policy_key)
        for name in required:
            item = mapping(mapping(section.get("items")).get(name))
            tested(item, name, missing)
            for flag in flags:
                fact(item, flag, missing, problems, name)
            if cid in ("GLAB-069",):
                if not item.get("change_reference") or not item.get("enforcement_record_reference"):
                    missing.append("%s: missing correlated change/enforcement record references" % name)
            if cid in ("GLAB-074", "GLAB-075") and not item.get("approval_profile_reference"):
                missing.append("%s: missing applicable approval/profile reference" % name)
            if cid in ("GLAB-077", "GLAB-078", "GLAB-083") and not item.get("cryptographic_mechanism_reference"):
                missing.append("%s: missing cryptographic mechanism reference" % name)
            if cid == "GLAB-082":
                scan = mapping(mapping(local.get("cipher_scans")).get(name))
                accepted = names(item.get("accepted_ciphers")) + names(scan.get("accepted_ciphers"))
                if scan and scan.get("complete") is not True:
                    missing.append("%s: local cipher enumeration unavailable/incomplete" % name)
                if not accepted:
                    missing.append("%s: no enumerated cipher suites" % name)
                if any(re.search(r"(?:^|[_-])(?:EXP|EXPORT)(?:[_-]|$)", cipher, re.I) for cipher in accepted):
                    problems.append("%s: export cipher offered" % name)
                if not item.get("enumeration_capability_reference"):
                    missing.append("%s: require evidence the enumeration can detect export cipher support" % name)
            if cid == "GLAB-081":
                allowed = names(item.get("approved_protocols"))
                if not allowed:
                    missing.append("%s: identify the approved protocol policy" % name)
                scan = mapping(mapping(local.get("cipher_scans")).get(name))
                if allowed and any(protocol not in allowed for protocol in names(scan.get("protocols"))):
                    problems.append("%s: local enumeration observed an unapproved protocol" % name)
            if cid == "GLAB-086":
                if section.get("gitlab_version") != ev.get("version") or not ev.get("version"):
                    missing.append("Invalid-input behavior review must match installed GitLab version")
        pending[cid] = (missing, problems)

    section, volumes, missing, problems = scope("capacity_alerts", "log_storage_volumes")
    for volume in volumes:
        item = mapping(mapping(section.get("items")).get(volume))
        tested(item, volume, missing)
        threshold = number(item.get("threshold_percent"))
        if threshold is None or threshold <= 0:
            missing.append("%s: missing valid capacity threshold" % volume)
        elif threshold > 75:
            problems.append("%s: warning threshold exceeds 75 percent" % volume)
        for flag in ("volume_coverage_verified", "immediate_delivery_verified", "sa_delivery_verified", "isso_delivery_verified"):
            fact(item, flag, missing, problems, volume)
    pending["GLAB-064"] = (missing, problems)

    for cid, key in (("GLAB-066", "clock_comparison"), ("GLAB-067", "clock_correction")):
        section = mapping(root.get(key))
        missing, problems = [], []
        tested(section, key, missing)
        fact(section, "application_clock_coverage_verified", missing, problems, key)
        fact(section, "authoritative_source_verified", missing, problems, key)
        approved = names(policy.get("authoritative_time_sources"))
        if not approved or not section.get("source"):
            missing.append("Define approved authoritative sources and observed source")
        elif section["source"] not in approved:
            problems.append("Observed time source is not approved")
        if cid == "GLAB-066":
            interval = number(section.get("maximum_comparison_interval_seconds"))
            if interval is None or interval <= 0:
                missing.append("Missing effective maximum clock comparison interval")
            elif interval > 86400:
                problems.append("Clock comparison interval exceeds 24 hours")
            fact(section, "comparison_history_verified", missing, problems, key)
        else:
            limit, configured = number(policy.get("clock_max_offset_seconds")), number(section.get("correction_threshold_seconds"))
            if limit is None or limit < 0 or configured is None or configured < 0:
                missing.append("Define nonnegative organization and effective correction thresholds")
            elif configured > limit:
                problems.append("Effective correction threshold exceeds organization-defined offset")
            fact(section, "correction_behavior_verified", missing, problems, key)
        clock = mapping(local.get("clock"))
        if section.get("provider") == "chrony":
            if clock.get("tracking_available") is not True:
                missing.append("Local chrony tracking evidence unavailable")
            fact(section, "effective_source_polling_reviewed", missing, problems, key)
        elif not section.get("provider") or not section.get("runtime_reference"):
            missing.append("Identify clock provider and its runtime evidence")
        pending[cid] = (missing, problems)

    section, sources, missing, problems = scope("timestamp_precision", "timestamp_log_sources")
    for source in sources:
        item = mapping(mapping(section.get("items")).get(source))
        tested(item, source, missing)
        fact(item, "format_coverage_verified", missing, problems, source)
        sample = mapping(mapping(local.get("timestamp_logs")).get(source))
        if sample.get("coarse_count", 0):
            problems.append("%s: sampled timestamps have less than one-second granularity" % source)
        if sample.get("seconds_count", 0) and not sample.get("unknown_count", 0):
            pass
        else:
            precision = number(item.get("precision_seconds"))
            fact(item, "records_verified", missing, problems, source)
            if precision is None or precision <= 0:
                missing.append("%s: no verified timestamp precision" % source)
            elif precision > 1:
                problems.append("%s: timestamp precision is coarser than one second" % source)
            if sample.get("unknown_count", 0) and item.get("local_sample_reviewed") is not True:
                missing.append("%s: unknown local timestamp formats require review" % source)
    pending["GLAB-068"] = (missing, problems)

    section, paths, missing, problems = scope("revocation_cache", "pki_auth_paths")
    absent = not paths and section.get("inventory_complete") is True and section.get("none_present") is True and bool(section.get("scope_reference")) and not section.get("items")
    native = mapping(ev.get("gitlab_yml"))
    native = mapping(native.get("production", native))
    if absent and str(mapping(native.get("smartcard")).get("enabled")).lower() in ("true", "1", "yes"):
        absent = False
        missing.append("PKI absence contradicts enabled native smartcard authentication")
    if absent:
        results.add("GLAB-071", sc.NA, "Reviewed inventory establishes no PKI authentication: %s" % section["scope_reference"], evidence)
    else:
        for path in paths:
            item = mapping(mapping(section.get("items")).get(path))
            tested(item, path, missing)
            for flag in ("cache_present", "cache_freshness_verified", "path_validation_supported", "network_outage_exercised", "cached_validation_verified", "revoked_credentials_rejected"):
                fact(item, flag, missing, problems, path)
        pending["GLAB-071"] = (missing, problems)

    section, stores, missing, problems = scope("protected_session_trust", "protected_session_trust_stores")
    normalize = lambda value: re.sub(r"[:\s]", "", value.lower()) if isinstance(value, str) else ""
    approved = names(policy.get("approved_ca_fingerprints"))
    approved = [normalize(value) for value in approved]
    if not approved or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in approved):
        missing.append("Define approved CA SHA-256 fingerprints")
        approved = []
    for store in stores:
        item = mapping(mapping(section.get("items")).get(store))
        tested(item, store, missing)
        for flag in ("effective_trust_inventory_verified", "overrides_reviewed", "only_approved_authorities_verified"):
            fact(item, flag, missing, problems, store)
        sample = mapping(mapping(local.get("trust_bundles")).get(store))
        anchors = names(sample.get("fingerprints")) if sample.get("complete") is True else names(item.get("fingerprints"))
        if sample and sample.get("complete") is not True:
            missing.append("%s: incomplete local trust bundle measurement" % store)
        if not anchors:
            missing.append("%s: no effective trust anchor fingerprints" % store)
        for anchor in anchors:
            digest = normalize(anchor)
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                missing.append("%s: malformed trust anchor fingerprint" % store)
            elif approved and digest not in approved:
                problems.append("%s: unapproved certificate authority fingerprint" % store)
    pending["GLAB-076"] = (missing, problems)

    section = mapping(root.get("high_availability"))
    missing, problems = [], []
    if section.get("mac_i") is False and section.get("applicability_reference"):
        results.add("GLAB-079", sc.NA, "Documented system designation is not MAC I: %s" % section["applicability_reference"], evidence)
    else:
        if section.get("mac_i") is not True or not section.get("applicability_reference"):
            missing.append("Document MAC I applicability")
        tested(section, "high_availability", missing)
        for flag in ("cluster_verified", "dependency_coverage_verified", "replication_health_verified", "failover_exercised"):
            fact(section, flag, missing, problems, "high_availability")
        pending["GLAB-079"] = (missing, problems)

    section, components, missing, problems = scope("retired_components", "retired_components")
    if section.get("gitlab_version") != ev.get("version") or not ev.get("version") or not section.get("removal_policy_reference"):
        missing.append("Need approved post-upgrade removal policy for installed version")
    for component in components:
        item = mapping(mapping(section.get("items")).get(component))
        tested(item, component, missing)
        for flag in ("removal_required", "removed_verified", "running_processes_reviewed", "retained_components_reviewed"):
            fact(item, flag, missing, problems, component)
        sample = mapping(mapping(local.get("retired_paths")).get(component))
        paths = mapping(sample.get("paths"))
        if sample.get("complete") is not True or not paths:
            missing.append("%s: missing complete local retired-path inventory" % component)
        for path, present in paths.items():
            if present is True and item.get("removal_required") is True:
                problems.append("%s: prohibited superseded component still exists: %s" % (component, path))
    pending["GLAB-087"] = (missing, problems)

    # Emit in catalog order, including the two explicit applicability results above.
    for cid in sorted(pending):
        missing, problems = pending[cid]
        collection_key = {"GLAB-068": "timestamp_logs", "GLAB-076": "trust_bundles", "GLAB-087": "retired_paths"}.get(cid)
        if collection_key and any(error.startswith(collection_key + ":") for error in names(local.get("errors"))):
            missing.append("Incomplete local collection for %s" % collection_key)
        finish(cid, missing, problems)
    results.items[first_result:] = sorted(results.items[first_result:], key=lambda result: result["id"])


class FilterModule(object):
    def filters(self):
        return {}
