"""GitLab identity, authentication UI, peer and session evidence evaluation.

External observations are scoped, dated audit inputs, not substitutes for tests.
Session cookies and credentials are never rendered into finding evidence.
"""
import json
import re
from html.parser import HTMLParser

import stig_common as sc
from gitlab_audit_extended import mapping, names, number, timestamp


class AuthInputs(HTMLParser):
    """Summarize candidate fields, without collecting values or executing page code."""
    def __init__(self):
        HTMLParser.__init__(self)
        self.fields = []

    def handle_starttag(self, tag, attrs):
        if tag != "input":
            return
        attrs = dict(attrs)
        field = attrs.get("name", "")
        kind = attrs.get("type", "text").lower()
        if kind in ("hidden", "submit", "button", "checkbox"):
            return
        if kind == "password" or re.search(r"password|passwd|(?:^|\[)(?:pin|otp_attempt|otp_code)(?:\]|$)", field, re.I):
            self.fields.append({"name": field[:100], "type": kind})


def evaluate_auth_controls(results, ev, policy):
    raw = ev.get("audit_control_evidence")
    doc = mapping(raw if isinstance(raw, dict) else sc._json(raw or "{}"))
    now, observed = timestamp(ev.get("collected_at")), timestamp(doc.get("observed_at"))
    age = number(policy.get("evidence_max_age_hours", 24))
    reference = doc.get("reference")
    valid = (isinstance(reference, str) and bool(reference.strip()) and now is not None and observed is not None and
             age is not None and age > 0 and 0 <= now - observed <= age * 3600)
    root = mapping(doc.get("auth_controls")) if valid else {}
    base_evidence = ["Authentication evidence reference: %s; observed_at: %s" %
                     (reference or "missing", doc.get("observed_at", "missing"))]

    base_evidence.extend(doc.get("session_probe_errors") if isinstance(doc.get("session_probe_errors"), list) else [])

    def recent(value):
        value = timestamp(value)
        return value is not None and now is not None and age is not None and age > 0 and 0 <= now - value <= age * 3600

    def fact(item, key, missing, problems, label):
        value = item.get(key)
        if value is False:
            problems.append("%s: %s=false" % (label, key))
        elif value is not True:
            missing.append("%s: missing verified %s" % (label, key))

    def finish(cid, missing, problems, success, extra=None):
        results.add(cid, sc.OPEN if problems else sc.NR if missing else sc.NF,
                    "; ".join(problems + missing) if problems or missing else success, base_evidence + (extra or []))

    def scope(key, policy_key, allow_absent=False):
        section = mapping(root.get(key))
        paths = names(policy.get(policy_key))
        missing, problems = [], []
        fact(section, "inventory_complete", missing, problems, key)
        # An empty list is unknown unless a reviewed inventory explicitly declares no paths.
        absent = section.get("none_present") is True and not paths and section.get("inventory_complete") is True and bool(section.get("scope_reference"))
        if not paths and not (allow_absent and absent):
            missing.append("Define %s or provide a reviewed absence inventory where applicable" % policy_key)
        if paths and section.get("none_present") is True:
            missing.append("Contradictory %s inventory: none_present with configured paths" % key)
        return section, paths, missing, problems, absent

    section, paths, missing, problems, absent = scope("group_auth", "group_auth_paths", True)
    for path in paths:
        item = mapping(mapping(section.get("paths")).get(path))
        for key in ("individual_auth_required", "bypass_prevented", "traceability_verified"):
            fact(item, key, missing, problems, path)
        records = item.get("records") if isinstance(item.get("records"), list) else []
        qualified = False
        for record in records:
            record = mapping(record)
            first, second = timestamp(record.get("individual_authenticated_at")), timestamp(record.get("group_used_at"))
            if first is None or second is None or not recent(record.get("group_used_at")) or not recent(record.get("individual_authenticated_at")):
                continue
            if not record.get("individual") or not record.get("group_account") or record.get("individual") == record.get("group_account") or not record.get("source"):
                continue
            if first > second:
                problems.append("%s: individual authentication follows group credential use" % path)
            else:
                qualified = True
        if not qualified:
            missing.append("%s: no recent correlated individual-authentication-before-group-use record" % path)
    finish("GLAB-041", missing, problems,
           "Reviewed inventory establishes no group authenticators are used." if absent else "All group authentication paths require prior individual authentication and traceable access.")

    section, endpoints, missing, problems, absent = scope("soap", "soap_endpoints", True)
    if absent:
        results.add("GLAB-042", sc.NA, "Reviewed service inventory establishes no in-scope SOAP services: %s" % section["scope_reference"], base_evidence)
    else:
        for endpoint in endpoints:
            item = mapping(mapping(section.get("endpoints")).get(endpoint))
            for key in ("ws_security_configured", "authentication_enforced", "unauthenticated_rejected", "invalid_credentials_rejected"):
                fact(item, key, missing, problems, endpoint)
            if not item.get("configuration_reference") or not item.get("test_reference"):
                missing.append("%s: need SOAP configuration and enforcement test references" % endpoint)
        finish("GLAB-042", missing, problems, "All in-scope SOAP endpoints enforce security extensions and secure authentication.")

    section, paths, missing, problems, absent = scope("pki_mapping", "pki_auth_paths", True)
    native = mapping(ev.get("gitlab_yml"))
    native = mapping(native.get("production", native))
    smartcard_enabled = mapping(native.get("smartcard")).get("enabled")
    if absent and str(smartcard_enabled).lower() in ("true", "yes", "1"):
        absent = False
        missing.append("PKI absence claim contradicts enabled native smartcard authentication")
    if absent:
        results.add("GLAB-043", sc.NA, "Reviewed authentication inventory establishes PKI authentication is not used: %s" % section["scope_reference"], base_evidence,
                    comments="PKI absence does not satisfy separate CAC/PIV authentication requirements.")
    else:
        for path in paths:
            item = mapping(mapping(section.get("paths")).get(path))
            for key in ("certificate_validated", "mapping_configured", "intended_account_verified", "unmapped_identity_rejected"):
                fact(item, key, missing, problems, path)
            if not item.get("certificate_identity_reference") or not item.get("account_reference") or not item.get("configuration_reference") or not item.get("test_reference"):
                missing.append("%s: missing certificate-to-principal-to-account mapping references" % path)
        finish("GLAB-043", missing, problems, "All PKI authentication paths map validated identities to the intended accounts and reject unmapped identities.")

    section, interfaces, missing, problems, _ = scope("input_masking", "authentication_interfaces")
    page = mapping(mapping(ev.get("http")).get("sign_in"))
    extra = []
    if page.get("status") == 200 and isinstance(page.get("content"), str):
        parser = AuthInputs()
        parser.feed(page["content"][:524288])
        extra.append("Static sign-in HTML candidate secret input types: %s" % ", ".join(sorted(set(f["type"] for f in parser.fields))))
        # A static response cannot establish rendered visibility, JS behavior or IdP/CLI coverage.
    for interface in interfaces:
        item = mapping(mapping(section.get("interfaces")).get(interface))
        for key in ("rendered_or_terminal_verified", "all_secret_inputs_obscured"):
            fact(item, key, missing, problems, interface)
        if not item.get("test_reference"):
            missing.append("%s: no rendered/terminal input test reference" % interface)
    finish("GLAB-044", missing, problems, "All inventoried authentication interfaces obscure applicable password, PIN and other secret input.", extra)

    section, connections, missing, problems, absent = scope("peer_auth", "peer_connections", True)
    if absent:
        results.add("GLAB-045", sc.NA, "Reviewed topology establishes no applicable peer connections: %s" % section["scope_reference"], base_evidence)
    else:
        for connection in connections:
            item = mapping(mapping(section.get("connections")).get(connection))
            for key in ("both_peers_authenticated", "peer_identity_verified", "missing_credentials_rejected", "untrusted_credentials_rejected", "bypass_prevented"):
                fact(item, key, missing, problems, connection)
            if not item.get("configuration_reference") or not item.get("test_reference"):
                missing.append("%s: missing peer authentication configuration/test references" % connection)
        finish("GLAB-045", missing, problems, "All applicable connections mutually authenticate peers and reject missing/untrusted credentials without bypass.")

    section = mapping(root.get("sessions"))
    methods = names(policy.get("session_termination_methods", ["logout"]))
    missing, problems = [], []
    fact(section, "termination_inventory_complete", missing, problems, "sessions")
    if "logout" not in methods:
        missing.append("session_termination_methods must include logout")
    for method in methods:
        item = mapping(mapping(section.get("termination")).get(method))
        if item.get("authenticated_before") is not True or item.get("termination_completed") is not True:
            missing.append("%s: replay test did not establish authentication and completed termination" % method)
        else:
            fact(item, "old_session_rejected", missing, problems, method)
        if not recent(item.get("tested_at")) or not item.get("test_reference"):
            missing.append("%s: missing recent replay test reference" % method)
    finish("GLAB-046", missing, problems, "Old authenticated sessions are rejected after logout and all inventoried termination mechanisms.")

    paths = names(policy.get("session_generation_paths", ["gitlab_web"]))
    for cid, keys, label in (
        ("GLAB-047", ("implementation_verified", "underlying_ids_unique", "independent_sessions_verified"), "unique session generation"),
        ("GLAB-048", ("implementation_verified", "fabricated_rejected", "tampered_rejected", "fixation_rejected"), "system-generated sessions"),
        ("GLAB-049", ("rng_path_traced", "validated_module_verified", "approved_runtime_verified"), "approved session RNG")):
        missing, problems, extra = [], [], []
        fact(section, "generation_inventory_complete", missing, problems, "sessions")
        if not paths:
            missing.append("Define session_generation_paths")
        for path in paths:
            item = mapping(mapping(section.get("generation")).get(path))
            for key in keys:
                fact(item, key, missing, problems, path)
            if not item.get("implementation_reference") or item.get("gitlab_version") != ev.get("version") or not ev.get("version"):
                missing.append("%s: require implementation reference for the installed GitLab version" % path)
            if cid != "GLAB-049":
                if not recent(item.get("tested_at")) or not item.get("test_reference"):
                    missing.append("%s: missing recent session test reference" % path)
            else:
                for key in ("rng_backend", "rng_reference", "module_validation_reference", "runtime_reference"):
                    if not item.get(key):
                        missing.append("%s: missing %s" % (path, key))
        if cid == "GLAB-049":
            rails = sc._json(ev.get("rails") or "{}")
            runtime = mapping(mapping(rails).get("session_crypto"))
            extra.append("Collected Ruby/OpenSSL session runtime: %s" % json.dumps(runtime, sort_keys=True))
            if runtime.get("openssl_fips_mode") is False and "gitlab_web" in paths:
                # Runtime false contradicts a claimed OpenSSL-backed approved configuration.
                item = mapping(mapping(section.get("generation")).get("gitlab_web"))
                if item.get("rng_backend") == "openssl":
                    problems.append("GitLab Ruby reports OpenSSL FIPS mode disabled for the declared OpenSSL RNG path")
            if "gitlab_web" in paths:
                item = mapping(mapping(section.get("generation")).get("gitlab_web"))
                if item.get("rng_backend") == "openssl" and runtime.get("openssl_fips_mode") is not True:
                    missing.append("Missing enabled Ruby/OpenSSL FIPS runtime evidence")
        finish(cid, missing, problems, "All declared generation paths have verified %s." % label, extra)


class FilterModule(object):
    def filters(self):
        return {}
