"""Management logout, attribute binding, remote access and privileged activity checks."""
import stig_common as sc
from gitlab_audit_extended import mapping, names, number, timestamp


def evaluate_management_controls(results, ev, policy):
    raw = ev.get("audit_control_evidence")
    doc = mapping(raw if isinstance(raw, dict) else sc._json(raw or "{}"))
    now, observed = timestamp(ev.get("collected_at")), timestamp(doc.get("observed_at"))
    age = number(policy.get("evidence_max_age_hours", 24))
    valid = (isinstance(doc.get("reference"), str) and bool(doc["reference"].strip()) and now is not None and
             observed is not None and age is not None and age > 0 and 0 <= now - observed <= age * 3600)
    root = mapping(doc.get("management_controls")) if valid else {}
    evidence = ["Management control evidence reference: %s; observed_at: %s" %
                (doc.get("reference", "missing"), doc.get("observed_at", "missing"))]

    def recent(value):
        value = timestamp(value)
        return value is not None and now is not None and age is not None and age > 0 and 0 <= now - value <= age * 3600

    def fact(item, key, missing, problems, label):
        if item.get(key) is False:
            problems.append("%s: %s=false" % (label, key))
        elif item.get(key) is not True:
            missing.append("%s: missing verified %s" % (label, key))

    def finish(cid, missing, problems, success):
        results.add(cid, sc.OPEN if problems else sc.NR if missing else sc.NF,
                    "; ".join(problems + missing) if problems or missing else success, evidence)

    def scope(key, policy_key):
        section = mapping(root.get(key))
        required = names(policy.get(policy_key))
        missing, problems = [], []
        fact(section, "inventory_complete", missing, problems, key)
        if not required:
            missing.append("Define %s" % policy_key)
        return section, required, missing, problems

    def tested(item, missing, label):
        if not recent(item.get("tested_at")) or not item.get("test_reference"):
            missing.append("%s: missing recent test and source reference" % label)

    for cid, confirmation in (("GLAB-056", False), ("GLAB-057", True)):
        section, interfaces, missing, problems = scope("logout", "management_interfaces")
        for interface in interfaces:
            item = mapping(mapping(section.get("interfaces")).get(interface))
            tested(item, missing, interface)
            if item.get("authenticated_before") is not True:
                missing.append("%s: test did not establish an authenticated management session" % interface)
                continue
            if not confirmation:
                fact(item, "visible_usable_control", missing, problems, interface)
                fact(item, "user_initiated_logout_completed", missing, problems, interface)
            else:
                if item.get("user_initiated_logout_completed") is not True:
                    missing.append("%s: user-initiated logout was not completed" % interface)
                    continue
                fact(item, "explicit_message_visible", missing, problems, interface)
            if item.get("user_initiated_logout_completed") is True:
                fact(item, "old_session_rejected", missing, problems, interface)
        finish(cid, missing, problems, "All management interfaces provide verified user-initiated logout%s." %
               (" and explicit rendered termination confirmation" if confirmation else ""))

    attributes = mapping(policy.get("security_attributes"))
    for cid, key, policy_key in (("GLAB-058", "processing_attributes", "processing_workflows"),
                                 ("GLAB-059", "transmission_attributes", "transmission_paths")):
        section, paths, missing, problems = scope(key, policy_key)
        if not attributes or any(not isinstance(name, str) or not name or not names(values) for name, values in attributes.items()):
            missing.append("Define security_attributes with nonempty approved value lists")
        if not section.get("policy_reference"):
            missing.append("Missing organization-defined security attribute policy reference")
        for path in paths:
            item = mapping(mapping(section.get("paths")).get(path))
            tested(item, missing, path)
            for flag in ("binding_verified", "lifecycle_coverage_verified", "unauthorized_change_prevented"):
                fact(item, flag, missing, problems, path)
            observed_attrs = mapping(item.get("observed_attributes"))
            for name, allowed in attributes.items():
                values = names(observed_attrs.get(name))
                if not values:
                    missing.append("%s: no observed values for attribute %s" % (path, name))
                elif names(allowed) and any(value not in allowed for value in values):
                    problems.append("%s: unapproved values observed for attribute %s" % (path, name))
            if not item.get("configuration_reference"):
                missing.append("%s: missing attribute binding configuration/implementation reference" % path)
        finish(cid, missing, problems, "Required attribute types/values remain associated throughout all inventoried %s." %
               ("processing workflows" if cid == "GLAB-058" else "transmission paths"))

    section, paths, missing, problems = scope("remote_access", "remote_management_paths")
    if not section.get("approval_reference"):
        missing.append("Missing approved remote management methods policy")
    for path in paths:
        item = mapping(mapping(section.get("paths")).get(path))
        for flag in ("method_approved", "authentication_enforced", "authorization_enforced", "network_restrictions_verified", "bypass_prevented"):
            fact(item, flag, missing, problems, path)
        tested(item, missing, path)
        if not item.get("configuration_reference"):
            missing.append("%s: missing remote access configuration reference" % path)
    finish("GLAB-060", missing, problems, "All inventoried remote management methods have approved and verified access controls without bypass.")

    section, paths, missing, problems = scope("remote_disconnect", "remote_management_paths")
    for path in paths:
        item = mapping(mapping(section.get("paths")).get(path))
        for flag in ("implemented", "authorized_operators_verified", "immediate_effect_verified", "scope_coverage_verified"):
            fact(item, flag, missing, problems, path)
        tested(item, missing, path)
        if item.get("exercise_completed") is not True:
            missing.append("%s: no completed controlled disconnect/disable exercise" % path)
        if item.get("mode") not in ("disconnect", "disable", "both"):
            missing.append("%s: define disconnect/disable mode" % path)
        # Do not infer that blocking new connections terminates established sessions.
        if item.get("mode") in ("disconnect", "both"):
            fact(item, "existing_connections_terminated", missing, problems, path)
        if item.get("mode") in ("disable", "both"):
            fact(item, "new_access_blocked", missing, problems, path)
        for key in ("configuration_reference", "procedure_reference"):
            if not item.get(key):
                missing.append("%s: missing %s" % (path, key))
    finish("GLAB-061", missing, problems, "All remote management paths have exercised immediate disconnect/disable capability operated by authorized personnel.")

    section, functions, missing, problems = scope("privileged_authorization", "privileged_functions")
    if not ev.get("version") or section.get("gitlab_version") != ev.get("version") or not section.get("implementation_reference"):
        missing.append("Need privileged authorization implementation review for installed GitLab version")
    fact(section, "effective_roles_reviewed", missing, problems, "privileged_authorization")
    for function in functions:
        item = mapping(mapping(section.get("functions")).get(function))
        tested(item, missing, function)
        fact(item, "server_authorization_verified", missing, problems, function)
        fact(item, "safeguard_bypass_prevented", missing, problems, function)
        if item.get("authorized_control_succeeded") is not True:
            missing.append("%s: no authorized positive control for this operation" % function)
        else:
            fact(item, "nonprivileged_rejected", missing, problems, function)
        if not names(item.get("tested_nonprivileged_roles")):
            missing.append("%s: no tested nonprivileged roles" % function)
    finish("GLAB-062", missing, problems, "Effective server-side authorization prevents tested nonprivileged roles from executing all inventoried privileged functions and bypassing safeguards.")

    section = mapping(root.get("privileged_logging"))
    required = mapping(policy.get("privileged_role_operations"))
    missing, problems = [], []
    fact(section, "inventory_complete", missing, problems, "privileged_logging")
    fact(section, "version_license_coverage_verified", missing, problems, "privileged_logging")
    if not required:
        missing.append("Define privileged_role_operations for all applicable roles")
    if section.get("gitlab_version") != ev.get("version") or not ev.get("version"):
        missing.append("Privileged logging coverage must match the installed GitLab version")
    if not section.get("coverage_reference"):
        missing.append("Missing privileged activity coverage reference")
    for role, operations in required.items():
        if not names(operations):
            missing.append("%s: define required privileged operations" % role)
            continue
        role_ev = mapping(mapping(section.get("roles")).get(role))
        fact(role_ev, "delegation_impersonation_reviewed", missing, problems, role)
        for operation in operations:
            item = mapping(mapping(role_ev.get("operations")).get(operation))
            fact(item, "coverage_verified", missing, problems, "%s/%s" % (role, operation))
            records = item.get("records") if isinstance(item.get("records"), list) else []
            good = False
            for record in records:
                record = mapping(record)
                if not recent(record.get("time")) or not record.get("actor") or not record.get("target") or not record.get("source") or record.get("operation") != operation or record.get("role") != role:
                    continue
                if record.get("individual_attribution_verified") is not True:
                    continue
                if record.get("impersonated") is True and not record.get("impersonating_admin"):
                    continue
                good = True
            if not good:
                missing.append("%s/%s: missing recent attributable privileged activity record" % (role, operation))
    finish("GLAB-063", missing, problems, "All inventoried privileged role operations have verified coverage and attributable recent records, including applicable delegated/impersonated activity.")


class FilterModule(object):
    def filters(self):
        return {}
