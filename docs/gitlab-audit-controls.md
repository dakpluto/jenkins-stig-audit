# GitLab audit controls: V-204715 through V-204720

GLAB-030 through GLAB-034 cover V-204715, V-204716, V-204718, V-204719 and V-204720 respectively. V-204717 remains covered by GLAB-023. Reports and checklists receive the new mappings automatically.

The collector reads at most the last 256 KiB / 200 lines of the current audit_json.log and exports only event type, actor/target identifiers and timestamps. Rotation and quiet systems can leave no matching evidence; sample absence produces Not_Reviewed, not Open. No service is restarted and no privileged operations are attempted. Collection errors appear in check evidence.

## Inventory configuration

```yaml
gitlab_stig_audit_control_evidence_file: /etc/gitlab/stig-audit-evidence.json
gitlab_stig_audit_controls:
  evidence_max_age_hours: 24
  nonrepudiation_actions: [user_admin_status_updated]
  aggregates_logs: false
  aggregation_scope_reference: "Architecture section 4: GitLab forwards to separate SIEM"
  aggregation_sources: []
  aggregation_tolerance_seconds: null
  approved_logging_principals: ['os:root', 'gitlab:alice']
  issm_approval_reference: 'ISSM authorization 42'
  privilege_operations: [admin_access]
```

Use actual event types available in the installed GitLab version/license. `admin_access` below is a normalized operation name for an external test report, not a claim that GitLab emits that event type. Do not equate permission changes or sign-ins with privileged-operation coverage. Include both success and failure observations.

For an aggregating host, set aggregates_logs=true, list every organization-required source and specify a nonnegative tolerance in seconds. Each source requires collector receipt, parseable timestamps, demonstrated correlation and a measured clock offset against the common authoritative time reference. Synchronization configuration alone does not prove correlation. A false applicability declaration requires a scope reference before Not_Applicable is returned.

## External evidence contract

The optional target JSON file supplies observations from a collector, access review or startup verification that the local role cannot independently establish. The role reads at most 1 MiB. Protect this file through the approved evidence management process; its contents are trusted audit inputs, not independently verified attestations. Reference a reviewable report containing the underlying configuration, records, version/license coverage assessment and measurement method. Never populate verification fields merely to obtain a pass.

`observed_at` must be timezone-aware, no later than collection time, and within evidence_max_age_hours (default 24). Missing, stale, unreferenced or malformed observations cannot produce a pass. Record timestamps must also be within this window. Use explicit JSON booleans. A verified false fact produces Open; missing facts produce Not_Reviewed. Existing gitlab_stig_overrides still apply and are reported through the normal override mechanism.

Example shape (values are illustrative; replace with measured facts):

```json
{
  "observed_at": "2026-11-12T12:00:00Z",
  "reference": "SIEM report 42 / access review 43 / startup report 44",
  "nonrepudiation": {
    "coverage_verified": true,
    "identity_binding_verified": true,
    "independent_retention_verified": true,
    "tamper_protection_verified": true
  },
  "aggregation": {
    "sources": {
      "puma": {
        "received": true,
        "timestamps_parseable": true,
        "correlation_verified": true,
        "clock_offset_seconds": -0.2
      }
    }
  },
  "logging_access": {
    "effective_principals": ["os:root", "gitlab:alice"],
    "scope_reviewed": {"os": true, "gitlab": true, "streaming": true}
  },
  "privilege_access": {"coverage_verified": true},
  "startup": {
    "automatic_logging_verified": true,
    "current_start_verified": true,
    "session_logging_verified": true,
    "application_started_at": "2026-11-12T10:00:00Z",
    "logging_started_at": "2026-11-12T09:59:59Z",
    "first_session_record_at": "2026-11-12T10:01:00Z"
  },
  "records": [
    {"event_type": "user_admin_status_updated", "actor": "alice", "target": "user:7", "time": "2026-11-12T11:00:00Z", "source": "SIEM record 1"},
    {"event_type": "admin_access", "outcome": "success", "actor": "alice", "target": "admin/users", "time": "2026-11-12T11:00:01Z", "source": "test record 2"},
    {"event_type": "admin_access", "outcome": "failure", "actor": "bob", "target": "admin/users", "time": "2026-11-12T11:00:02Z", "source": "test record 3"}
  ]
}
```

The access review must inventory everyone able to change event selection through OS root/sudo, groups, configuration management, GitLab administrator/delegated roles, group ownership and streaming filters. Principal names are namespace-qualified identifiers chosen by the organization. A reviewed scope that has no applicable controls may be marked reviewed=true with the reason in the referenced report. All effective principals must appear in the ISSM-approved list.

Startup evidence must verify the currently running application start, automatic logger configuration/supervision and an actual session record after startup. logging_started_at is the time logging became available, not the first event time; it must precede or equal application_started_at. Retained startup evidence can be examined without restarting production. These timestamps alone do not establish automatic startup; the referenced verification must support the three startup booleans.

External records contain only actor/target identifiers, event type, timestamp, outcome and source reference. Avoid tokens, headers, payloads and free-form sensitive messages: evidence is saved in the normal raw evidence report when enabled.

GitLab reference documentation: [event types](https://docs.gitlab.com/user/compliance/audit_event_types/), [security telemetry](https://docs.gitlab.com/security/security_telemetry/), [instance streaming](https://docs.gitlab.com/administration/compliance/audit_event_streaming/). Some events are streaming-only; presence of audit_json.log or a particular edition never proves complete coverage.

## Privileged recording and log protection: V-204727, V-204735?739

GLAB-035 through GLAB-040 add these six rules. The same dated external evidence file supports them. [Example external observations](examples/gitlab-audit-extended-evidence.json) illustrate the schema; the dates, tool list and verification values are examples, not production evidence. Merge the sections into the existing evidence object when using both sets of checks.

Add these keys to gitlab_stig_audit_controls (preserve the other policy keys):

```yaml
privileged_access_paths:
  sudo: full_command
  shared-admin: individual_identity
required_log_tools:
  - /opt/gitlab/embedded/bin/svlogd
approved_log_tool_writers: [root]
approved_log_tool_groups: [root]
backup_log_sources: [audit]
integrity_log_sources: [audit]
```

Set gitlab_stig_log_tool_paths separately to include additional absolute agent/tool/configuration paths. Required tools are automatically added to collection. Discovery also covers existing standard Omnibus logging binaries, gitlab-ctl, service log scripts, logrotate configuration, rsyslog/journald controls and common forwarder executables. This is a starting inventory: the referenced review must establish completeness, including deployment tooling, library/interpreter dependencies, enabled custom agents and controls not found automatically. Omitted custom tools prevent a defensible completeness attestation.

### GLAB-035 / V-204727

Define every applicable privileged access path, including sudo maintenance, Rails runner/console, shared GitLab accounts and relevant delegated or service-account operations. Each policy path selects full_command or individual_identity mode. The privileged_recording.paths observation must include configuration_verified=true, coverage_verified=true and at least one recent, sourced record meeting that mode. An explicit recording_gap=true or false configuration/coverage fact yields Open. Missing observations yield Not_Reviewed.

For full_command, the record needs actor, time, source, full_text_verified=true and command_record_reference pointing to the complete command in the protected source. The role does not retrieve command text: it can contain credentials. This path depends on the referenced inspection confirming full command capture rather than a truncated command, event name or URL. For individual_identity, provide account, a different individual, individual_identity_verified=true, time and source. A shared author_id or a service account name alone does not prove human attribution. The review must establish the identity binding; different strings by themselves are insufficient.

### GLAB-036/037/038 / V-204735/736/737

The target collector obtains owners, groups, modes, resolved targets and lexical/resolved ancestor metadata. It collects getfacl output with filenames for review. Discovery is limited to 128 paths and ACL output to 256 KiB, with a 15-second ACL command timeout. Missing tools, errors or truncation cannot produce a pass. Install getfacl on the target to obtain complete ACL evidence; the role does not install it.

log_tool_protection must have inventory_complete=true and effective_access_reviewed=true. Each discovered or required path must have access_restricted, modification_restricted and deletion_restricted observations. The reviewer must consider named ACL entries/masks, directory traversal, group membership, root/sudo, tool-specific read/execute policy, service controls and configuration management. Broad read/execute modes are not automatically findings: approved access depends on the tool's purpose. Local ACL text is retained as evidence, not automatically interpreted as a complete effective-access model.

For modification, the evaluator flags unapproved owners, unapproved writable groups and non-sticky world-writable files/directories. For deletion it evaluates directories rather than assuming file write permissions govern removal. Both ancestor chains are examined for symlinks. Sticky world-writable ancestors require review and remain Not_Reviewed. Required absent tools are Open; unknown metadata remains Not_Reviewed. Reviewed false restriction facts yield Open. Root-owned binaries alone cannot produce a pass.

### GLAB-039 / V-204738

List every required log source in backup_log_sources. log_backup.sources must provide per source:

- coverage_verified, separate_destination_verified and history_verified booleans;
- destination_reference identifying the other system/component;
- schedule_interval_hours and maximum_success_gap_hours, both positive and at most 168;
- last_success_at, a timezone-aware successful completion timestamp no more than 168 hours before collection.

A failed coverage/separation/history verification, an interval over seven days or an overdue last successful backup is Open. Missing or future timestamps, absent history and unknown destinations are Not_Reviewed. Maximum successful gap is measured from the reviewed backup history, not inferred from the cron interval. The evidence must cover a representative interval and identify it in the referenced report. Continuous forwarding is acceptable evidence only when the reviewed destination actually retains complete required logs as the approved backup arrangement. Neither forwarding configuration nor a normal GitLab backup command proves log backup coverage.

### GLAB-040 / V-204739

List protected sources in integrity_log_sources. log_integrity.sources must identify digital_signature, hmac, authenticated_storage or protected_hash_manifest as the mechanism. Each source needs coverage_verified, mechanism_approved, verification_material_protected and verification_success booleans, configuration_reference, verification_reference and a recent last_verified_at. Cryptographic verification occurs in the referenced system; this role validates the observations and freshness rather than signing logs or accessing keys. Protect verification keys/manifests independently from the logs and include applicable transport/storage coverage in the referenced assessment.

False verification/protection facts or tampering_detected=true are Open. Missing observations or unsupported mechanisms remain Not_Reviewed. HTTPS alone, a streaming bearer token, encryption without integrity authentication, file permissions and an unprotected adjacent checksum file do not establish retained-log cryptographic integrity. A protected hash manifest can qualify only when its trusted baseline and verification process are independently protected and approved.

All six checks default to Not_Reviewed. Local collection is read-only, does not restart services, run privileged test commands, perform backups, or modify integrity settings. External observations are trusted inputs whose references must substantiate their claims. No live GitLab/collector validation is performed by controller unit tests.

## Identity and session controls: V-204748/749/756/757/762?766

GLAB-041 through GLAB-049 cover these nine rules in order. [Authentication evidence example](examples/gitlab-auth-control-evidence.json) supplies the exact JSON schema. Its values are illustrative observations, not evidence of your deployment. Merge the auth_controls member into the same dated, referenced evidence file used by the earlier checks. Never place credentials, tokens, cookies, CSRF values or private certificate material in that file.

Add the applicable paths to gitlab_stig_audit_controls, preserving the other policy entries:

```yaml
group_auth_paths: [broker]
soap_endpoints: [gateway]
pki_auth_paths: [cac-idp]
authentication_interfaces: [gitlab-web]
peer_connections: [proxy-gitlab]
session_termination_methods: [logout, expiry]
session_generation_paths: [gitlab_web]
```

Each name is an organization-defined inventory key matching the corresponding evidence object. Include all applicable SSO/IdP, shared-account, native smartcard, gateway, browser, terminal and additional session-generation paths. A group/project token used by automation is not automatically a human group authenticator; the reviewed usage determines applicability. Inventory completeness is explicitly verified in each evidence section. False verified control facts yield Open, missing/invalid/stale evidence yields Not_Reviewed. Reviews are trusted external inputs; the role does not independently reproduce their claims.

### Scope and identity mapping

- **GLAB-041 / V-204748:** group_auth requires inventory_complete and paths keyed by group_auth_paths. Each path verifies individual_auth_required, bypass_prevented and traceability_verified. Representative sourced records identify individual and group_account separately and show individual_authenticated_at preceding or equaling group_used_at. Both timestamps must be recent. Observed reversed order is Open. An absence inventory may establish NotAFinding when no group authenticators are used; an empty list alone cannot.
- **GLAB-042 / V-204749:** soap requires inventory_complete and endpoints keyed by soap_endpoints. Each verifies ws_security_configured, authentication_enforced, unauthenticated_rejected and invalid_credentials_rejected, supported by configuration_reference and test_reference. HTTPS alone does not establish WS-Security. For ordinary GitLab without in-scope SOAP, use the documented absence format below, not a guessed SOAP URL returning 404.
- **GLAB-043 / V-204756:** pki_mapping requires inventory_complete and paths keyed by pki_auth_paths. Each verifies certificate_validated, mapping_configured, intended_account_verified and unmapped_identity_rejected; supply certificate_identity_reference, account_reference, configuration_reference and test_reference. For federation, trace certificate to IdP principal to GitLab account, including bypass controls and ambiguous/unmapped identity tests. Native smartcard enablement or a CA file alone cannot pass. The collector now retains the non-secret SAN mapping setting as supporting evidence.

For a reviewed absence, leave the associated policy list empty and set that evidence section to:

```json
{"inventory_complete": true, "none_present": true, "scope_reference": "reviewed deployment inventory section 4"}
```

This produces Not_Applicable for SOAP, PKI and peer authentication, or NotAFinding for group authentication. Use pki_mapping absence only when there is genuinely no PKI authentication path; enabled native smartcard configuration contradicts that claim and leaves the check Not_Reviewed. PKI absence does not satisfy the separate CAC/PIV requirements. Scope evidence must include custom gateways, co-hosted services and external IdP boundaries relevant to the assessment. Unknown scope remains Not_Reviewed.

### Input and peer authentication

- **GLAB-044 / V-204757:** input_masking requires inventory_complete and interfaces keyed by authentication_interfaces. Each supplies rendered_or_terminal_verified, all_secret_inputs_obscured and test_reference. Verify dummy input in every applicable secret-entry field without submitting real credentials. The existing unauthenticated sign-in-page response is parsed for candidate input types without exporting field values. Static HTML, especially without browser execution, does not establish computed visibility or JavaScript behavior, so it cannot alone pass or fail this rule. Rendered browser, IdP, smartcard middleware and terminal observations provide the complete result. Usernames need not be masked.
- **GLAB-045 / V-204762:** peer_auth requires inventory_complete and connections keyed by peer_connections. Each supplies both_peers_authenticated, peer_identity_verified, missing_credentials_rejected, untrusted_credentials_rejected and bypass_prevented with configuration_reference and test_reference. Verify both directions and effective trust/identity checks. A trusted source IP, ordinary server-authenticated HTTPS or a client certificate configured without verification is insufficient. Local sockets do not automatically prove no applicable peer connections; document the topology before claiming non-applicability.

### Sessions and RNG

All session observations reside under auth_controls.sessions. session_termination_methods must include logout and every other applicable termination mechanism, such as inactivity/absolute expiry, explicit revocation or IdP-triggered termination where supported/required. termination_inventory_complete establishes that the list was reviewed. termination.<method> needs authenticated_before, termination_completed, old_session_rejected, tested_at and test_reference. An old cookie still authenticating after confirmed termination is Open. A probe that never established an authenticated session or never completed termination is inconclusive, not proof of an invalidation defect.

Set generation_inventory_complete and generation.<path> for every session_generation_paths entry. Each path requires implementation_reference for the exact installed gitlab_version. This avoids applying a code review from one release to another.

- **GLAB-047 / V-204764:** implementation_verified, underlying_ids_unique and independent_sessions_verified, with recent tested_at and test_reference. Compare actual underlying session IDs through an approved controlled inspection or implementation-aware test. Do not export IDs. Different encrypted cookie values alone do not prove unique underlying identifiers.
- **GLAB-048 / V-204765:** implementation_verified, fabricated_rejected, tampered_rejected and fixation_rejected, with recent tested_at and test_reference. Confirm bogus identifiers cannot establish authentication and an identifier supplied before login cannot be used to replay the resulting authenticated session.
- **GLAB-049 / V-204766:** rng_path_traced, validated_module_verified and approved_runtime_verified, plus rng_backend, rng_reference, module_validation_reference and runtime_reference. Trace the actual installed generation path to an approved RNG within the validated module and its operational environment. The read-only Rails query now collects Ruby version, linked OpenSSL version, OpenSSL FIPS mode and configured session-store class. For rng_backend=openssl, missing runtime mode is inconclusive and explicitly disabled mode is Open. Approved runtime claims for other backends require the referenced runtime assessment. OS FIPS mode, package names, TLS settings or statistically random samples alone cannot pass this high-severity rule.

V-204764 and V-204765 share SRG-APP-000223. GLAB-047/048 carry explicit V-ID bindings so each changes only the intended checklist entry. Normal gitlab_stig_rule_map overrides remain available.

### Optional session-test workflow

The role remains read-only. Run [scripts/gitlab_session_probe.py](../scripts/gitlab_session_probe.py) explicitly from a trusted machine against a dedicated test account when you want active session evidence. It creates two local-password sessions and logs them out, so it is deliberately not called by an ordinary audit or Ansible check mode.

Supply GITLAB_SESSION_TEST_USER and GITLAB_SESSION_TEST_PASSWORD through your approved secret-injection method, then run:

```text
python scripts/gitlab_session_probe.py --url https://gitlab.example.mil --reference session-test-report-42 --ca-file /path/to/approved-ca.pem
```

Omit --ca-file to use system trust. TLS verification is mandatory; HTTP, credentials in URLs, query strings and fragments are rejected. Environment HTTP proxies and redirects are disabled, so credentials are never forwarded to an unexpected IdP or host. SSO-only, MFA, CAPTCHA and unsupported login flows return inconclusive observations without attempting to bypass them. GitLab installed under a relative URL can be addressed with that base path. The expected session cookie is _gitlab_session; other names require a separately reviewed test.

The probe checks that both sessions authenticate to the same account at /api/v4/user, tests fabricated/tampered cookies and fixation replay, compares opaque cookie values, logs out using the current CSRF token, and replays the original session cookie. Only confirmed JSON 401 Unauthorized responses count as rejection; redirects, WAF errors, outages and unexpected responses remain inconclusive. Authenticated state is checked before replay tests. Passwords, cookies and response bodies remain in memory and are not emitted. Cleanup attempts logout for both sessions, with a sanitized notice if cleanup is incomplete; revoke the dedicated account's test sessions when needed.

The JSON output is a partial evidence document, not a pass result. Merge its sessions.termination.logout and sessions.generation.gitlab_web observations into your reviewed evidence without erasing implementation/RNG/scope evidence. Retain the probe report at its reference and preserve the original tested_at timestamps. The probe does not declare inventory completeness, test expiry/revocation, inspect underlying IDs or prove a FIPS RNG. Those remain Not_Reviewed until separately verified. Invalidated or inactive test sessions should not be reused as independent evidence in a later run.

Reference documentation: [GitLab authentication implementation](https://docs.gitlab.com/development/authentication/), [session storage](https://docs.gitlab.com/development/session/), [smartcard identity mapping](https://docs.gitlab.com/administration/auth/smartcard/), [FIPS verification](https://docs.gitlab.com/development/fips_gitlab/), [mutual TLS configuration](https://docs.gitlab.com/omnibus/settings/ssl/).

## Storage, input and error handling: V-204770?774, V-204776

GLAB-050 through GLAB-055 cover these six rules in order. [Data control evidence example](examples/gitlab-data-control-evidence.json) provides the schema under data_controls in the existing dated, referenced external evidence file. The example values and digest are illustrative only; replace them with verified observations for your deployment. Missing coverage remains Not_Reviewed and verified false protection facts produce Open. These reviews are trusted audit inputs, not independent proof generated by the role.

Configure these gitlab_stig_audit_controls keys, preserving the existing policy values:

```yaml
storage_locations: [repositories, postgresql, uploads, artifacts, registry, logs, secrets, external-object-storage]
offline_copies: [backup-media]
management_inputs: [admin/session_timeout]
error_conditions: [authentication_failure, authorization_failure, validation_failure, application_exception]
error_outputs: [rails-errors, administrative-messages, http-error-responses]
required_log_tools: [/opt/gitlab/embedded/bin/svlogd]
```

Inventory keys are organization-defined names matching evidence entries. These lists are examples, not a complete inventory for every installation. Include CI job output, packages/LFS, temporary/swap locations, snapshots and external databases/storage wherever the applicable information is stored. The inventory_complete fact in each evidence section must establish that all relevant items were reviewed; listing one store or endpoint cannot establish system-wide coverage.

### GLAB-050 / V-204770

at_rest.locations.<name> requires confidentiality_verified, integrity_verified and effective_access_verified plus storage_reference, configuration_reference and verification_reference. Verify storage mapping, ownership/ACLs, approved access paths, storage-level protection and applicable integrity controls. Encryption is supporting evidence for confidentiality; it does not automatically establish integrity, and application encryption of selected secrets does not cover repositories or other data. Hypervisor/cloud volume and object-store facts can be supplied through their referenced assessments. There is no Not_Applicable result for an empty live-storage list.

### GLAB-051 / V-204771

offline.copies.<name> requires encryption_verified, cryptographic_integrity_verified, key_protection_verified and coverage_verified plus mechanism_reference, verification_reference and key_management_reference. Include exports, removable media, offline backups and offline snapshots within the assessed scope. Verify cryptographic confidentiality and integrity separately, along with protected key management and actual coverage of each copy. A backup job succeeding, an encrypted disk or a checksum stored beside a writable backup cannot alone establish this requirement.

When there are genuinely no offline copies, leave offline_copies empty and provide:

```json
{"inventory_complete": true, "none_present": true, "scope_reference": "reviewed offline-media and backup inventory", "copies": {}}
```

Place that object under data_controls.offline to return Not_Applicable. An empty list without a referenced absence inventory remains Not_Reviewed.

### GLAB-052 / V-204772

input_validation requires inventory_complete, gitlab_version matching the installed version, and implementation_reference. Each inputs.<name> needs server_validation_verified, type_format_verified, bounds_verified, unexpected_parameters_verified and invalid_input_rejected with recent tested_at and test_reference. Review the installed server-side implementation and representative invalid-input rejection tests for management UI/API fields, including custom gateways. The role does not submit management changes or run fuzzing against production. Referenced tests should run in an approved test environment and cover relevant parameter types, ranges, lengths, formats and unexpected parameters. A few HTTP 400 responses, client-side validation or a WAF alone cannot establish full coverage.

For an input specifically exempted by the organization, set exception=true and provide organization_approval_reference and exception_scope_reference identifying the exact exemption. Unapproved exemptions remain Not_Reviewed. Exceptions do not eliminate the version-specific implementation and complete-inventory requirements.

### GLAB-053 / V-204773

error_identification.conditions.<name> requires recognition_verified, configuration_reference and at least one recent record containing time and source. The collector can supply local records for authentication_failure (HTTP 401), authorization_failure (403), validation_failure (400/422), application_error (5xx) and application_exception (an exception field in JSON logs). These status-based categories are supporting observations; the referenced recognition review must confirm their security meaning and coverage for the deployment. Other classes, including session, TLS and component failures, need external sourced records and the same review. No event found in the bounded sample produces Not_Reviewed rather than Open.

### GLAB-054 / V-204774

error_sanitization requires inventory_complete, installed gitlab_version and implementation_reference. Each outputs.<name> needs sanitization_verified, corrective_information_verified and sensitive_disclosure_prevented with recent tested_at and test_reference. Include error logs, client responses and administrative messages. Review parameter filtering, exception handling, logging level and version-specific behavior. Verify useful diagnostic information as well as absence of sensitive exposure.

The collector reads at most the last 64 KiB and 200 lines from each of production_json.log, exceptions_json.log and api_json.log beside audit_json.log. It emits sample counts, category names and limited event metadata only. It never exports matching lines, parameter values, exception messages or response bodies. Pattern candidates include token shapes, private-key headers, credential assignments, bearer values and session cookies. Candidates are inconclusive until reviewed in the protected source; set sample_candidates_reviewed=true only when that referenced review resolves them. Confirmed disclosure should set sensitive_disclosure_prevented=false on the affected output, producing Open. A clean sample does not establish complete coverage.

For a controlled redaction test, optionally set gitlab_stig_error_canary to a unique NON-SECRET dummy marker used in an approved test. Its exact presence in a sampled error log produces Open without copying the marker into findings. Never put an actual credential in this variable. The role neither injects the marker nor triggers errors; arrange the controlled test separately. A marker not found in the current bounded tails is not proof of correct sanitization.

### GLAB-055 / V-204776

The collector hashes each discovered/required regular log-tool file with SHA-256, following the resolved target. It reads at most 32 MiB per file and 128 MiB across the existing 128-path inventory. It rejects changed-during-read files, unavailable files, special files and directories; enumerate concrete files instead of using a directory as a tool. Hash errors or truncated discovery prevent a pass. Newly discovered tools require baseline entries even if not explicitly listed in required_log_tools.

tool_integrity requires inventory_complete, baseline_authenticated, baseline_independently_protected, baseline_approved and baseline_reference. paths.<absolute-path>.sha256 contains the expected digest for each tool. The referenced approved manifest/signature or integrity-monitoring process must establish authentic provenance and independent protection of those expected values. The role measures current files and compares them; it does not authenticate a manifest signature itself. Do not create expected digests from the same unverified target during the audit. A trusted baseline mismatch or missing required tool produces Open; missing/untrusted baselines or collection errors remain Not_Reviewed. Verified false baseline-protection facts are Open.

This verifies the tool contents against a trusted cryptographic baseline; modes and ACLs remain separate GLAB-036?038 checks. Required inventory review must include relevant scripts, effective configuration and interpreter/library dependencies. RPM database integrity verification remains excluded; this check does not invoke rpm -V or alter package metadata. Baselines must be updated through the approved process after legitimate upgrades.

GLAB-050/051 and GLAB-053/054 have explicit V-ID bindings because each pair shares a base SRG identifier. Their checklist results remain independent.

## Management access and security attributes: V-204778?785

GLAB-056 through GLAB-063 cover these eight rules in order. [Management evidence example](examples/gitlab-management-control-evidence.json) shows the management_controls section of the same dated, referenced external evidence file. Replace illustrative values with observed deployment facts. Each section requires inventory_complete=true for a pass, and observations must satisfy the configured evidence freshness window. Missing scope or tests remain Not_Reviewed; verified false control facts produce Open. Referenced reviews and exercises remain trusted external inputs, not independently reproduced by the default role.

Add these organization-defined inventory keys under gitlab_stig_audit_controls, preserving the other entries:

```yaml
management_interfaces: [gitlab-web]
security_attributes:
  classification: [CUI]
processing_workflows: [repository-read]
transmission_paths: [repository-download]
remote_management_paths: [admin-web]
privileged_functions: [change-security-settings]
privileged_role_operations:
  administrator: [change-security-settings]
```

These are schema examples, not complete coverage lists. Include relevant management UI/API paths, delegated/custom roles, alternate gateways, authentication methods and privileged actions supported by the installed release/license. Empty lists do not establish non-applicability.

### GLAB-056/057 / V-204778/779

management_controls.logout.interfaces.<interface> supplies authenticated_before, visible_usable_control, user_initiated_logout_completed, old_session_rejected, explicit_message_visible, tested_at and test_reference. Verify the actual rendered management UI and exercise its user-accessible control. An API/script logout alone is supporting evidence, not proof that the user has a usable logout control. For GLAB-056, a visible usable control and successful user-initiated logout are required. For GLAB-057, completed user-initiated logout and a visible explicit termination confirmation are required. Both verify rejection of the previous authenticated session after completed logout.

A missing authentication precondition is inconclusive. Redirecting to the sign-in page is not an explicit logout message. A displayed success message while the prior session remains usable produces Open. The version-specific interface and applicable IdP/session boundaries should be described in the referenced test report. These checks complement GLAB-046's broader logout/expiry/revocation assessment rather than replacing it.

#### Optional rendered logout probe

[scripts/gitlab_logout_browser_probe.py](../scripts/gitlab_logout_browser_probe.py) adds a Playwright-based rendered exercise to the existing optional session-test workflow. Provision Python Playwright and Chromium separately in the approved test environment; neither is installed or launched by the role. Provide GITLAB_SESSION_TEST_USER and GITLAB_SESSION_TEST_PASSWORD through the same approved secret-injection method as the HTTP session probe. Use a dedicated account and run:

```text
python scripts/gitlab_logout_browser_probe.py --url https://gitlab.example.mil --reference logout-exercise-42 --interface gitlab-web --message-text "Signed out successfully"
```

The probe requires HTTPS with browser trust verification, blocks browser requests outside the supplied origin, and does not bypass MFA, SSO, CAPTCHA or unsupported forms. It attempts local-password login, verifies authenticated identity, finds a rendered visible/enabled logout control, clicks it, checks current unauthenticated state and replays the original cookies in an independent request context. API requests disable redirects. It then looks for visible explicit confirmation text. Credentials, cookie values, response bodies, screenshots, recordings and browser traces are never exported or saved.

--menu-selector and --logout-selector can adapt the installed GitLab UI. A selector miss remains inconclusive; it is not proof that logout is unavailable. With no --message-text, an English heuristic can identify a confirmation but a missed phrase remains inconclusive. Supply reviewed expected localized confirmation text to assess its absence; a wrong expected phrase can invalidate that observation, so retain the matcher in the test report. The probe is not a general authentication-interface crawler.

Merge the partial management_controls.logout.interfaces observation into the reviewed evidence file, preserving its tested_at timestamp, test reference and the reviewed inventory_complete fact. The script does not declare inventory completeness. Closing the browser is not counted as logout. It attempts explicit cleanup even after an unsupported UI flow; sanitized errors indicate when manual session revocation may be needed. A live deployment/browser exercise remains necessary beyond mocked controller tests.

### GLAB-058/059 / V-204780/781

Define security_attributes as attribute name to nonempty approved value lists. processing_attributes and transmission_attributes each need inventory_complete and policy_reference. Their paths.<inventory-key> objects supply binding_verified, lifecycle_coverage_verified, unauthorized_change_prevented, observed_attributes, configuration_reference, tested_at and test_reference. observed_attributes contains lists of actual values for every required attribute. Missing attributes are inconclusive; observed values outside the approved lists produce Open.

Inspect association throughout the relevant processing or transmission lifecycle. Representative paths may include Git operations, API retrieval, exports, artifact transfers, runners and gateways depending on the organization-defined information scope. A project-level security attribute, compliance framework or classification label alone does not prove preservation through processing or transmission. Verify the binding and any necessary integrity/access controls at each boundary. TLS alone does not establish security-attribute association. No policy defaults or automatic Not_Applicable result are inferred for these rules.

### GLAB-060 / V-204782

remote_access requires inventory_complete, approval_reference and paths keyed by remote_management_paths. Each path supplies method_approved, authentication_enforced, authorization_enforced, network_restrictions_verified, bypass_prevented, configuration_reference, tested_at and test_reference. The review must cover direct backend addresses, alternate ports, management APIs, proxies, host-level administration and any other relevant route, rather than only the advertised HTTPS endpoint. Existing port, TLS and Admin Mode checks provide supporting evidence but do not establish complete remote-method control.

### GLAB-061 / V-204783

remote_disconnect.paths.<path> supplies implemented, authorized_operators_verified, immediate_effect_verified, scope_coverage_verified, exercise_completed, mode, configuration_reference, procedure_reference, tested_at and test_reference. mode is disconnect, disable or both. Disconnect requires existing_connections_terminated=true; disable requires new_access_blocked=true; both requires both observations. Do not claim existing sessions/connections terminate merely because new connections are blocked. The reviewed exercise must substantiate immediate effect for the declared mode and full relevant scope.

The default audit never changes a firewall, disables an account/service, revokes management access or disconnects production sessions. Conduct the controlled exercise in an approved environment, record observed effects and restore its state through that exercise's procedure. The test report should identify authorization, timing, preconditions and applicability of existing session/connection behavior. A runbook without a completed exercise remains Not_Reviewed.

### GLAB-062 / V-204784

privileged_authorization requires inventory_complete, effective_roles_reviewed, installed gitlab_version and implementation_reference. functions.<function> supplies server_authorization_verified, safeguard_bypass_prevented, authorized_control_succeeded, nonprivileged_rejected, tested_nonprivileged_roles, tested_at and test_reference. Include privileged functions that can alter safeguards, along with UI/API/delegated/custom-role routes.

A known authorized positive control must establish that the operation exists and works before denial of a nonprivileged test role counts as meaningful evidence. Unavailable routes, invalid requests and unrelated proxy denials are inconclusive. If an authorized control succeeds and the nonprivileged user also succeeds, the result is Open. Review the installed implementation and effective roles; Admin Mode alone cannot pass. The role does not submit privileged changes or negative authorization tests to production.

### GLAB-063 / V-204785

privileged_logging requires inventory_complete, version_license_coverage_verified, installed gitlab_version, coverage_reference and roles keyed by privileged_role_operations. Each role needs delegation_impersonation_reviewed. Each operations.<operation> needs coverage_verified and recent records containing time, actor, target, source, the matching role/operation names and individual_attribution_verified=true. For impersonated=true, also provide impersonating_admin so the administrator remains traceable.

Verify coverage for the installed edition/license and version, including delegated administrators, group owners, custom roles and impersonation where applicable. Sign-ins and role assignment changes alone do not establish logging of privileged activity. A missing sample remains Not_Reviewed; an explicitly verified coverage gap produces Open. The source may be audit, application or controlled test records, but the coverage report must demonstrate that the required privileged actions are actually recorded. These checks complement GLAB-033/035 rather than assuming their passes establish this rule.

## Infrastructure, federation and transport controls

[GLAB-064?087 configuration and evidence](gitlab-infrastructure-controls.md) covers V-204790?793, V-204795, V-204797/798, V-204805?809 and V-204811?822. V-204810 is absent from the bundled SRG V4R6 index and is intentionally not mapped. The infrastructure checks share the same dated external evidence document and add bounded read-only clock, timestamp, trust-bundle and retired-file collection, with optional single-port cipher enumeration.

## Audit lifecycle, MFA and key assurance

[GLAB-088?101 configuration and evidence](gitlab-assurance-controls.md) covers V-204824/825/827?829/831?833, V-240925 and V-263550/552?555. These checks reuse privileged-role coverage and trust measurements where applicable, with separate V-ID results. Referenced identity, alerting, key-lifecycle and session-correlation evidence remains necessary. See [offline deployment](airgap-deployment.md) for the RHEL 8 runtime bundle.
