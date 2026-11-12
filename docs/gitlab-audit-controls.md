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
