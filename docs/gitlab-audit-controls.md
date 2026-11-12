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
