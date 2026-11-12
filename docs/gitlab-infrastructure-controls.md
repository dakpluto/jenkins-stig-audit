# GitLab infrastructure, federation and transport checks

GLAB-064?087 cover 24 indexed requirements. V-204810 is absent from the bundled Application Server SRG V4R6 index; no rule or applicability result is invented for it. Assess a different checklist version against its actual rule contents before adding that mapping.

Use the existing gitlab_stig_audit_control_evidence_file on the target. Merge the infrastructure_controls section from the [example JSON](examples/gitlab-infrastructure-control-evidence.json) with the other evidence sections. Example dates, approvals, test results and fingerprints are illustrative, not live evidence. The outer observed_at must be recent, timezone-aware and not in the future; reference identifies the reviewable assessment. evidence_max_age_hours defaults to 24. Missing/stale evidence is Not_Reviewed, verified protection gaps are Open, and complete evidence produces NotAFinding. Evidence claims are trusted inputs whose referenced observations must substantiate their truth.

## Policy and collection inputs

The defaults file lists all organization-defined scopes under gitlab_stig_audit_controls. Empty scope lists mean unknown scope. Populate log_storage_volumes, logging_failure_events, authoritative_time_sources, clock_max_offset_seconds, timestamp_log_sources, enforcement_actions, reauthentication_triggers, federal_piv_issuers, third_party_credential_providers, ficam_profiles, protected_session_trust_stores, approved_ca_fingerprints, integrity_components, confidentiality_components, dos_safeguards, tls_connections, preparation_paths, reception_paths, invalid_input_cases and retired_components as appropriate. pki_auth_paths is reused from the existing identity checks.

Additional top-level collection variables map inventory names to local paths or network endpoints:

```yaml
gitlab_stig_timestamp_log_paths:
  audit: /var/log/gitlab/gitlab-rails/audit_json.log
gitlab_stig_trust_bundle_paths:
  gitlab: /etc/gitlab/approved-effective-ca-bundle.pem
gitlab_stig_retired_component_paths:
  old-agent: [/opt/retired-agent/bin/agent]
# Optional; no scan occurs unless explicitly configured. Install Nmap separately.
gitlab_stig_tls_cipher_endpoints:
  web: {host: gitlab.example.mil, port: 443}
```

Names must match the policy lists and evidence items. Inventory all relevant GitLab components, gateways, backends, outbound integrations and external services; the advertised web endpoint alone is insufficient. The role does not install scanners or dependencies, change the clock, revoke credentials, fill filesystems, send alerts, induce outages, trigger failover, submit malformed management changes or delete software.

The collector runs read-only chronyc tracking/sources commands and reads bounded chrony configuration metadata. It does not export key files. Includes, sourcedir and confdir make the local configuration inventory explicitly incomplete until the referenced effective-source review resolves them. Clock numbers alone do not establish authoritative-source approval or historical comparison frequency. For non-chrony clocks, supply provider-specific runtime evidence through the referenced assessment.

Timestamp collection reads at most 64 KiB / 200 lines from each of up to 16 configured JSON logs. It counts second-or-finer, minute-only and unknown formats without exporting log text or timestamps. time, created_at and timestamp fields are recognized; unknown/mixed formats require referenced review. Calendar/time components are validated. This measures representation granularity, not clock accuracy.

Trust collection reads up to eight PEM files, each at most 1 MiB / 256 certificates, and obtains each certificate's SHA-256 fingerprint with OpenSSL. It never exports private keys or certificate contents and does not inspect merely the first certificate of a bundle. Alternate encodings, unprocessed PEM objects, invalid certificates or command failures make collection incomplete. The effective trust inventory review must cover directories, environment overrides, embedded/system bundles, proxies and application-specific validators, not just the files chosen for collection.

Retired-path collection checks at most 64 components / 64 absolute paths per component using lstat. Access errors are inconclusive rather than mistaken for absence. Symlinks count as present. It does not invoke RPM integrity verification or remove anything; referenced package, deployment and running-process review supplies coverage beyond those paths.

Optional cipher enumeration runs Nmap ssl-enum-ciphers against only the configured host/port, using a TCP connect scan, capped at four endpoints. DNS/IP host strings and integer ports are validated; no shell or port-range argument is used. Network probes have bounded timeouts. The infrastructure collector has an overall command budget of 45 seconds, with eight seconds per command; unavailable, timed-out, oversized or malformed results stay inconclusive. Large trust inventories may require separately collected referenced evidence. A modern scanner that cannot offer legacy suites cannot prove absence of export ciphers: capable_enumeration_verified and enumeration_capability_reference must substantiate the enumeration capability independently. No TLS handshake or enumeration output is treated as proof of cryptographic module validation.

## Shared evidence structure

Most sections use inventory_complete=true and items keyed by the policy list. Each item supplies configuration_reference, recent tested_at, test_reference and the rule-specific facts below. Use JSON booleans, not strings. Configuration references must identify effective settings, not merely templates. Test references must identify observed outcomes and applicable scope. Unknown scope or absence of sample records does not prove a finding. No external messages are sent by these checks.

| Check / V-ID | Section / policy list | Required verification beyond shared fields |
|---|---|---|
| GLAB-064 / V-204790 | capacity_alerts / log_storage_volumes | threshold_percent must be positive and no greater than 75; volume_coverage_verified, immediate_delivery_verified, sa_delivery_verified, isso_delivery_verified. Verify actual receipt by both SA and ISSO without filling a production filesystem. |
| GLAB-065 / V-204791 | failure_alerts / logging_failure_events | detection_verified, delivery_verified, real_time_verified, recipients_authorized. Inventory all required logging failures and test routing/delivery. |
| GLAB-068 / V-204795 | timestamp_precision / timestamp_log_sources | format_coverage_verified plus usable local samples, or records_verified and precision_seconds greater than zero and no greater than one. Unknown local formats also need local_sample_reviewed. Explicit minute-only samples are Open. |
| GLAB-069 / V-204797 | enforcement_logging / enforcement_actions | change_correlated, enforcement_recorded, individual_attribution_verified, change_reference and enforcement_record_reference. A change event alone does not establish enforcement logging. |
| GLAB-070 / V-204798 | reauthentication / reauthentication_triggers | trigger_exercised, fresh_authentication_verified, bypass_prevented. Silent SSO or an existing session alone is insufficient. |
| GLAB-071 / V-204805 | revocation_cache / pki_auth_paths | cache_present, cache_freshness_verified, path_validation_supported, network_outage_exercised, cached_validation_verified, revoked_credentials_rejected. Exercise the actual validator at GitLab, gateway or IdP. Cached CRL/OCSP filenames alone cannot pass. |
| GLAB-072 / V-204806 | piv_acceptance / federal_piv_issuers | trust_approved, identity_mapping_verified, successful_authentication_verified. Include approved cross-agency credential acceptance. |
| GLAB-073 / V-204807 | piv_verification / federal_piv_issuers | chain_verified, validity_verified, revocation_verified, usage_verified, identity_mapping_verified, invalid_credentials_rejected. Acceptance alone is insufficient. |
| GLAB-074 / V-204808 | third_party_credentials / third_party_credential_providers | provider_approved, credential_approved, successful_authentication_verified, invalid_credentials_rejected and approval_profile_reference. Approval is externally established, never guessed from issuer names. |
| GLAB-075 / V-204809 | ficam_profiles / ficam_profiles | profile_version_identified, conformance_verified, assurance_verified, trust_verified, claims_verified and approval_profile_reference. Identify the applicable profile/version; SAML/OIDC enablement alone cannot pass. |
| GLAB-076 / V-204811 | protected_session_trust / protected_session_trust_stores | effective_trust_inventory_verified, overrides_reviewed, only_approved_authorities_verified. All measured effective fingerprints must match approved_ca_fingerprints. When local collection is unavailable, supply item.fingerprints from the referenced validator assessment. Incomplete configured local measurement prevents a pass. |
| GLAB-077 / V-204812 | at_rest_integrity / integrity_components | scope_coverage_verified, cryptographic_integrity_verified, verification_material_protected, verification_success and cryptographic_mechanism_reference. Confidentiality encryption does not prove integrity. |
| GLAB-078 / V-204813 | at_rest_confidentiality / confidentiality_components | scope_coverage_verified, encryption_verified, key_management_verified, approved_mechanism_verified and cryptographic_mechanism_reference. Define the protected information and components. |
| GLAB-080 / V-204815 | dos_protection / dos_safeguards | threat_coverage_verified, safeguard_enabled, effective_limits_verified, bypass_prevented. Cover required attack classes and dependencies, not merely one rate limiter. |
| GLAB-081 / V-204816 | tls_versions / tls_connections | approved_protocols_only, certificate_validation_verified, connection_coverage_verified and approved_protocols list. Locally observed protocols outside that list are Open. |
| GLAB-082 / V-204817 | export_ciphers / tls_connections | effective_cipher_policy_verified, export_ciphers_disabled, capable_enumeration_verified, accepted_ciphers and enumeration_capability_reference. Local or external EXP/EXPORT suite observations produce Open even if the claimed policy is clean. Failed/incomplete configured scans stay inconclusive. |
| GLAB-083 / V-204818 | transmission_crypto / tls_connections | approved_algorithms_verified, validated_modules_verified, peer_validation_verified, connection_coverage_verified and cryptographic_mechanism_reference. Include applicable inbound/backend/outbound paths. |
| GLAB-084 / V-204819 | transmission_preparation / preparation_paths | confidentiality_verified, integrity_verified, staging_queues_ipc_reviewed, boundary_coverage_verified. Include preparation before transport encryption starts. |
| GLAB-085 / V-204820 | reception / reception_paths | confidentiality_verified, integrity_verified, decrypted_handoffs_reviewed, boundary_coverage_verified. Include protection after edge decryption. |
| GLAB-086 / V-204821 | invalid_input_behavior / invalid_input_cases | expected_behavior_documented, expected_behavior_observed, no_unintended_state_change, continued_operation_verified. Section gitlab_version must match the installed version. Use controlled tests, not production fuzzing. |
| GLAB-087 / V-204822 | retired_components / retired_components | removal_required, removed_verified, running_processes_reviewed, retained_components_reviewed. Section gitlab_version and removal_policy_reference identify the approved post-upgrade state. Complete local path evidence is required; a required removed component still present is Open. |

## Clock comparison and correction

clock_comparison (GLAB-066 / V-204792) and clock_correction (GLAB-067 / V-204793) are global objects rather than items mappings. Both supply configuration_reference, tested_at, test_reference, application_clock_coverage_verified, authoritative_source_verified, source and provider. The source must be in authoritative_time_sources. The referenced review must resolve hostnames/pools and IPs, and cover internal application clocks rather than assuming every component uses the host clock.

clock_comparison adds maximum_comparison_interval_seconds, positive and at most 86400, plus comparison_history_verified. A currently synchronized clock does not establish that comparisons occur every 24 hours. clock_correction adds correction_threshold_seconds, nonnegative and no greater than clock_max_offset_seconds, plus correction_behavior_verified. Verify the actual correction behavior and organization-defined maximum offset; a service simply running is insufficient. Non-finite or invalid numbers are inconclusive.

For provider=chrony, local tracking must be available and effective_source_polling_reviewed must verify the effective polling configuration/history, including dynamic sources and includes. For other clock providers, supply runtime_reference. The read-only collector does not intentionally skew or correct time.

## Applicability and checklist binding

For V-204805 only, an empty pki_auth_paths list with revocation_cache.inventory_complete=true, none_present=true and scope_reference can establish Not_Applicable when no PKI authentication exists. Enabled native smartcard configuration contradicts that claim. PKI absence never satisfies the separate PIV/FICAM acceptance requirements.

high_availability (GLAB-079 / V-204814) is global. A current mac_i=false declaration with applicability_reference establishes Not_Applicable. MAC I is the system designation, not a CAT I vulnerability severity. When applicable, supply mac_i=true, applicability_reference, configuration_reference, tested_at, test_reference, cluster_verified, dependency_coverage_verified, replication_health_verified and failover_exercised. Multiple Rails nodes or backups alone do not establish end-to-end HA. Failover exercises occur outside the role.

All 24 checks carry explicit V-ID bindings, including HA/DoS and TLS-version/export-cipher pairs sharing a base SRG ID. The earlier GLAB-027 retains storage-allocation coverage but no longer binds the 75-percent-warning rule; GLAB-064 owns that result, so a broad manual storage check cannot suppress its automated result. Existing TLS checks with ambiguous base mappings remain supporting comments. V-204810 remains deliberately unmapped.

Reference documentation: [GitLab federal controls](https://docs.gitlab.com/security/hardening_nist_800_53/), [certificate trust](https://docs.gitlab.com/omnibus/settings/ssl/), [cipher enumeration](https://docs.gitlab.com/omnibus/settings/ssl/openssl_3/), [HA architectures](https://docs.gitlab.com/administration/reference_architectures/), [rate limits](https://docs.gitlab.com/administration/settings/user_and_ip_rate_limits/).
