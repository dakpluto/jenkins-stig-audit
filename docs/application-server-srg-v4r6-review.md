# Application Server SRG V4R6 review

Reviewed 26 October 2026 against the repository's bundled V4R5 index, the official
V4R6 XCCDF, and DISA's V4R6 revision history. The benchmark date is 30 September
2026. This review covers GitLab, Jenkins, and Nexus; PostgreSQL uses a separate STIG.

## Sources and scope

- [Official DISA V4R6 archive](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Application_Server_V4R6_SRG.zip).
- Archive XCCDF: `U_Application_Server_V4R6_Manual_SRG/U_Application_Server_SRG_V4R6_Manual-xccdf.xml`.
- Archive revision history: `U_Application_Server_V4R6_Revision_History.pdf`, page 1.
- Archive SHA-256: `7527c3b2b42a8608650c27b3db7be2bcfbf39512859b814076eefe29f1c87aaa`.

The prior V4R5 archive is no longer available at the corresponding DISA download
URL. Metadata was compared directly to the committed V4R5 index; the assessment
of requirement changes relies on DISA's revision history, rather than a full
V4R5-to-V4R6 check/fix text diff.

## Findings

- Both indexes contain 137 rules. No Vuln IDs or full SRG requirement IDs were
  added or removed. Seventeen Rule IDs changed. Four titles changed DoD/DOD to
  DoW; one additional title lost trailing whitespace.
- DISA identifies the functional change as V-204833 / SRG-APP-000515-AS-000203
  increasing from medium (CAT II) to high (CAT I). Its requirement remains
  real-time log transfer for interconnected systems and weekly transfer for
  standalone systems.
- DISA identifies the remaining requirement edits as the DoD-to-DoW terminology
  change. Existing evidence collection and pass/fail logic do not need changes
  for that rename. Local setting names and deployed certificate issuer strings
  must continue to match actual systems; they should not be renamed automatically.

## Repository changes and limits

The shared bundled index now uses V4R6 Rule IDs, titles, release metadata and
severity. All three application audits use this index when no XCCDF is supplied.
Supply the V4R6 archive through the product's `*_stig_xccdf` setting to generate
V4R6 checklists; a supplied older XCCDF still controls its own checklist metadata.
Explicit rule maps pinned to any old SV Rule ID below must be updated. Vuln IDs
and full SRG requirement IDs are unchanged and remain valid map targets.

V-204833 has no automated check mapped to it. GLAB-026, JNKS-027, and NXRM-022
map to SRG-APP-000358 (off-loading), not SRG-APP-000515 (transfer timing). Finding
a forwarding configuration alone does not verify receipt or timeliness. Keep
V-204833 Not_Reviewed and obtain collector delivery evidence or a documented
weekly transfer procedure, as applicable. Do not map a passing forwarding check
to this CAT I rule without additional timing evidence. Other uncovered SRG rules
also remain manual review items; updating the index does not add full SRG coverage.

## Changed Rule IDs and related local checks

A related check below is a base-SRG match, not necessarily an automatic checklist
binding: several full SRG rules can share a base ID.

| Vuln ID | V4R6 Rule ID | Related checks |
| --- | --- | --- |
| V-204708 | SV-204708r1265167_rule | GLAB-009, NXRM-007, JNKS-009 |
| V-204716 | SV-204716r1265168_rule | Manual review; no mapped check |
| V-204740 | SV-204740r1265169_rule | Manual review; no mapped check |
| V-204743 | SV-204743r1265170_rule | GLAB-019, NXRM-016, JNKS-019 |
| V-204744 | SV-204744r1265171_rule | GLAB-018, NXRM-015, JNKS-018 |
| V-204745 | SV-204745r1265172_rule | GLAB-001, NXRM-001, JNKS-001 |
| V-204756 | SV-204756r1265175_rule | Manual review; no mapped check |
| V-204758 | SV-204758r1265176_rule | GLAB-013, NXRM-011, JNKS-013 |
| V-204770 | SV-204770r1265177_rule | Manual review; no mapped check |
| V-204798 | SV-204798r1265178_rule | Manual review; no mapped check |
| V-204800 | SV-204800r1265179_rule | GLAB-005, NXRM-004, JNKS-004 |
| V-204801 | SV-204801r1265180_rule | GLAB-005, NXRM-004, JNKS-004 |
| V-204807 | SV-204807r1265182_rule | Manual review; no mapped check |
| V-204811 | SV-204811r1265185_rule | Manual review; no mapped check |
| V-204832 | SV-204832r1265188_rule | GLAB-013, NXRM-011, JNKS-013 |
| V-204833 | SV-204833r1265166_rule | Manual review; no mapped check |
| V-204834 | SV-204834r1265191_rule | GLAB-021, JNKS-021 |
