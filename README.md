# Jenkins Application Server SRG Audit (Ansible)

Read-only Ansible audit of RHEL 8 Jenkins controllers against the DISA
**Application Server Security Requirements Guide (SRG)**. DISA does not publish
a Jenkins-specific STIG, so the Application Server SRG is the governing
benchmark. This project turns its requirements into 29 concrete Jenkins checks.

The playbook **changes nothing on the target**. Every task only reads files,
runs status commands, makes unauthenticated `GET` requests, or does TLS
handshakes. It also works under `--check`.

## Outputs

Reports are written on the machine running `ansible-playbook`, under `reports/<host>/`:

| File | Contents |
|---|---|
| `*.html` | Human-readable report with status filters, evidence and remediation |
| `*.json` | Machine-readable results, summary, and SRG→Vuln ID binding |
| `*.csv` | One row per check, for POA&M / spreadsheet work |
| `*.ckl` | STIG Viewer checklist for the whole SRG (only when `jenkins_stig_xccdf` is set) |
| `*_evidence.json` | Raw collected evidence (secrets redacted), for assessor review |

## Quick start: run on the Jenkins controller itself

No SSH and no separate Ansible machine are needed. Copy this directory to the
Jenkins host and run it there:

```bash
sudo dnf install ansible-core        # RHEL 8 AppStream; the only dependency
cd jenkins-stig-audit
./run_local.sh                       # prompts for your sudo password if needed
# optional: produce a STIG Viewer .ckl too
./run_local.sh -e jenkins_stig_xccdf=stig/U_Application_Server_SRG_V#R#_Manual.zip
```

Reports are written under `./reports/<fqdn>/` on that host. `run_local.sh` runs
`ansible-playbook -i inventory/local.yml jenkins_stig_audit.yml`, and any extra
arguments are passed through (`--check`, `-e ...`, `-v`). Site settings still come from
`inventory/group_vars/jenkins.yml`. When run locally, modules use the same Python
as `ansible-playbook`, so the Python 3.6 limitation below doesn't apply.

Air-gapped hosts: `dnf download --resolve ansible-core` on a connected RHEL 8
machine and carry the RPMs across. For advisory checks, also bring
`update-center.actual.json` (see `jenkins_stig_update_center_file`).

## Quick start: run from a separate Ansible controller

```bash
# 1. Controller: ansible-core 2.16 recommended (see "Python on RHEL 8" below)
# 2. Put the target in inventory/hosts.yml under the 'jenkins' group
# 3. Optional: download the Application Server SRG from https://public.cyber.mil/stigs/
#    and drop the zip in ./stig/
ansible-playbook jenkins_stig_audit.yml \
  -e jenkins_stig_xccdf=stig/U_Application_Server_SRG_V#R#_Manual.zip
```

The account needs `sudo` (root) because it reads `JENKINS_HOME/secrets`, `/proc/<pid>/cmdline`, and `ss -p`.

### Python on RHEL 8
RHEL 8's `platform-python` is 3.6. **ansible-core 2.17+ cannot manage Python 3.6
targets**, so do one of these:
- use ansible-core **2.16** (shipped in RHEL 8.10 / 9 AppStream), or
- install `python3.9`+ on the target and set `ansible_python_interpreter`.

## How it works

```
discover.yml  find the RPM, the Jenkins JVM, JENKINS_HOME, WAR, service account
collect.yml   slurp config XML, stat permissions, plugins, rpm -V, ss, firewalld,
              FIPS, chrony, rsyslog, sudo rights, update-center cache
probe.yml     GET /login and /api/json without credentials; openssl s_client per TLS version
evaluate.yml  filter_plugins/jenkins_stig.py -> jenkins_stig_evaluate
report.yml    JSON / CSV / HTML / CKL on the controller
```

The pass/fail logic is all in `roles/jenkins_stig_audit/filter_plugins/jenkins_stig.py`,
which is plain Python with unit tests (`python -m unittest discover -s tests -v`).

## Checks

| ID | Check | SRG (base IDs) |
|---|---|---|
| JNKS-001 | Authentication required (security realm configured) | 000148, 000033 |
| JNKS-002 | Least-privilege authorization, no anonymous access (config + live probe) | 000033, 000340 |
| JNKS-003 | Self sign-up disabled | 000033 |
| JNKS-004 | DoD PKI (CAC/PIV) or MFA | 000149, 000391, 000392 |
| JNKS-005 | Lockout / password complexity (Jenkins' own user DB can't enforce these) | 000065, 000164 |
| JNKS-006 | LDAPS / StartTLS with certificate validation | 000172, 000439 |
| JNKS-007 | "Remember me" disabled | 000400 |
| JNKS-008 | Session inactivity timeout ≤ org limit | 000295 |
| JNKS-009 | Concurrent session limit (no native capability) | 000001 |
| JNKS-010 | DoD Notice & Consent banner on the login page | 000068 |
| JNKS-011 | HTTPS only; no exposed plaintext listener; https Jenkins URL | 000014, 000015, 000439, 000172 |
| JNKS-012 | No SSL / TLS 1.0 / 1.1 (live handshakes) | 000014, 000439 |
| JNKS-013 | FIPS mode + crypto policy, honored by the JVM | 000179, 000514 |
| JNKS-014 | Non-root, nologin, no sudo/wheel/docker service account | 000342 |
| JNKS-015 | JENKINS_HOME / secrets permissions, world-writable files | 000380, 000171 |
| JNKS-016 | WAR root-owned, `rpm -V` integrity | 000133 |
| JNKS-017 | 0 executors on built-in node; agent→controller security on | 000211 |
| JNKS-018 | Fixed/approved ports, SSH server, firewalld | 000142 |
| JNKS-019 | Plugin baseline: prohibited, unapproved, deprecated, disabled | 000141 |
| JNKS-020 | Security advisories for core/plugins, Java 17+, pending RPMs | 000456 |
| JNKS-021 | Security-disabling `-D` properties, CSRF, legacy API tokens | 000516 |
| JNKS-022 | Safe markup formatter, CSP not overridden | 000251 |
| JNKS-023 | No stack traces / version headers | 000266, 000267 |
| JNKS-024 | Audit Trail plugin installed with a logger | 000089, 000095–000100 |
| JNKS-025 | HTTP access log | 000016 |
| JNKS-026 | Log file/directory permissions | 000118, 000119, 000120 |
| JNKS-027 | Logs off-loaded (rsyslog forwarding / remote logger) | 000358 |
| JNKS-028 | Audit storage capacity and 75% alert (manual, with `df` evidence) | 000357, 000359 |
| JNKS-029 | chronyd active and synchronized | 000116, 000374 |

Statuses use STIG Viewer's terms: `Open`, `NotAFinding`, `Not_Applicable`, `Not_Reviewed`.
`Not_Reviewed` means the evidence was collected, but a person has to make the
determination. For example, checking that a SAML IdP actually enforces CAC.

## Mapping to Vuln IDs (.ckl)

This repo deliberately contains **no DISA Vuln/Rule IDs**. You supply the
current XCCDF, and every Vuln ID, Rule ID, title, check and fix text in the
checklist comes from DISA's file. Checks are bound to rules by base SRG ID:

- **One matching rule**: the check's status is written to that rule.
- **Several matching rules** (for example, the catch-all `SRG-APP-000516`): the
  rule stays `Not_Reviewed`, and the check's result is added to its comments.
  To resolve it, pin the check with `jenkins_stig_rule_map`:
  ```yaml
  jenkins_stig_rule_map:
    JNKS-021: [SRG-APP-000516-AS-000237]   # or V-xxxxxx / SV-xxxxxxrN_rule
  ```
- **No matching rule**: the SRG release doesn't contain that requirement. The
  JSON report's `srg_binding` lists these checks under `unmatched`.

Rules that no check covers stay `Not_Reviewed`, and you complete them in STIG Viewer.

## Tuning

All options are in `roles/jenkins_stig_audit/defaults/main.yml`. Set per-site
values in `inventory/group_vars/jenkins.yml`. The main ones:

| Variable | Purpose |
|---|---|
| `jenkins_audit_url` | Public URL when a reverse proxy terminates TLS, so banner/header/TLS checks test what users hit |
| `jenkins_stig_tls_termination` | `auto` (detects a :443 proxy), `jenkins`, or `proxy` |
| `jenkins_stig_max_session_timeout` | Organization-defined inactivity limit (minutes) |
| `jenkins_stig_approved_ports` / `_approved_plugins` | Turn JNKS-018/019 from manual review into automated checks |
| `jenkins_stig_update_center_file` | For air-gapped sites: a copy of `update-center.actual.json` on the controller, used for advisory checks |
| `jenkins_stig_overrides` | Record mitigations/risk acceptances. The original status is kept in the report |
| `jenkins_stig_fail_on` | For example `[high]` to fail the play on Open CAT I findings (CI gating) |
| `jenkins_stig_check_repo_updates` | Run `dnf check-update` for jenkins/java (needs repo access) |

## Scope notes

- This covers the **Jenkins application layer**. Run the **RHEL 8 STIG** (for example
  with the SCAP Compliance Checker or `ansible-lockdown/RHEL8-STIG` in audit mode)
  for the OS. A few checks here (FIPS, firewalld, chrony) overlap on purpose,
  because the SRG requires them for the application server.
- If Configuration-as-Code (`jenkins.yaml`) is in use, fix findings in the CasC
  file. Otherwise the next reload puts the old settings back.
- An automated result supports an assessor's determination but does not replace
  it. Review `Not_Reviewed` items and the SRG rules that no check covers.
