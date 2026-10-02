# DISA SRG/STIG Audits (Ansible): Jenkins, GitLab, Nexus, PostgreSQL

Read-only Ansible audits of RHEL servers against DISA benchmarks:

- **Jenkins**, **Omnibus GitLab** and **Sonatype Nexus Repository 3** against the
  **Application Server Security Requirements Guide (SRG)**. DISA publishes no
  product STIG for these, so each playbook turns the SRG into concrete product checks.
- **Crunchy Data PostgreSQL 16** against DISA's product STIG, the **Crunchy Data
  Postgres 16 STIG (V1R3)**, with one result per STIG rule.

| Playbook | Inventory group | Benchmark | Checks |
|---|---|---|---|
| `jenkins_stig_audit.yml` | `jenkins` | Application Server SRG | 29 (`JNKS-*`) |
| `gitlab_stig_audit.yml` | `gitlab` | Application Server SRG | 29 (`GLAB-*`) |
| `nexus_stig_audit.yml` | `nexus` | Application Server SRG | 24 (`NXRM-*`) |
| `postgres_stig_audit.yml` | `postgres` | Crunchy Data Postgres 16 STIG V1R3 | 111 (`CD16-00-*`, every rule) |

The playbooks **change nothing on the target**. Every task only reads files,
runs status commands, makes `GET` requests, or does TLS handshakes. They also
work under `--check`.

## Outputs

Reports are written on the machine running `ansible-playbook`, under `reports/<host>/`,
named `<host>_<product>_appsrv_srg_<date>.*`:

| File | Contents |
|---|---|
| `*.html` | Human-readable report with status filters, Vuln IDs, evidence and remediation |
| `*.json` | Machine-readable results, summary, and SRG→Vuln ID binding |
| `*.csv` | One row per check, for POA&M / spreadsheet work |
| `*.ckl` | STIG Viewer checklist for the whole SRG (only when `<product>_stig_xccdf` is set) |
| `*_evidence.json` | Raw collected evidence (secrets redacted), for assessor review |

## Quick start: run on the server itself

No SSH and no separate Ansible machine are needed. Copy this directory to the
server and run it there:

```bash
sudo dnf install ansible-core        # RHEL 8 AppStream; the only dependency
cd jenkins-stig-audit
./run_local.sh                       # Jenkins; prompts for your sudo password if needed
./run_local.sh gitlab                # Omnibus GitLab
./run_local.sh nexus                 # Sonatype Nexus Repository
./run_local.sh postgres              # Crunchy Data PostgreSQL 16
# optional: produce a STIG Viewer .ckl too
./run_local.sh gitlab -e gitlab_stig_xccdf=stig/U_Application_Server_SRG_V#R#_Manual.zip
```

Reports are written under `./reports/<fqdn>/` on that host. `run_local.sh [product]` runs
`ansible-playbook -i inventory/local.yml <product>_stig_audit.yml`, and any extra
arguments are passed through (`--check`, `-e ...`, `-v`). Site settings still come from
`inventory/group_vars/<product>.yml`. When run locally, modules use the same Python
as `ansible-playbook`, so the Python 3.6 limitation below doesn't apply.

Air-gapped hosts: `dnf download --resolve ansible-core` on a connected RHEL 8
machine and carry the RPMs across. For Jenkins advisory checks, also bring
`update-center.actual.json` (see `jenkins_stig_update_center_file`).

## Quick start: run from a separate Ansible controller

```bash
# 1. Controller: ansible-core 2.16 recommended (see "Python on RHEL 8" below)
# 2. Put the targets in inventory/hosts.yml under 'jenkins', 'gitlab' or 'nexus'
# 3. Optional: download the Application Server SRG from https://public.cyber.mil/stigs/
#    and drop the zip in ./stig/
ansible-playbook jenkins_stig_audit.yml \
  -e jenkins_stig_xccdf=stig/U_Application_Server_SRG_V#R#_Manual.zip
ansible-playbook gitlab_stig_audit.yml
ansible-playbook nexus_stig_audit.yml --ask-vault-pass   # if the API password is vaulted
```

The account needs `sudo` (root), because the audits read root-only configuration
and secrets files, `/proc/<pid>/cmdline`, and `ss -p`.

### Python on RHEL 8
RHEL 8's `platform-python` is 3.6. **ansible-core 2.17+ cannot manage Python 3.6
targets**, so do one of these:
- use ansible-core **2.16** (shipped in RHEL 8.10 / 9 AppStream), or
- install `python3.9`+ on the target and set `ansible_python_interpreter`.

## How it works

```
discover.yml  find the package, process, install/data directories, service account
collect.yml   read config (secrets redacted), stat permissions, rpm -V, logs, host evidence
probe         unauthenticated GETs; openssl s_client per TLS version
evaluate.yml  filter_plugins/<product>_stig.py -> <product>_stig_evaluate
report        JSON / CSV / HTML / CKL on the controller
```

The pass/fail logic is all in plain Python filter plugins with unit tests
(`python -m unittest discover -s tests -v`; the GitLab YAML test also uses PyYAML,
which Ansible ships):

- `roles/jenkins_stig_audit/filter_plugins/jenkins_stig.py`
- `roles/gitlab_stig_audit/filter_plugins/gitlab_stig.py`
- `roles/nexus_stig_audit/filter_plugins/nexus_stig.py`
- `roles/postgres_stig_audit/filter_plugins/postgres_stig.py`
- `roles/stig_common/`: the shared code for GitLab and Nexus (host evidence, HTTP/TLS
  probes, redaction, host-level checks, the XCCDF/.ckl/CSV/HTML reports and the
  bundled SRG index). The Jenkins role keeps its own copy of that code for now.

Statuses use STIG Viewer's terms: `Open`, `NotAFinding`, `Not_Applicable`, `Not_Reviewed`.
`Not_Reviewed` means the evidence was collected, but a person has to make the
determination. For example, checking that a SAML IdP actually enforces CAC.

## Jenkins checks

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

If Configuration-as-Code (`jenkins.yaml`) is in use, fix findings in the CasC
file. Otherwise the next reload puts the old settings back.

## GitLab checks

Written for **Omnibus GitLab** (`gitlab-ee`, `gitlab-ce` or `gitlab-fips` RPM). Evidence
comes from `/etc/gitlab/gitlab.rb`, the rendered `gitlab.yml`, `gitlab-ctl status`, file
permissions, and unauthenticated probes of `external_url`. Application settings (sign-up,
2FA, session length, visibility and so on) live in the database, so the role reads them
with a read-only `gitlab-rails runner` script. Rails boot alone often takes 5 minutes or more
(the limit is `gitlab_stig_rails_timeout`, 30 minutes by default); set
`gitlab_stig_query_settings: false` to skip it, and those checks become `Not_Reviewed`.
The sign-in page can also be slow to render on a busy server, so each HTTP probe waits up to
`gitlab_stig_http_timeout` seconds (60 by default).

| ID | Check | SRG (base IDs) |
|---|---|---|
| GLAB-001 | LDAP/SAML/OIDC/smartcard in use and local password web sign-in disabled | 000148 |
| GLAB-002 | Public visibility restricted; no projects listed anonymously (live probe) | 000033 |
| GLAB-003 | Self-registration disabled (or admin approval required) | 000033 |
| GLAB-004 | MFA enforced (2FA, smartcard, or an MFA IdP) | 000149, 000820 |
| GLAB-005 | PIV/CAC accepted and verified (smartcard or CAC IdP) | 000391, 000392 |
| GLAB-006 | LDAP uses `simple_tls`/`start_tls` with `verify_certificates` | 000172, 000439 |
| GLAB-007 | "Remember me" disabled | 000400 |
| GLAB-008 | Session duration ≤ org limit | 000295 |
| GLAB-009 | Concurrent session limit (no native capability) | 000001 |
| GLAB-010 | DoD banner on the sign-in page and acknowledged via enforced Terms | 000068, 000069 |
| GLAB-011 | HTTPS external_url; HTTP redirects to HTTPS; Puma/Workhorse not exposed | 000014, 000015, 000439, 000172 |
| GLAB-012 | No SSL / TLS 1.0 / 1.1 (live handshakes) | 000014, 000439 |
| GLAB-013 | FIPS mode + crypto policy, and the `gitlab-fips` package | 000179, 000514 |
| GLAB-014 | Service accounts unprivileged; app processes not root | 000342 |
| GLAB-015 | `gitlab.rb`, `gitlab-secrets.json`, TLS keys 0600; `initial_root_password` removed | 000380, 000171, 000176 |
| GLAB-016 | `/opt/gitlab` root-owned, `rpm -V` integrity | 000133 |
| GLAB-017 | Admin Mode enabled; no GitLab Runner on the server | 000211 |
| GLAB-018 | Approved ports, internal components on loopback, firewalld | 000142 |
| GLAB-019 | Bundled services baseline; Service Ping / Gravatar off | 000141 |
| GLAB-020 | Version ≥ org minimum; pending RPM updates | 000456, 001035 |
| GLAB-021 | Webhooks/integrations cannot reach the local network (SSRF) | 000516 |
| GLAB-022 | `/api/v4/version` not anonymous; no version in `Server` header | 000266, 000267 |
| GLAB-023 | Audit events recorded (`audit_json.log`; CE is limited) | 000089, 000095–000100, 000503, 000509 |
| GLAB-024 | NGINX access log | 000016 |
| GLAB-025 | Log file/directory permissions | 000118, 000119, 000120 |
| GLAB-026 | Logs off-loaded (`udp_log_shipping_host` or rsyslog) | 000358 |
| GLAB-027 | Audit storage capacity and 75% alert (manual, with `df` evidence) | 000357, 000359 |
| GLAB-028 | chronyd active and synchronized | 000116, 000374, 000920 |
| GLAB-029 | No active accounts idle > 35 days; dormant-user deactivation | 000163, 000705 |

## Nexus Repository checks

Written for **Nexus Repository 3** run from the tarball or RPM (the role finds the install and
`sonatype-work` directories from the running JVM, or from `nexus_install_dir` /
`nexus_data_dir`). Realms, anonymous access, users and LDAP settings are kept in
Nexus' database and are only exposed by its REST API. To evaluate them, give the role a
**read-only account**. Create a role with the privileges `nx-settings-read`,
`nx-users-read`, `nx-ldap-read` and `nx-repository-view-*-*-browse`, assign it to a
dedicated local user, and set:

```yaml
nexus_stig_api_user: stig-audit
nexus_stig_api_password: !vault |       # ansible-vault encrypt_string '...' --name nexus_stig_api_password
  ...
```

Without it, NXRM-001 to NXRM-005 are `Not_Reviewed`. However, repositories
visible anonymously and `nexus.security.randompassword=false` are still reported.
The API calls are `GET`s only, and password fields are removed from the stored responses.

| ID | Check | SRG (base IDs) |
|---|---|---|
| NXRM-001 | LDAP/SAML/PKI realm active and the local realm not active (API) | 000148 |
| NXRM-002 | Anonymous access disabled (API + live probe) | 000033 |
| NXRM-003 | Shared `admin` account disabled; no default password (`randompassword=false`) | 000153 |
| NXRM-004 | PIV/CAC or MFA (Remote User Token realm behind a CAC proxy, or SAML) | 000149, 000391, 000392, 000820 |
| NXRM-005 | LDAP connections use LDAPS (API) | 000172, 000439 |
| NXRM-006 | Session timeout ≤ org limit (manual; not exposed by the API) | 000295 |
| NXRM-007 | Concurrent session limit (no native capability) | 000001 |
| NXRM-008 | DoD Notice & Consent banner before login | 000068, 000069 |
| NXRM-009 | HTTPS only; no exposed plaintext Jetty listener | 000014, 000015, 000439, 000172 |
| NXRM-010 | No SSL / TLS 1.0 / 1.1 (live handshakes) | 000014, 000439 |
| NXRM-011 | FIPS mode + crypto policy; RHEL JDK rather than the bundled JDK | 000179, 000514 |
| NXRM-012 | Non-root, nologin, no sudo/wheel/docker service account | 000342 |
| NXRM-013 | Data dir, `nexus-store.properties`, keystores restricted; `admin.password` removed | 000380, 000171, 000176 |
| NXRM-014 | Install directory not writable by the service account; `rpm -V` | 000133 |
| NXRM-015 | Approved ports, firewalld | 000142 |
| NXRM-016 | Groovy scripting disabled; repository inventory | 000141 |
| NXRM-017 | Version ≥ org minimum; Java 17+ | 000456, 001035 |
| NXRM-018 | No version in the `Server` header | 000266, 000267 |
| NXRM-019 | Audit capability writing `log/audit/audit.log` | 000089, 000095–000100, 000503, 000509 |
| NXRM-020 | Jetty request log | 000016 |
| NXRM-021 | Log file/directory permissions | 000118, 000119, 000120 |
| NXRM-022 | Logs off-loaded (rsyslog imfile + forwarding) | 000358 |
| NXRM-023 | Audit storage capacity and 75% alert (manual, with `df` evidence) | 000357, 000359 |
| NXRM-024 | chronyd active and synchronized | 000116, 000374, 000920 |

## Crunchy Data PostgreSQL 16 (product STIG)

Written for **Crunchy Data PostgreSQL 16** (PGDG-layout RPMs: `/usr/pgsql-16`,
`postgresql-16` service, `PGDATA=/var/lib/pgsql/16/data`; all configurable). Because this is a
product STIG, every one of its 111 rules gets its own result, named by its STIG ID
(`CD16-00-000100` ...) and bound directly to its Vuln ID. Titles and fix text in the
report are DISA's (`roles/postgres_stig_audit/files/crunchy_pg16_stig_index.json`).
For a STIG Viewer checklist, pass the STIG's XCCDF:
`-e postgres_stig_xccdf=stig/U_Crunchy_Data_Postgres_16_V1R3_Manual_STIG.zip`.

How the evidence is gathered (all read-only):

- **SQL**: `psql` runs as `postgres` over the local socket with
  `default_transaction_read_only=on`. It reads `pg_settings`, `pg_file_settings`, roles,
  password *types* (never the hashes), `pg_hba_file_rules`, `pg_ident_file_mappings`,
  and in each database the extensions, untrusted languages, `SECURITY DEFINER`
  functions, schema privileges and object owners. If psql cannot connect, settings
  come from `postgresql.conf`/`postgresql.auto.conf` and `pg_hba.conf`, and the
  role/extension rules are `Not_Reviewed`.
- **Files**: ownership and modes of `PGDATA` (recursively), the config, SSL key/CRL and
  log files, and `/usr/pgsql-16` (and which RPMs own its files).
- **Host**: FIPS mode and the OpenSSL FIPS provider, rsyslog forwarding, disk usage.

Many of DISA's check procedures *write* to the database (`CREATE ROLE bob`, a test table,
a failed login) and then look for the log entry. The audit does not do that. For those
rules it verifies the configuration that produces the record (logging enabled,
`log_min_messages`/`log_min_error_statement`, `pgaudit.log` classes, `log_connections`)
and shows how many `AUDIT:`, `permission denied`, `connection authorized` and `FATAL`
entries the newest log already holds. Each such result carries a comment saying so;
run the test during the assessment if your assessor requires it.

What is automated:

| Area | Rules |
|---|---|
| pgaudit preloaded and `pgaudit.log` classes (`role, read, write, ddl`), `log_catalog` | 000500, 000700, 000900, 009400–011100, 011400, 011800 |
| Logging enabled so denials/errors are recorded; `log_line_prefix` tokens; connections/disconnections | 000400, 000800, 001000–001500, 007600, 007900, 009000, 009500–011900 (denial rules), 011200–012000 |
| Log file mode 0600 and ownership; `client_min_messages = error` | 002000–002200, 006000, 006100 |
| PGDATA/config/software ownership and permissions; pgaudit files root-owned; only PostgreSQL RPMs in `/usr/pgsql-16` | 000600, 002300–002600, 002800, 005600 |
| `pg_hba.conf`: gss/sspi/ldap/cert only (plus documented exceptions), no `trust`, no `password`/`md5`, `hostssl … cert clientcert=verify-ca` + CRL | 000200, 003600, 003900, 004000 |
| `scram-sha-256` storage, SSL on, private key protection, DoD-issued certificate, FIPS | 003800, 004100, 004400, 004900, 008400, 008800, 008900, 012200, 012300 |
| Superusers/admin attributes, connection limits, keepalives/`statement_timeout`, extensions, untrusted languages, `SECURITY DEFINER`, PUBLIC `CREATE` | 000100, 003200, 003400, 004600, 004700, 006800, 006900, 007700, 007800 |
| Port, `log_timezone`, syslog + forwarding, single PostgreSQL major version, version ≥ org minimum | 003500, 007000, 007500, 008000, 009100–009300, 012400 |

The remaining rules (documentation, procedures, application code review, encryption at rest,
security labels) are `Not_Reviewed` with the relevant evidence attached; record the
outcome with `postgres_stig_overrides` (keyed by STIG ID). Organization-defined values,
such as approved superusers, extensions, ports, `pg_hba.conf` exceptions, `max_connections`,
the minimum version, and whether the system is classified, are in
`roles/postgres_stig_audit/defaults/main.yml`. Until `postgres_stig_classified` is set,
CD16-00-008300 is `Not_Reviewed`. `SECURITY DEFINER` functions installed by an approved
extension (such as pgaudit's event-trigger functions) pass CD16-00-006900.

## Mapping to Vuln IDs (.ckl)

The PostgreSQL audit binds each result to its own Vuln ID. The rest of this section
applies to the SRG-based audits.

The HTML report always shows each check's Vuln IDs (V-xxxxxx) and full
`SRG-APP-xxxxxx-AS-xxxxxx` rule versions. Without `<product>_stig_xccdf` they come
from a bundled index of the Application Server SRG V4R5
(`roles/stig_common/files/app_server_srg_index.json`: Vuln ID, Rule ID, rule
version and title only). The `.ckl` still needs the XCCDF you supply, and when
it is set every Vuln ID, Rule ID, title, check and fix text comes from DISA's
file instead of the index. Checks are bound to rules by base SRG ID:

- **One matching rule**: the check's status is written to that rule.
- **Several matching rules** (for example, the catch-all `SRG-APP-000516`): the
  rule stays `Not_Reviewed`, and the check's result is added to its comments.
  To resolve it, pin the check with `<product>_stig_rule_map`:
  ```yaml
  jenkins_stig_rule_map:
    JNKS-021: [SRG-APP-000516-AS-000237]   # or V-xxxxxx / SV-xxxxxxrN_rule
  ```
- **No matching rule**: the SRG release doesn't contain that requirement. The
  JSON report's `srg_binding` lists these checks under `unmatched`.

Rules that no check covers stay `Not_Reviewed`, and you complete them in STIG Viewer.

## Tuning

All options are in each role's `defaults/main.yml`. Set per-site values in
`inventory/group_vars/<product>.yml`. Each product has the same core options, with
its own prefix (`jenkins_stig_`, `gitlab_stig_`, `nexus_stig_`):

| Variable | Purpose |
|---|---|
| `<product>_audit_url` | Public URL when a reverse proxy terminates TLS, so banner/header/TLS checks test what users hit |
| `*_tls_termination` | `auto` (detects a :443 proxy), the product name, or `proxy` |
| `*_max_session_timeout` | Organization-defined inactivity limit (minutes) |
| `*_approved_ports` | Turns the ports check from manual review into an automated one |
| `*_overrides` | Record mitigations/risk acceptances. The original status is kept in the report |
| `*_fail_on` | For example `[high]` to fail the play on Open CAT I findings (CI gating) |
| `*_check_repo_updates` | Run `dnf check-update` for the product (needs repo access) |
| `*_xccdf` / `*_rule_map` | SRG XCCDF for the `.ckl`, and pinned rule bindings |

Product-specific options:

| Variable | Purpose |
|---|---|
| `jenkins_stig_approved_plugins` / `_prohibited_plugins` | Plugin baseline for JNKS-019 |
| `jenkins_stig_update_center_file` | For air-gapped sites: a copy of `update-center.actual.json` on the controller, used for advisory checks |
| `gitlab_stig_min_version` / `nexus_stig_min_version` | Lowest acceptable release; turns GLAB-020 / NXRM-017 into automated checks |
| `gitlab_stig_approved_services` | `gitlab-ctl status` service baseline for GLAB-019 |
| `gitlab_stig_expected_settings` | Application settings and their required values (GLAB-019) |
| `gitlab_stig_query_settings` / `gitlab_stig_rpm_verify` | Skip the slower `gitlab-rails runner` / `rpm -V` steps |
| `nexus_stig_api_user` / `nexus_stig_api_password` | Read-only REST API account (see above) |
| `nexus_install_dir` / `nexus_data_dir` | Set when Nexus is stopped and not in a standard location |

## Scope notes

- These audits cover the **application layer**. Run the **RHEL 8 STIG** (for example
  with the SCAP Compliance Checker or `ansible-lockdown/RHEL8-STIG` in audit mode)
  for the OS. A few checks here (FIPS, firewalld, chrony) overlap on purpose,
  because the SRG requires them for the application server.
- GitLab's bundled PostgreSQL and Redis, and any database behind Nexus, are not
  assessed by those playbooks. The PostgreSQL playbook targets a Crunchy Data
  PostgreSQL 16 server, not GitLab's embedded database.
- An automated result supports an assessor's determination but does not replace
  it. Review `Not_Reviewed` items and the SRG rules that no check covers.
