# Offline RHEL 8 deployment

The runtime ZIP targets the user's RHEL 8 server where Ansible is already installed. It contains all four product playbooks, roles, filters, templates, shared reporting files, inventory templates, documentation/examples, run_local.sh and optional helper scripts. It excludes tests, .git, reports, caches, generated archives, private key/certificate-container files and untracked local inventory/credential overrides. No Ansible/Python dependency download is required for the default audit on that existing installation.

After validating the project, commit and push source changes, then build the runtime artifact:

```text
python scripts/build_airgap.py --output dist/stig-audit-airgap-<commit>.zip
```

The builder writes a SHA-256 sidecar and verifies ZIP integrity, the runtime file manifest, and exclusions. It normalizes runtime text to LF and gives shell scripts executable modes. AIRGAP_MANIFEST.json records the source commit and hashes of packaged runtime files; AIRGAP_README.txt provides offline run instructions. Generated artifacts remain outside Git under dist/.

Transfer the ZIP and matching .sha256 file. On the server, verify and extract them, then run:

```sh
sha256sum -c stig-audit-airgap-<commit>.zip.sha256
unzip stig-audit-airgap-<commit>.zip
cd stig-audit
chmod +x run_local.sh
./run_local.sh gitlab -e gitlab_stig_xccdf=/existing/path/to/Application_Server_SRG.zip
```

Use the actual absolute path of the SRG already on the server. It is intentionally not duplicated in this delivery. Without gitlab_stig_xccdf the bundled SRG index supports HTML reports; the full official XCCDF is needed for CKL output. The wrapper selects inventory/local.yml, runs locally and requests sudo when needed. Set site policy in inventory/group_vars/gitlab.yml or an explicit variables file; deliver any sensitive evidence or credential overrides separately through the approved transfer process.

The default role does not install packages or exercise authentication, outages, alert delivery, privileged operations, failover, time skew or firewall changes. Missing site-specific policy/evidence remains Not_Reviewed. Configure references/observations using the included examples; do not use illustrative approvals or positive booleans as actual evidence.

OpenSSL and getfacl provide supporting metadata; missing tools leave related evidence inconclusive. Nmap is needed only for explicitly configured cipher enumeration. Playwright and Chromium are needed only for the separately invoked browser probe; they are not required or bundled for the default Ansible run. The ZIP contains no tests and requires no Git installation on the destination.
