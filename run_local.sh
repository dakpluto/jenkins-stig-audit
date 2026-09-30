#!/bin/sh
# Run the read-only SRG audit against this machine (the Jenkins controller).
# Reports land in ./reports/<fqdn>/. Extra arguments go to ansible-playbook, e.g.
#   ./run_local.sh -e jenkins_stig_xccdf=stig/U_Application_Server_SRG_V4R1_Manual.zip
set -eu
cd "$(dirname "$0")"

if ! command -v ansible-playbook >/dev/null 2>&1; then
  echo "ansible-playbook not found. Install it with: sudo dnf install ansible-core" >&2
  exit 1
fi

# The audit reads root-only files; ask for the sudo password unless it isn't needed.
become_opt=""
if [ "$(id -u)" -ne 0 ] && ! sudo -n true 2>/dev/null; then
  become_opt="--ask-become-pass"
fi

exec ansible-playbook -i inventory/local.yml jenkins_stig_audit.yml $become_opt "$@"
