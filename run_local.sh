#!/bin/sh
# Run a read-only SRG audit against this machine. Reports land in ./reports/<fqdn>/.
#   ./run_local.sh                  # Jenkins (default)
#   ./run_local.sh gitlab           # Omnibus GitLab
#   ./run_local.sh nexus            # Sonatype Nexus Repository
#   ./run_local.sh postgres         # Crunchy Data PostgreSQL 16 (product STIG)
# Extra arguments go to ansible-playbook, e.g.
#   ./run_local.sh gitlab -e gitlab_stig_xccdf=stig/U_Application_Server_SRG_V4R5_Manual.zip
set -eu
cd "$(dirname "$0")"

product=jenkins
case "${1:-}" in
  jenkins|gitlab|nexus|postgres) product=$1; shift ;;
esac

if ! command -v ansible-playbook >/dev/null 2>&1; then
  echo "ansible-playbook not found. Install it with: sudo dnf install ansible-core" >&2
  exit 1
fi

# The audit reads root-only files; ask for the sudo password unless it isn't needed.
become_opt=""
if [ "$(id -u)" -ne 0 ] && ! sudo -n true 2>/dev/null; then
  become_opt="--ask-become-pass"
fi

exec ansible-playbook -i inventory/local.yml "${product}_stig_audit.yml" $become_opt "$@"
