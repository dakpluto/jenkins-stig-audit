#!/bin/sh
# Run a read-only SRG audit against this machine. Reports land in ./reports/<fqdn>/.
#   ./run_local.sh                  # Jenkins (default)
#   ./run_local.sh gitlab           # Omnibus GitLab
#   ./run_local.sh nexus            # Sonatype Nexus Repository
#   ./run_local.sh postgres         # Crunchy Data PostgreSQL 16 (product STIG)
#   ./run_local.sh postgres hsv     # Load inventory/group_vars/postgres_hsv.yml
# Extra arguments go to ansible-playbook, e.g.
#   ./run_local.sh gitlab -e gitlab_stig_xccdf=stig/U_Application_Server_SRG_V4R5_Manual.zip
set -eu
cd "$(dirname "$0")"

product=jenkins
case "${1:-}" in
  jenkins|gitlab|nexus|postgres) product=$1; shift ;;
esac

location_vars=""
location_vault_config=""
case "${1:-}" in
  ""|-*) ;;
  *)
    location=$1
    shift
    case "$location" in
      *[!a-zA-Z0-9_-]*)
        echo "Invalid location '$location': use letters, numbers, underscores or hyphens." >&2
        exit 1
        ;;
    esac
    location_vars="inventory/group_vars/${product}_${location}.yml"
    location_vault_config="inventory/group_vars/${product}_${location}.vault-password-file"
    if [ ! -f "$location_vars" ]; then
      echo "Location variables file not found: $location_vars" >&2
      exit 1
    fi
    ;;
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

if [ -n "$location_vars" ]; then
  set -- -e "@$location_vars" "$@"
fi

# The optional companion file contains a path, never shell commands or the secret.
if [ -n "$location_vault_config" ] && [ -f "$location_vault_config" ]; then
  vault_password_file=$(cat "$location_vault_config")
  # Accept companion files edited on Windows as well as Unix.
  vault_password_file=$(printf '%s' "$vault_password_file" | tr -d '\r')
  case "$vault_password_file" in
    '~/'*) vault_password_file="$HOME/${vault_password_file#\~/}" ;;
  esac
  if [ -z "$vault_password_file" ] || [ ! -r "$vault_password_file" ]; then
    echo "Vault password file configured in $location_vault_config is missing or unreadable." >&2
    exit 1
  fi
  set -- --vault-password-file "$vault_password_file" "$@"
fi

exec ansible-playbook -i inventory/local.yml "${product}_stig_audit.yml" $become_opt "$@"
