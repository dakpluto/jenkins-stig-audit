"""Build a test-free runtime ZIP for an offline RHEL 8 server with Ansible installed."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

ROOT_FILES = {"README.md", "ansible.cfg", "run_local.sh", "gitlab_stig_audit.yml", "jenkins_stig_audit.yml", "nexus_stig_audit.yml", "postgres_stig_audit.yml"}
PREFIXES = {"roles", "docs", "inventory", "scripts", "stig"}
EXCLUDED = {"tests", ".git", "dist", "reports", "__pycache__", ".aws", ".codex", "node_modules", ".validation-deps"}
TEXT_SUFFIXES = {".md", ".cfg", ".sh", ".py", ".yml", ".yaml", ".j2", ".json", ".txt", ".html", ".css", ".js"}


def allowed(path, tracked=True):
    path = Path(path)
    if path.is_absolute() or ".." in path.parts or any(part in EXCLUDED or part.startswith(".") for part in path.parts):
        return False
    lower = path.name.lower()
    if lower.endswith((".pyc", ".key", ".pem", ".p12", ".pfx", ".vault-password-file")) or lower in ("credentials", "gitlab-secrets.json"):
        return False
    if path.parts[0] == "stig" and path.suffix.lower() in (".zip", ".xml"):
        return False  # official SRG already resides on the destination
    if path.parts[0] == "inventory" and not tracked:
        return False  # local inventory/secret overrides must be transferred separately and deliberately
    return str(path).replace("\\", "/") in ROOT_FILES or path.parts[0] in PREFIXES


def source_files(root):
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=str(root)).decode().split("\0")
    extra = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=str(root)).decode().split("\0")
    files = {name for name in tracked if name and allowed(name)}
    files.update(name for name in extra if name and allowed(name, False))
    return sorted(name for name in files if (root / name).is_file())


def build(root, output):
    root, output = Path(root).resolve(), Path(output).resolve()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(root), text=True).strip()
    files = source_files(root)
    required = {"ansible.cfg", "run_local.sh", "inventory/local.yml", "gitlab_stig_audit.yml", "roles/gitlab_stig_audit/tasks/main.yml", "roles/stig_common/tasks/report.yml"}
    if not required.issubset(files):
        raise ValueError("Runtime files are missing: " + ", ".join(sorted(required - set(files))))
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest = dict(commit=commit, target="RHEL 8; Ansible already installed", files={})
    with zipfile.ZipFile(str(output), "w", zipfile.ZIP_DEFLATED) as archive:
        for name in files:
            source = root / name
            if source.is_symlink() or root not in source.resolve().parents:
                raise ValueError("Refusing symlink or source outside workspace: " + name)
            data = source.read_bytes()
            if Path(name).suffix.lower() in TEXT_SUFFIXES:
                data = data.replace(b"\r\n", b"\n")
            manifest["files"][name] = hashlib.sha256(data).hexdigest()
            info = zipfile.ZipInfo("stig-audit/" + name)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (0o100755 if name.endswith(".sh") else 0o100644) << 16
            archive.writestr(info, data)
        archive.writestr("stig-audit/AIRGAP_MANIFEST.json", json.dumps(manifest, indent=2) + "\n")
        archive.writestr("stig-audit/AIRGAP_README.txt", """Offline RHEL 8 audit bundle

Ansible is already installed on the destination. No Internet downloads are
required for the default audit. Extract this ZIP, then:

  cd stig-audit
  chmod +x run_local.sh
  ./run_local.sh gitlab

run_local.sh uses inventory/local.yml and prompts for sudo when needed.
Review inventory/group_vars/gitlab.yml and the role defaults for site policy.
No tests, Git metadata, reports, caches, local secret overrides or private keys
are included. Runtime files use LF line endings; scripts have executable modes.
The manifest identifies the source commit and SHA-256 of each packaged file.

The bundled SRG index supports HTML reports. To generate a full CKL, place your
official DISA Application Server SRG XCCDF XML/ZIP in stig/ and set
 gitlab_stig_xccdf: '{{ playbook_dir }}/stig/<official-file>'
The user's official SRG is already on the destination and is not duplicated.
Use its existing absolute path, for example:
 ./run_local.sh gitlab -e gitlab_stig_xccdf=/existing/path/to/SRG.zip
Supply site-specific policy/evidence files separately. Unknown controls stay
Not_Reviewed; absence of a site evidence file does not imply compliance.

Optional tools are not dependencies of the default audit: Nmap is needed only
for configured cipher enumeration; Playwright/Chromium are needed only for the
explicit browser probe. getfacl and OpenSSL supply optional supporting evidence.
The role follows Ansible's Python interpreter on the RHEL 8 target. It does not
install packages or trigger outage/failover/authorization exercises.
""")
    with zipfile.ZipFile(str(output)) as archive:
        if archive.testzip() is not None:
            raise ValueError("ZIP integrity test failed")
        for name in archive.namelist():
            if set(Path(name).parts).intersection(EXCLUDED):
                raise ValueError("Excluded content in archive")
        for name, digest in manifest["files"].items():
            if hashlib.sha256(archive.read("stig-audit/" + name)).hexdigest() != digest:
                raise ValueError("Manifest verification failed: " + name)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    checksum = Path(str(output) + ".sha256")
    checksum.write_text(digest + "  " + output.name + "\n", encoding="ascii")
    return dict(zip=str(output), sha256=digest, file_count=len(files), commit=commit)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    print(json.dumps(build(Path(__file__).resolve().parents[1], args.output), indent=2))
