import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec=importlib.util.spec_from_file_location("build_airgap",Path(__file__).resolve().parents[1]/"scripts"/"build_airgap.py")
builder=importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class AirgapBundleTests(unittest.TestCase):
    def test_filters_exclude_tests_secrets_and_build_outputs(self):
        for name in ("tests/test_gitlab_stig.py","roles/x/__pycache__/x.pyc","reports/report.html","dist/old.zip","inventory/site.key","inventory/site.pem","inventory/.env","inventory/location.vault-password-file",".git/config"):
            self.assertFalse(builder.allowed(name),name)
        self.assertFalse(builder.allowed("inventory/private-overrides.yml",tracked=False))
        for name in ("roles/gitlab_stig_audit/tasks/main.yml","docs/gitlab-audit-controls.md","scripts/gitlab_session_probe.py","inventory/local.yml"):
            self.assertTrue(builder.allowed(name),name)

    def test_archive_manifest_lf_executable_modes_and_checksum(self):
        required=["ansible.cfg","run_local.sh","inventory/local.yml","gitlab_stig_audit.yml","roles/gitlab_stig_audit/tasks/main.yml","roles/stig_common/tasks/report.yml"]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in required:
                path=root/name
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(b"line1\r\nline2\r\n")
            with patch.object(builder,"source_files",return_value=required),patch.object(builder.subprocess,"check_output",return_value="deadbeef\n"):
                result=builder.build(root,root/"out.zip")
            with zipfile.ZipFile(result["zip"]) as archive:
                self.assertEqual(archive.read("stig-audit/run_local.sh"),b"line1\nline2\n")
                self.assertEqual((archive.getinfo("stig-audit/run_local.sh").external_attr>>16)&0o777,0o755)
                manifest=json.loads(archive.read("stig-audit/AIRGAP_MANIFEST.json"))
                self.assertEqual(manifest["commit"],"deadbeef")
                self.assertEqual(len(manifest["files"]),len(required))
                self.assertIsNone(archive.testzip())
            self.assertTrue(Path(result["zip"]+".sha256").read_text().startswith(result["sha256"]))
