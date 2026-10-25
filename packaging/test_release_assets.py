import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile

import release_assets as release


class ReleaseAssetsTests(unittest.TestCase):
    def test_versions_follow_semver_component_rules(self):
        for version in ("0.0.0", "1.2.3", "1.2.3-rc.1", "1.2.3-0", "1.2.3-01a", "1.2.3-alpha-beta"):
            with self.subTest(version=version):
                self.assertEqual(release.validate_version(version), version)
        for version in ("01.2.3", "1.02.3", "1.2.03", "١.٢.٣", "1.2.3-01", "1.2.3-rc..1", "1.2.3-.", "1.2.3-rc.", "1.2.3\n", "1.2.3+meta"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                release.validate_version(version)

    def test_missing_and_file_inputs_fail_without_creating_release_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file = root / "file"
            file.write_bytes(b"not-a-directory")
            output = root / "output"
            for source in (root / "missing", file):
                operations = (
                    lambda: release.archive(source, output / "opscope.zip"),
                    lambda: release.sbom(source, output / "opscope.spdx.json", "1.2.3", "linux-x64", None),
                    lambda: release.checksums(source, output / "SHA256SUMS"),
                    lambda: release.manifests(source, output, "1.2.3", "Example/opscope"),
                )
                for operation in operations:
                    with self.subTest(source=source, operation=operation), self.assertRaises(ValueError):
                        operation()
                self.assertFalse(output.exists())

    def test_release_inputs_reject_symlink_roots_and_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            publish = root / "publish"
            publish.mkdir()
            (publish / "opscope").write_bytes(b"published")
            alias = root / "alias"
            try:
                alias.symlink_to(publish, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Symbolic links are unavailable for this account.")
            with self.assertRaises(ValueError):
                release.archive(alias, root / "opscope.zip")
            (publish / "linked").symlink_to(root / "outside")
            for operation in (
                lambda: release.archive(publish, root / "opscope.zip"),
                lambda: release.sbom(publish, root / "opscope.spdx.json", "1.2.3", "linux-x64", None),
                lambda: release.checksums(publish, root / "SHA256SUMS"),
                lambda: release.manifests(publish, root / "manifests", "1.2.3", "Example/opscope"),
            ):
                with self.subTest(operation=operation), self.assertRaises(ValueError):
                    operation()

    @unittest.skipUnless(os.name != "nt" and shutil.which("sha256sum"), "GNU checksum verification requires Unix filenames and sha256sum.")
    def test_checksum_special_filenames_verify_with_sha256sum(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("normal", "back\\slash", "line\nbreak", "carriage\rreturn"):
                (root / name).write_bytes(name.encode())
            release.checksums(root, root / "SHA256SUMS")
            subprocess.run(["sha256sum", "--check", "SHA256SUMS"], cwd=root, check=True, capture_output=True)
            (root / "line\nbreak").write_bytes(b"tampered")
            result = subprocess.run(["sha256sum", "--check", "SHA256SUMS"], cwd=root, capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    def test_real_artifact_hashes_and_required_rids(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            for rid in release.RIDS:
                extension = "zip" if rid.startswith("win-") else "tar.gz"
                (artifacts / f"opscope-1.2.3-{rid}.{extension}").write_bytes(rid.encode())
            release.manifests(artifacts, root / "manifests", "1.2.3", "Example/opscope")
            formula = (root / "manifests/opscope.rb").read_text()
            installer = (root / "manifests/winget/Example.Opscope.installer.yaml").read_text()
            self.assertIn(hashlib.sha256(b"osx-arm64").hexdigest(), formula)
            self.assertIn(hashlib.sha256(b"linux-x64").hexdigest(), formula)
            self.assertIn(hashlib.sha256(b"win-arm64").hexdigest().upper(), installer)
            (artifacts / "opscope-1.2.3-win-x64.zip").unlink()
            with self.assertRaises(FileNotFoundError):
                release.manifests(artifacts, root / "missing", "1.2.3", "Example/opscope")

    def test_archive_sbom_and_checksums_use_published_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            publish = root / "publish"
            publish.mkdir()
            (publish / "opscope").write_bytes(b"real-published-bytes")
            release.archive(publish, root / "opscope.zip")
            with zipfile.ZipFile(root / "opscope.zip") as bundle:
                self.assertEqual(bundle.read("opscope"), b"real-published-bytes")
            release.sbom(publish, root / "opscope.spdx.json", "1.2.3", "linux-x64", None)
            document = json.loads((root / "opscope.spdx.json").read_text())
            self.assertEqual(document["spdxVersion"], "SPDX-2.3")
            self.assertEqual(document["files"][0]["checksums"][0]["checksumValue"], hashlib.sha256(b"real-published-bytes").hexdigest())
            release.checksums(root, root / "SHA256SUMS")
            expected = hashlib.sha256((root / "opscope.zip").read_bytes()).hexdigest()
            self.assertIn(expected + "  opscope.zip", (root / "SHA256SUMS").read_text())


if __name__ == "__main__":
    unittest.main()
