import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

import release_assets as release


class ReleaseAssetsTests(unittest.TestCase):
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
