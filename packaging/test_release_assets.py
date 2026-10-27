import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import warnings
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


class DistributionIntegrityTests(unittest.TestCase):
    version = "1.2.3-ci.7"
    repository = "Example/opscope"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="opscope-distribution-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.sources = {}
        for rid in release.RIDS:
            source = self.root / rid
            source.mkdir()
            executable = source / ("opscope.exe" if rid.startswith("win-") else "opscope")
            executable.write_bytes(self.binary_header(rid) + ("published-" + rid).encode())
            if not rid.startswith("win-"):
                executable.chmod(0o755)
            (source / "README.md").write_text("Read-only diagnostic application.\n", encoding="utf-8")
            (source / "LICENSE").write_text("MIT\n", encoding="utf-8")
            self.sources[rid] = source
            self.build_archive(rid)
            release.sbom(source, self.sbom_path(rid), self.version, rid, None)
        self.package = self.dist / f"Opscope.{self.version}.nupkg"
        with zipfile.ZipFile(self.package, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr("Opscope.nuspec", f'''<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata>
<id>Opscope</id><version>{self.version}</version><authors>Opscope contributors</authors>
<description>Read-only diagnostic application.</description>
<packageTypes><packageType name="DotnetTool" /></packageTypes></metadata></package>''')
            bundle.writestr("tools/net8.0/any/DotnetToolSettings.xml", '<DotNetCliTool Version="1"><Commands><Command Name="opscope" EntryPoint="opscope.dll" Runner="dotnet" /></Commands></DotNetCliTool>')
            bundle.writestr("tools/net8.0/any/opscope.dll", b"fixture-tool-assembly")
            bundle.writestr("tools/net8.0/any/opscope.deps.json", "{}")
            bundle.writestr("tools/net8.0/any/opscope.runtimeconfig.json", '{"runtimeOptions":{"tfm":"net8.0","frameworks":[{"name":"Microsoft.NETCore.App","version":"8.0.0"},{"name":"Microsoft.AspNetCore.App","version":"8.0.0"}]}}')
        self.refresh_tool_sbom()
        self.refresh_manifests()
        self.refresh_checksums()

    def archive_path(self, rid):
        return self.dist / f"opscope-{self.version}-{rid}.{'zip' if rid.startswith('win-') else 'tar.gz'}"

    def build_archive(self, rid):
        source = self.sources[rid]
        if rid.startswith("win-"):
            release.archive(source, self.archive_path(rid))
            return
        # Keep the Linux/macOS fixture's executable bit on Windows test runners too.
        with tarfile.open(self.archive_path(rid), "w:gz") as bundle:
            for path in sorted(source.rglob("*")):
                if path.is_file():
                    entry = tarfile.TarInfo(path.relative_to(source).as_posix())
                    content = path.read_bytes()
                    entry.size = len(content)
                    entry.mode = 0o755 if entry.name == "opscope" else 0o644
                    bundle.addfile(entry, io.BytesIO(content))

    @staticmethod
    def binary_header(rid):
        if rid.startswith("linux-"):
            header = bytearray(64)
            header[:7] = b"\x7fELF\x02\x01\x01"
            struct.pack_into("<HHI", header, 16, 2, 62 if rid.endswith("x64") else 183, 1)
            return bytes(header)
        if rid.startswith("win-"):
            header = bytearray(256)
            header[:2] = b"MZ"
            struct.pack_into("<I", header, 0x3c, 0x80)
            header[0x80:0x84] = b"PE\0\0"
            struct.pack_into("<H", header, 0x84, 0x8664 if rid.endswith("x64") else 0xAA64)
            struct.pack_into("<H", header, 0x98, 0x20b)
            return bytes(header)
        header = bytearray(64)
        struct.pack_into("<III", header, 0, 0xFEEDFACF, 0x01000007 if rid.endswith("x64") else 0x0100000c, 0)
        return bytes(header)

    def sbom_path(self, rid):
        return self.dist / f"opscope-{self.version}-{rid}.spdx.json"

    def refresh_tool_sbom(self):
        source = self.root / "tool-sbom-source"
        source.mkdir(exist_ok=True)
        shutil.copyfile(self.package, source / self.package.name)
        release.sbom(source, self.dist / "opscope-dotnet-tool.spdx.json", self.version, "dotnet-tool", None)

    def refresh_manifests(self):
        release.manifests(self.dist, self.dist / "manifests", self.version, self.repository)
        release.archive(self.dist / "manifests", self.dist / f"opscope-{self.version}-package-manifests.tar.gz")

    def refresh_checksums(self):
        release.checksums(self.dist, self.dist / "SHA256SUMS")

    def verify(self):
        return release.verify_assets(self.dist, self.version, self.repository)

    def assert_rejected(self):
        with self.assertRaises((ValueError, OSError, zipfile.BadZipFile, tarfile.TarError)):
            self.verify()

    def rewrite_package(self, transform):
        with zipfile.ZipFile(self.package) as bundle:
            entries = {entry.filename: bundle.read(entry) for entry in bundle.infolist()}
        transform(entries)
        with zipfile.ZipFile(self.package, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for name, content in entries.items():
                bundle.writestr(name, content)
        self.refresh_tool_sbom()
        self.refresh_checksums()

    def test_complete_distribution_verifies_actual_archives_packages_and_sboms(self):
        result = self.verify()
        self.assertIsInstance(result, dict)
        self.assertTrue(result)
        # Verification inspects bytes in place and never extracts members into the distribution.
        self.assertFalse((self.dist / "opscope").exists())
        self.assertFalse((self.dist / "tools").exists())

    def test_each_archive_can_be_verified_before_extraction(self):
        for rid in release.RIDS:
            with self.subTest(rid=rid):
                result = release.verify_archive(self.archive_path(rid), self.sbom_path(rid), rid, self.version)
                self.assertIsInstance(result, dict)
                self.assertTrue(result)

    def test_archives_reject_a_binary_built_for_the_other_architecture(self):
        for rid in ("linux-x64", "win-x64", "osx-x64"):
            with self.subTest(rid=rid):
                other = rid.replace("x64", "arm64")
                binary = self.sources[rid] / ("opscope.exe" if rid.startswith("win-") else "opscope")
                binary.write_bytes(self.binary_header(other))
                self.build_archive(rid)
                release.sbom(self.sources[rid], self.sbom_path(rid), self.version, rid, None)
                with self.assertRaises(ValueError):
                    release.verify_archive(self.archive_path(rid), self.sbom_path(rid), rid, self.version)

    def test_candidate_version_uses_a_literal_project_version(self):
        project = self.root / "candidate.csproj"
        for base, expected in (("0.2.0", "0.2.0-ci.123"), ("0.2.0-rc.1", "0.2.0-rc.1.ci.123")):
            project.write_text(f'<Project><PropertyGroup><Version>{base}</Version></PropertyGroup></Project>', encoding="utf-8")
            self.assertEqual(release.candidate_version(project, "ci.123"), expected)
        project.write_text('<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><PropertyGroup><Version>0.2.0</Version></PropertyGroup></Project>', encoding="utf-8")
        self.assertEqual(release.candidate_version(project, "ci.123"), "0.2.0-ci.123")

    def test_candidate_version_rejects_dynamic_ambiguous_or_malformed_projects(self):
        project = self.root / "candidate.csproj"
        for xml in (
            '<Project><PropertyGroup><Version>$(PackageVersion)</Version></PropertyGroup></Project>',
            '<Project><PropertyGroup><Version>0.2.0</Version><Version>0.3.0</Version></PropertyGroup></Project>',
            '<Project><PropertyGroup><Version Condition="true">0.2.0</Version></PropertyGroup></Project>',
            '<Project><PropertyGroup Condition="true"><Version>0.2.0</Version></PropertyGroup></Project>',
            '<Project><Target Name="ComputeVersion"><PropertyGroup><Version>0.2.0</Version></PropertyGroup></Target></Project>',
            '<Project><PropertyGroup><Version>01.2.3</Version></PropertyGroup></Project>',
            '<Project><PropertyGroup><Version /></PropertyGroup></Project>',
            '<Project><PropertyGroup /></Project>',
            '<Project><PropertyGroup><Version>0.2.0</Version>',
            '<!DOCTYPE Project [<!ENTITY version "0.2.0">]><Project><PropertyGroup><Version>&version;</Version></PropertyGroup></Project>',
        ):
            with self.subTest(xml=xml), self.assertRaises(ValueError):
                project.write_text(xml, encoding="utf-8")
                release.candidate_version(project, "ci.123")

    def test_candidate_version_rejects_invalid_suffixes_and_oversized_project(self):
        project = self.root / "candidate.csproj"
        project.write_text('<Project><PropertyGroup><Version>0.2.0</Version></PropertyGroup></Project>', encoding="utf-8")
        for suffix in ("", "ci..1", "ci.01", "ci.1\n", "../1", "ci/1", "ci.١", "ci.1+metadata"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                release.candidate_version(project, suffix)
        with mock.patch.object(release, "MAX_PROJECT_BYTES", 16), self.assertRaises(ValueError):
            release.candidate_version(project, "ci.123")

    def test_cli_candidate_and_distribution_verification_emit_machine_readable_output(self):
        project = self.root / "candidate.csproj"
        project.write_text('<Project><PropertyGroup><Version>0.2.0</Version></PropertyGroup></Project>', encoding="utf-8")
        script = str(Path(release.__file__).resolve())
        candidate = subprocess.run([sys.executable, script, "candidate-version", "--project", str(project), "--suffix", "ci.123"], check=True, text=True, capture_output=True)
        self.assertEqual(candidate.stdout.strip(), "0.2.0-ci.123")
        verified = subprocess.run([sys.executable, script, "verify", "--input", str(self.dist), "--version", self.version, "--repository", self.repository], check=True, text=True, capture_output=True)
        self.assertTrue(json.loads(verified.stdout))

    def test_every_required_distribution_asset_must_exist(self):
        required = [self.archive_path(rid) for rid in release.RIDS] + [self.sbom_path(rid) for rid in release.RIDS]
        required += [self.package, self.dist / "opscope-dotnet-tool.spdx.json", self.dist / f"opscope-{self.version}-package-manifests.tar.gz"]
        for path in required:
            with self.subTest(path=path.name):
                content = path.read_bytes()
                path.unlink()
                self.refresh_checksums()
                self.assert_rejected()
                path.write_bytes(content)
        self.refresh_checksums()
        self.assertTrue(self.verify())

    def test_checksum_manifest_detects_tampering_and_unlisted_files(self):
        archive = self.archive_path("linux-x64")
        original = archive.read_bytes()
        archive.write_bytes(original + b"tampered")
        self.assert_rejected()
        archive.write_bytes(original)
        (self.dist / "unlisted-file.txt").write_text("not in SHA256SUMS", encoding="utf-8")
        self.assert_rejected()

    def test_checksum_manifest_rejects_duplicate_and_unsafe_records(self):
        manifest = self.dist / "SHA256SUMS"
        original = manifest.read_text(encoding="utf-8")
        for appended in (original.splitlines()[0], hashlib.sha256(b"outside").hexdigest() + "  ../outside", hashlib.sha256(b"outside").hexdigest() + "  /absolute"):
            with self.subTest(record=appended):
                manifest.write_text(original + appended + "\n", encoding="utf-8")
                self.assert_rejected()
        manifest.write_text(original, encoding="utf-8")
        self.assertTrue(self.verify())

    def test_sbom_must_match_payload_bytes_even_with_fresh_outer_checksums(self):
        path = self.sbom_path("linux-x64")
        document = json.loads(path.read_text(encoding="utf-8"))
        document["files"][0]["checksums"][0]["checksumValue"] = "0" * 64
        path.write_text(json.dumps(document), encoding="utf-8")
        self.refresh_checksums()
        self.assert_rejected()

    def test_sbom_requires_exact_unique_file_inventory_and_package_version(self):
        path = self.sbom_path("linux-x64")
        original = path.read_text(encoding="utf-8")
        for mutate in (
            lambda document: document["files"].pop(),
            lambda document: document["files"].append(document["files"][0]),
            lambda document: document["files"][0].update(fileName="./invented-file"),
            lambda document: document["packages"][0].update(versionInfo="9.9.9"),
        ):
            with self.subTest(mutate=mutate):
                document = json.loads(original)
                mutate(document)
                path.write_text(json.dumps(document), encoding="utf-8")
                self.refresh_checksums()
                self.assert_rejected()
        path.write_text(original, encoding="utf-8")

    def test_binary_archives_require_executable_readme_and_license(self):
        rid = "linux-x64"
        source = self.sources[rid]
        for name in ("opscope", "README.md", "LICENSE"):
            with self.subTest(missing=name):
                path = source / name
                content = path.read_bytes()
                mode = path.stat().st_mode
                path.unlink()
                self.build_archive(rid)
                release.sbom(source, self.sbom_path(rid), self.version, rid, None)
                self.refresh_manifests()
                self.refresh_checksums()
                self.assert_rejected()
                path.write_bytes(content)
                path.chmod(mode)

    def test_nuget_identity_version_and_tool_configuration_are_verified(self):
        original = self.package.read_bytes()
        for old, new in ((b"<id>Opscope</id>", b"<id>DifferentPackage</id>"),
                         (self.version.encode(), b"9.9.9"),
                         (b'name="DotnetTool"', b'name="Library"'),
                         (b'Name="opscope"', b'Name="unrelated"'),
                         (b'EntryPoint="opscope.dll"', b'EntryPoint="missing.dll"'),
                         (b'<DotNetCliTool Version="1">', b'<DotNetCliTool Version="999">'),
                         (b'Runner="dotnet"', b'Runner="custom"')):
            with self.subTest(replacement=(old, new)):
                self.package.write_bytes(original)
                self.rewrite_package(lambda entries: entries.update({name: data.replace(old, new) for name, data in entries.items()}))
                self.assert_rejected()
        self.package.write_bytes(original)
        self.refresh_tool_sbom()
        self.refresh_checksums()
        self.assertTrue(self.verify())

    def test_tool_entrypoint_must_exist_in_the_package(self):
        self.rewrite_package(lambda entries: entries.pop("tools/net8.0/any/opscope.dll"))
        self.assert_rejected()

    def test_nuget_metadata_requires_the_package_root_element(self):
        def change_root(entries):
            entries["Opscope.nuspec"] = entries["Opscope.nuspec"].replace(b"<package ", b"<invalidRoot ", 1).replace(b"</package>", b"</invalidRoot>", 1)
        self.rewrite_package(change_root)
        self.assert_rejected()

    def test_checksum_exclusions_do_not_hide_other_signatures_or_nested_manifests(self):
        for relative in ("extra.sig", "nested/SHA256SUMS"):
            with self.subTest(relative=relative):
                path = self.dist / relative
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(b"unsigned and unlisted data")
                self.assert_rejected()
                self.refresh_checksums()
                self.assertIn("  " + relative + "\n", (self.dist / "SHA256SUMS").read_text(encoding="utf-8"))
                self.assertTrue(self.verify())
                path.unlink()
                self.refresh_checksums()

    def test_optional_signing_artifacts_preserve_integrity_without_claiming_a_signer(self):
        public_key = self.dist / "release-signing-public.pem"
        public_key.write_bytes(b"opaque public-key artifact")
        signature = self.dist / "SHA256SUMS.sig"
        signature.write_bytes(b"opaque detached-signature artifact")
        self.refresh_checksums()
        manifest = (self.dist / "SHA256SUMS").read_text(encoding="utf-8")
        self.assertIn("  release-signing-public.pem\n", manifest)
        self.assertNotIn("  SHA256SUMS.sig\n", manifest)
        self.assertFalse(self.verify()["publisherSignatureVerified"])

    def test_zip_paths_links_and_duplicate_members_are_rejected(self):
        path = self.archive_path("win-x64")
        original = path.read_bytes()
        for name in ("../outside", "/absolute", "C:/absolute", "nested\\outside", "README.md"):
            with self.subTest(name=name):
                path.write_bytes(original)
                with warnings.catch_warnings(), zipfile.ZipFile(path, "a") as bundle:
                    warnings.simplefilter("ignore", UserWarning)
                    bundle.writestr(name, b"unsafe")
                self.refresh_manifests()
                self.refresh_checksums()
                self.assert_rejected()
        path.write_bytes(original)
        with zipfile.ZipFile(path, "a") as bundle:
            linked = zipfile.ZipInfo("linked")
            linked.create_system = 3
            linked.external_attr = 0o120777 << 16
            bundle.writestr(linked, "outside")
        self.refresh_manifests()
        self.refresh_checksums()
        self.assert_rejected()
        self.assertFalse((self.root / "outside").exists())

    def test_tar_paths_symlinks_and_hardlinks_are_rejected(self):
        path = self.archive_path("linux-x64")
        for name, kind in (("../outside", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE), ("linked", tarfile.SYMTYPE), ("linked", tarfile.LNKTYPE)):
            with self.subTest(name=name, kind=kind):
                with tarfile.open(path, "w:gz") as bundle:
                    entry = tarfile.TarInfo(name)
                    entry.type = kind
                    if kind == tarfile.REGTYPE:
                        entry.size = 6
                        bundle.addfile(entry, io.BytesIO(b"unsafe"))
                    else:
                        entry.linkname = "outside"
                        bundle.addfile(entry)
                self.refresh_manifests()
                self.refresh_checksums()
                self.assert_rejected()
        self.assertFalse((self.root / "outside").exists())

    def test_artifact_expansion_entry_and_metadata_budgets_are_enforced(self):
        for name, limit in (("MAX_ARTIFACT_BYTES", 16), ("MAX_EXPANDED_BYTES", 16), ("MAX_ARCHIVE_ENTRIES", 1), ("MAX_METADATA_BYTES", 16)):
            with self.subTest(bound=name), mock.patch.object(release, name, limit):
                self.assert_rejected()

    def test_tar_extended_metadata_is_bounded_before_its_body_is_read(self):
        path = self.archive_path("linux-x64")
        for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
            with self.subTest(kind=kind):
                entry = tarfile.TarInfo("metadata")
                entry.type = kind
                entry.size = release.MAX_METADATA_BYTES + 1
                # Only the header is present: decoding the missing body must never be attempted.
                path.write_bytes(gzip.compress(entry.tobuf(format=tarfile.GNU_FORMAT)))
                with self.assertRaisesRegex(ValueError, "metadata"):
                    release.verify_archive(path, self.sbom_path("linux-x64"), "linux-x64", self.version)

    def test_sparse_tar_headers_are_rejected_before_sparse_metadata_is_decoded(self):
        path = self.archive_path("linux-x64")
        entry = tarfile.TarInfo("opscope")
        entry.type = tarfile.GNUTYPE_SPARSE
        path.write_bytes(gzip.compress(entry.tobuf(format=tarfile.GNU_FORMAT)))
        with self.assertRaisesRegex(ValueError, "unsupported"):
            release.verify_archive(path, self.sbom_path("linux-x64"), "linux-x64", self.version)

    def test_package_manager_manifests_must_match_real_archive_hashes(self):
        manifest = self.dist / "manifests" / "opscope.rb"
        original = manifest.read_text(encoding="utf-8")
        manifest.write_text(original.replace(release.digest(self.archive_path("linux-x64")), "0" * 64), encoding="utf-8")
        release.archive(self.dist / "manifests", self.dist / f"opscope-{self.version}-package-manifests.tar.gz")
        self.refresh_checksums()
        self.assert_rejected()

    def test_manifest_archive_must_agree_with_its_loose_files(self):
        path = self.dist / f"opscope-{self.version}-package-manifests.tar.gz"
        with tarfile.open(path, "w:gz") as bundle:
            entry = tarfile.TarInfo("opscope.rb")
            entry.size = 7
            bundle.addfile(entry, io.BytesIO(b"altered"))
        self.refresh_checksums()
        self.assert_rejected()


if __name__ == "__main__":
    unittest.main()
