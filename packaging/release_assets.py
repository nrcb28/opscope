#!/usr/bin/env python3
"""Create local release assets from real build outputs; never publish or fetch packages."""
import argparse
import base64
import datetime as dt
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import tarfile
import tempfile
import uuid
import xml.etree.ElementTree as ET
import zipfile

RIDS = ("linux-x64", "linux-arm64", "win-x64", "win-arm64", "osx-x64", "osx-arm64")
VERSION_NUMBER = r"(?:0|[1-9][0-9]*)"
PRERELEASE_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
VERSION_PATTERN = rf"{VERSION_NUMBER}\.{VERSION_NUMBER}\.{VERSION_NUMBER}(?:-{PRERELEASE_IDENTIFIER}(?:\.{PRERELEASE_IDENTIFIER})*)?"
MAX_PROJECT_BYTES = 256 * 1024
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 10000


def digest(path, algorithm="sha256"):
    value = hashlib.new(algorithm)
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def validate_version(version):
    if not re.fullmatch(VERSION_PATTERN, version):
        raise ValueError("Version must be a concrete semantic version.")
    return version


def candidate_version(project, suffix):
    """Read a literal version without evaluating MSBuild, imports or conditions."""
    source = Path(project)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_PROJECT_BYTES:
        raise ValueError("Project version input must be a bounded regular file.")
    root = _xml(_bounded_bytes(source, MAX_PROJECT_BYTES), MAX_PROJECT_BYTES)
    versions = []

    def visit(element, conditional=False, ancestors=()):
        conditional = conditional or any(_local(name).lower() == "condition" for name in element.attrib)
        if _local(element.tag).lower() == "version":
            if conditional or len(element) or element.attrib or ancestors != ("Project", "PropertyGroup"):
                raise ValueError("Project version must be one unconditional literal property.")
            versions.append((element.text or "").strip())
        for child in element:
            visit(child, conditional, ancestors + (_local(element.tag),))

    if _local(root.tag) != "Project":
        raise ValueError("Project version input must be an MSBuild project.")
    visit(root)
    if len(versions) != 1 or len(versions[0]) > 128:
        raise ValueError("Project must declare exactly one literal version.")
    version = validate_version(versions[0])
    if not isinstance(suffix, str) or len(suffix) > 128 or not re.fullmatch(rf"{PRERELEASE_IDENTIFIER}(?:\.{PRERELEASE_IDENTIFIER})*", suffix):
        raise ValueError("Candidate suffix must contain valid semantic-version prerelease identifiers.")
    return validate_version(version + ("." if "-" in version else "-") + suffix)


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _xml(content, limit=MAX_METADATA_BYTES):
    if len(content) > limit or content.count(b"<") > MAX_ARCHIVE_ENTRIES:
        raise ValueError("XML metadata exceeds its bound.")
    try:
        decoded = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("XML metadata must use UTF-8.") from error
    if "\0" in decoded or re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", decoded, re.IGNORECASE):
        raise ValueError("XML metadata exceeds its bound or contains declarations.")
    try:
        root = ET.fromstring(content)
        pending = [(root, 0)]
        while pending:
            node, depth = pending.pop()
            if depth > 64:
                raise ValueError("XML metadata exceeds its depth bound.")
            pending.extend((child, depth + 1) for child in node)
        return root
    except (ET.ParseError, RecursionError) as error:
        raise ValueError("Invalid XML metadata.") from error


def files_in(directory):
    # EN: Reject linked inputs so an archive cannot silently include files outside its selected source.
    # ES: Se rechazan enlaces para que el archivo no incluya silenciosamente ficheros ajenos a su origen elegido.
    directory = Path(directory)
    if directory.is_symlink():
        raise ValueError("Release input must not contain symbolic links.")
    if not directory.is_dir():
        raise ValueError("Release input must be an existing directory.")
    directory = directory.resolve()
    files = sorted(directory.rglob("*"))
    if any(path.is_symlink() for path in files):
        raise ValueError("Release input must not contain symbolic links.")
    return directory, [path for path in files if path.is_file()]


def archive(directory, output):
    root, files = files_in(directory)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.resolve().is_relative_to(root):
        raise ValueError("Archive output must be outside its source directory.")
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    if output.suffix == ".zip":
        stamp = dt.datetime.fromtimestamp(max(epoch, 315532800), dt.timezone.utc).timetuple()[:6]
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
            for path in files:
                entry = zipfile.ZipInfo(path.relative_to(root).as_posix(), stamp)
                entry.external_attr = (0o100755 if path.stat().st_mode & 0o111 else 0o100644) << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                bundle.writestr(entry, path.read_bytes())
    elif output.name.endswith(".tar.gz"):
        with output.open("wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as bundle:
                for path in files:
                    content = path.read_bytes()
                    entry = tarfile.TarInfo(path.relative_to(root).as_posix())
                    entry.size = len(content)
                    entry.mtime = epoch
                    entry.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                    bundle.addfile(entry, io.BytesIO(content))
    else:
        raise ValueError("Archive output must end in .zip or .tar.gz.")


def sbom(directory, output, version, rid, assets):
    validate_version(version)
    root, paths = files_in(directory)
    files = []
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Opscope"}]
    for path in paths:
        name = path.relative_to(root).as_posix()
        identifier = "SPDXRef-File-" + hashlib.sha256(name.encode()).hexdigest()[:20]
        files.append({"SPDXID": identifier, "fileName": "./" + name,
                      "checksums": [{"algorithm": "SHA256", "checksumValue": digest(path)}, {"algorithm": "SHA1", "checksumValue": digest(path, "sha1")}],
                      "licenseConcluded": "NOASSERTION", "licenseInfoInFiles": ["NOASSERTION"], "copyrightText": "NOASSERTION"})
        relationships.append({"spdxElementId": "SPDXRef-Opscope", "relationshipType": "CONTAINS", "relatedSpdxElement": identifier})
    verification = hashlib.sha1("".join(sorted(item["checksums"][1]["checksumValue"] for item in files)).encode()).hexdigest()
    packages = [{"SPDXID": "SPDXRef-Opscope", "name": "Opscope", "versionInfo": version, "downloadLocation": "NOASSERTION", "filesAnalyzed": True,
                 "packageVerificationCode": {"packageVerificationCodeValue": verification}, "licenseConcluded": "MIT", "licenseDeclared": "MIT", "copyrightText": "NOASSERTION"}]
    resolved = json.loads(Path(assets).read_text(encoding="utf-8")) if assets else {}
    for name_version, library in sorted(resolved.get("libraries", {}).items()):
        if library.get("type") != "package":
            continue
        name, package_version = name_version.rsplit("/", 1)
        identifier = "SPDXRef-NuGet-" + hashlib.sha256(name_version.encode()).hexdigest()[:20]
        package = {"SPDXID": identifier, "name": name, "versionInfo": package_version,
                   "downloadLocation": f"https://api.nuget.org/v3-flatcontainer/{name.lower()}/{package_version.lower()}/{name.lower()}.{package_version.lower()}.nupkg",
                   "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
                   "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": f"pkg:nuget/{name}@{package_version}"}]}
        sha512 = library.get("sha512", "").removeprefix("sha512-")
        if sha512:
            package["checksums"] = [{"algorithm": "SHA512", "checksumValue": base64.b64decode(sha512, validate=True).hex()}]
        packages.append(package)
        relationships.append({"spdxElementId": "SPDXRef-Opscope", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": identifier})
    identity = version + rid + json.dumps(files, sort_keys=True)
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    document = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": f"Opscope-{version}-{rid}",
                "documentNamespace": "https://spdx.org/spdxdocs/opscope-" + str(uuid.uuid5(uuid.NAMESPACE_URL, identity)),
                "creationInfo": {"created": dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "creators": ["Tool: Opscope-release_assets.py"]},
                "documentComment": "File hashes cover the actual publish output. NuGet entries are resolved package metadata; embedded runtime component licenses are not inferred.",
                "packages": packages, "files": files, "relationships": relationships}
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def manifests(directory, output, version, repository):
    validate_version(version)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Repository must be owner/name.")
    directory, _ = files_in(directory)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    hashes = {}
    base = f"https://github.com/{repository}/releases/download/v{version}"
    for rid in RIDS:
        filename = f"opscope-{version}-{rid}." + ("zip" if rid.startswith("win-") else "tar.gz")
        path = directory / filename
        if not path.is_file():
            raise FileNotFoundError(f"Required release artifact missing: {filename}")
        hashes[rid] = (filename, digest(path))
    owner = repository.split("/")[0]
    identifier = re.sub(r"[^A-Za-z0-9]", "", owner) + ".Opscope"
    winget = output / "winget"
    winget.mkdir(exist_ok=True)
    (winget / f"{identifier}.yaml").write_text(f"PackageIdentifier: {identifier}\nPackageVersion: {version}\nDefaultLocale: en-US\nManifestType: version\nManifestVersion: 1.9.0\n", encoding="utf-8")
    locale = f"PackageIdentifier: {identifier}\nPackageVersion: {version}\nPackageLocale: en-US\nPublisher: {owner}\nPublisherUrl: https://github.com/{owner}\nPackageName: Opscope\nPackageUrl: https://github.com/{repository}\nLicense: MIT\nLicenseUrl: https://github.com/{repository}/blob/v{version}/LICENSE\nShortDescription: Read-only host and cloud investigation reports\nManifestType: defaultLocale\nManifestVersion: 1.9.0\n"
    (winget / f"{identifier}.locale.en-US.yaml").write_text(locale, encoding="utf-8")
    installer = f"PackageIdentifier: {identifier}\nPackageVersion: {version}\nInstallerType: zip\nNestedInstallerType: portable\nNestedInstallerFiles:\n- RelativeFilePath: opscope.exe\n  PortableCommandAlias: opscope\nInstallers:\n"
    for architecture in ("x64", "arm64"):
        filename, sha = hashes["win-" + architecture]
        installer += f"- Architecture: {architecture}\n  InstallerUrl: {base}/{filename}\n  InstallerSha256: {sha.upper()}\n"
    installer += "ManifestType: installer\nManifestVersion: 1.9.0\n"
    (winget / f"{identifier}.installer.yaml").write_text(installer, encoding="utf-8")
    formula = f'class Opscope < Formula\n  desc "Read-only host and cloud investigation reports"\n  homepage "https://github.com/{repository}"\n  version "{version}"\n  license "MIT"\n\n'
    for platform, prefix in (("macos", "osx"), ("linux", "linux")):
        formula += f"  on_{platform} do\n    if Hardware::CPU.arm?\n"
        for architecture, branch in (("arm64", ""), ("x64", "    else\n")):
            filename, sha = hashes[prefix + "-" + architecture]
            formula += branch + f'      url "{base}/{filename}"\n      sha256 "{sha}"\n'
        formula += "    end\n  end\n\n"
    formula += '  def install\n    bin.install "opscope"\n    prefix.install "LICENSE" if File.exist?("LICENSE")\n  end\n\n  test do\n    assert_match "opscope", shell_output("#{bin}/opscope --help")\n  end\nend\n'
    (output / "opscope.rb").write_text(formula, encoding="utf-8")


def checksums(directory, output):
    # EN: Hash actual output bytes and escape filenames using the format accepted by GNU verification tools.
    # ES: Se calculan hashes de los bytes reales y se escapan nombres según el formato de las herramientas GNU.
    root, files = files_in(directory)
    output = Path(output).resolve()
    lines = []
    for path in files:
        if path.resolve() not in (output, Path(str(output) + ".sig")):
            name = path.relative_to(root).as_posix()
            escaped = any(character in name for character in "\\\r\n")
            if escaped:
                name = name.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")
            # GNU checksum tools prefix escaped records with a backslash.
            lines.append(("\\" if escaped else "") + f"{digest(path)}  {name}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _bounded_bytes(path, limit=MAX_METADATA_BYTES):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("Required distribution file is missing, linked or too large.")
    with path.open("rb") as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ValueError("Distribution metadata exceeds its byte bound.")
    return content


def _safe_name(name):
    if not isinstance(name, str) or not name or len(name) > 1024 or name.startswith("/") or "\\" in name or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValueError("Archive contains an unsafe path.")
    parts = name.split("/")
    if any(not part or part in (".", "..") or ":" in part or part.endswith((".", " ")) for part in parts):
        raise ValueError("Archive contains a non-portable path.")
    return name


class _ArchiveBudget:
    def __init__(self):
        self.entries = 0
        self.expanded = 0

    def entry(self, size):
        self.entries += 1
        if self.entries > MAX_ARCHIVE_ENTRIES or size < 0 or size > MAX_ARTIFACT_BYTES:
            raise ValueError("Archive exceeds its entry or member-size bound.")

    def observe(self, content):
        self.expanded += len(content)
        if self.expanded > MAX_EXPANDED_BYTES:
            raise ValueError("Distribution exceeds its expanded-byte bound.")
        return content


def _zip_headers(path):
    # Bound the central directory before ZipFile allocates one object per entry.
    with Path(path).open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(max(0, size - 65557))
        tail = stream.read(65557)
    offset = tail.rfind(b"PK\x05\x06")
    if offset < 0 or len(tail) - offset < 22:
        raise ValueError("ZIP has no bounded end record.")
    _, disk, central_disk, disk_entries, entries, central_size, central_offset, comment = struct.unpack_from("<4s4H2LH", tail, offset)
    if disk or central_disk or disk_entries != entries or entries == 65535 or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF or entries > MAX_ARCHIVE_ENTRIES or central_size > MAX_METADATA_BYTES or offset + 22 + comment != len(tail) or central_offset + central_size > size:
        raise ValueError("ZIP central directory exceeds supported bounds.")


def _hash_member(stream, size, budget, count_bytes=True, capture=False, header=False):
    hashes = {"sha256": hashlib.sha256(), "sha1": hashlib.sha1()}
    total = 0
    content = bytearray()
    head = bytearray()
    while True:
        block = stream.read(1024 * 1024)
        if not block:
            break
        total += len(block)
        if total > size:
            raise ValueError("Archive member exceeds its declared size.")
        if count_bytes:
            budget.observe(block)
        for value in hashes.values():
            value.update(block)
        if capture:
            if total > MAX_METADATA_BYTES:
                raise ValueError("Package metadata exceeds its bound.")
            content.extend(block)
        if header and len(head) < 4096:
            head.extend(block[:4096 - len(head)])
    if total != size:
        raise ValueError("Archive member is truncated.")
    return {key: value.hexdigest() for key, value in hashes.items()} | {"size": total, "content": bytes(content), "head": bytes(head)}


def _archive_members(path, budget):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ValueError("Archive must be a bounded regular file.")
    result = {}
    seen = set()

    def register(raw, size, directory=False):
        name = _safe_name(raw[:-1] if directory and raw.endswith("/") else raw)
        key = name.casefold()
        if key in seen:
            raise ValueError("Archive contains duplicate or case-ambiguous paths.")
        seen.add(key)
        budget.entry(size)
        return name

    def capture(name):
        return name.lower().endswith(".nuspec") or name.endswith("/DotnetToolSettings.xml")

    try:
        if path.name.endswith((".zip", ".nupkg")):
            _zip_headers(path)
            with zipfile.ZipFile(path) as bundle:
                for item in bundle.infolist():
                    directory = item.is_dir()
                    name = register(item.filename, item.file_size, directory)
                    mode = item.external_attr >> 16
                    kind = stat.S_IFMT(mode)
                    if item.flag_bits & 1 or item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) or kind not in (0, stat.S_IFREG, stat.S_IFDIR) or kind == stat.S_IFDIR and not directory or directory and item.file_size:
                        raise ValueError("ZIP contains links, encrypted entries or unsupported entry types.")
                    if directory:
                        continue
                    with bundle.open(item) as stream:
                        result[name] = _hash_member(stream, item.file_size, budget, capture=capture(name), header=name in ("opscope", "opscope.exe")) | {"mode": mode}
        elif path.name.endswith(".tar.gz"):
            class BoundedTarReader:
                def __init__(self, stream):
                    self.stream = stream

                def read(self, size):
                    return budget.observe(self.stream.read(size))

            with gzip.open(path, "rb") as compressed:
                bounded = BoundedTarReader(compressed)
                class BoundedTarInfo(tarfile.TarInfo):
                    def _proc_member(self, bundle):
                        # Extended headers are decoded before iteration yields a member.
                        if self.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK) and self.size > MAX_METADATA_BYTES:
                            raise ValueError("TAR extended metadata exceeds its byte bound.")
                        if self.type == tarfile.GNUTYPE_SPARSE:
                            raise ValueError("Sparse TAR members are unsupported.")
                        return super()._proc_member(bundle)

                with tarfile.open(fileobj=bounded, mode="r|", tarinfo=BoundedTarInfo) as bundle:
                    for item in bundle:
                        name = register(item.name, item.size, item.isdir())
                        if item.issym() or item.islnk() or item.sparse is not None or not (item.isfile() or item.isdir()) or item.isdir() and item.size:
                            raise ValueError("TAR contains links or unsupported entry types.")
                        if item.isdir():
                            continue
                        with bundle.extractfile(item) as stream:
                            result[name] = _hash_member(stream, item.size, budget, count_bytes=False, capture=capture(name), header=name in ("opscope", "opscope.exe")) | {"mode": item.mode}
                while bounded.read(1024 * 1024):
                    pass
        else:
            raise ValueError("Unsupported distribution archive.")
    except (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise ValueError("Distribution archive is invalid or unreadable.") from error
    if not result:
        raise ValueError("Distribution archive is empty.")
    return result


def _json_metadata(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Metadata contains duplicate JSON properties.")
            result[key] = value
        return result
    try:
        return json.loads(_bounded_bytes(path).decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("Distribution JSON metadata is invalid.") from error


def _verify_sbom(path, payload, version, rid):
    document = _json_metadata(path)
    if not isinstance(document, dict) or document.get("spdxVersion") != "SPDX-2.3" or document.get("SPDXID") != "SPDXRef-DOCUMENT" or document.get("name") != f"Opscope-{version}-{rid}":
        raise ValueError("SBOM identity does not match the distribution.")
    packages = document.get("packages")
    if not isinstance(packages, list):
        raise ValueError("SBOM package metadata is missing.")
    root = [package for package in packages if isinstance(package, dict) and package.get("SPDXID") == "SPDXRef-Opscope"]
    if len(root) != 1 or root[0].get("name") != "Opscope" or root[0].get("versionInfo") != version or root[0].get("filesAnalyzed") is not True:
        raise ValueError("SBOM package version or identity is incorrect.")
    listed = document.get("files")
    if not isinstance(listed, list) or len(listed) != len(payload):
        raise ValueError("SBOM file coverage does not match archive contents.")
    names = set()
    for item in listed:
        if not isinstance(item, dict) or not isinstance(item.get("fileName"), str) or not item["fileName"].startswith("./"):
            raise ValueError("SBOM contains an invalid file entry.")
        name = _safe_name(item["fileName"][2:])
        if name not in payload or name in names:
            raise ValueError("SBOM contains missing, duplicate or unexpected file entries.")
        names.add(name)
        checks = item.get("checksums")
        if not isinstance(checks, list):
            raise ValueError("SBOM lacks file checksums.")
        declared = {}
        for check in checks:
            if not isinstance(check, dict) or check.get("algorithm") in declared:
                raise ValueError("SBOM file checksums are invalid or ambiguous.")
            declared[check.get("algorithm")] = check.get("checksumValue")
        if declared.get("SHA256") != payload[name]["sha256"] or declared.get("SHA1") != payload[name]["sha1"]:
            raise ValueError("SBOM hashes do not match the archive bytes.")
    verification = hashlib.sha1("".join(sorted(item["sha1"] for item in payload.values())).encode()).hexdigest()
    declared_verification = root[0].get("packageVerificationCode")
    if not isinstance(declared_verification, dict) or declared_verification.get("packageVerificationCodeValue") != verification:
        raise ValueError("SBOM package verification code does not match shipped files.")


def _verify_binary(payload, rid):
    executable = "opscope.exe" if rid.startswith("win-") else "opscope"
    if executable not in payload or not {"README.md", "LICENSE"}.issubset(payload):
        raise ValueError("Binary archive lacks its executable, README or license.")
    entry = payload[executable]
    head = entry["head"]
    arm = rid.endswith("-arm64")
    valid = False
    if rid.startswith("linux-") and len(head) >= 20:
        valid = head[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", head, 18)[0] == (183 if arm else 62)
    elif rid.startswith("win-") and len(head) >= 64 and head[:2] == b"MZ":
        offset = struct.unpack_from("<I", head, 60)[0]
        valid = offset <= len(head) - 6 and head[offset:offset + 4] == b"PE\0\0" and struct.unpack_from("<H", head, offset + 4)[0] == (0xAA64 if arm else 0x8664)
    elif rid.startswith("osx-") and len(head) >= 8:
        valid = struct.unpack_from("<II", head)[0:2] == (0xFEEDFACF, 0x0100000C if arm else 0x01000007)
    if not valid or not rid.startswith("win-") and not entry["mode"] & 0o111:
        raise ValueError("Executable format, architecture or executable permissions do not match the RID.")


def verify_archive(archive_path, sbom_path, rid, version):
    validate_version(version)
    if rid not in RIDS:
        raise ValueError("Unsupported binary RID.")
    budget = _ArchiveBudget()
    payload = _archive_members(archive_path, budget)
    _verify_binary(payload, rid)
    _verify_sbom(sbom_path, payload, version, rid)
    return {"version": version, "rid": rid, "filesVerified": len(payload), "expandedBytes": budget.expanded, "publisherSignatureVerified": False}


def _verify_tool(payload, version):
    specs = [name for name in payload if name.lower().endswith(".nuspec")]
    settings = [name for name in payload if name.endswith("/DotnetToolSettings.xml")]
    if len(specs) != 1 or len(settings) != 1:
        raise ValueError("Tool package must have one nuspec and one command settings file.")
    spec = _xml(payload[specs[0]]["content"])
    metadata = [element for element in spec if _local(element.tag) == "metadata"]
    if _local(spec.tag) != "package" or len(metadata) != 1:
        raise ValueError("Tool package metadata is missing or ambiguous.")
    def values(name):
        return [(element.text or "").strip() for element in metadata[0] if _local(element.tag) == name]
    types = [element.attrib.get("name") for group in metadata[0] if _local(group.tag) == "packageTypes" for element in group if _local(element.tag) == "packageType"]
    if values("id") != ["Opscope"] or values("version") != [version] or types != ["DotnetTool"]:
        raise ValueError("NuGet package ID, version or package type does not match the tool.")
    command_file = _xml(payload[settings[0]]["content"])
    commands = [element for group in command_file if _local(group.tag) == "Commands" for element in group if _local(element.tag) == "Command"]
    if _local(command_file.tag) != "DotNetCliTool" or command_file.attrib != {"Version": "1"} or len(commands) != 1 or commands[0].attrib != {"Name": "opscope", "EntryPoint": "opscope.dll", "Runner": "dotnet"}:
        raise ValueError("Tool command settings do not match the expected command.")
    prefix = settings[0].rsplit("/", 1)[0] + "/"
    if not {prefix + name for name in ("opscope.dll", "opscope.deps.json", "opscope.runtimeconfig.json")}.issubset(payload):
        raise ValueError("Tool package lacks its entrypoint or runtime metadata.")


def verify_assets(directory, version, repository=None):
    validate_version(version)
    if not isinstance(repository, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("A concrete owner/name repository is required to verify package manifests.")
    root, paths = files_in(directory)
    if len(paths) > MAX_ARCHIVE_ENTRIES or any(path.stat().st_size > MAX_ARTIFACT_BYTES for path in paths):
        raise ValueError("Distribution exceeds its file or artifact-byte bound.")
    actual = {path.relative_to(root).as_posix(): path for path in paths if path.relative_to(root).as_posix() not in ("SHA256SUMS", "SHA256SUMS.sig")}
    listed = {}
    try:
        for line in _bounded_bytes(root / "SHA256SUMS").decode("utf-8").splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
            if not match:
                raise ValueError("Checksum manifest contains unsupported or invalid records.")
            name = _safe_name(match.group(2))
            if name in listed or name not in actual:
                raise ValueError("Checksum manifest has duplicate or unexpected entries.")
            listed[name] = match.group(1)
    except UnicodeError as error:
        raise ValueError("Checksum manifest must use UTF-8.") from error
    if set(actual) != set(listed):
        raise ValueError("Checksum manifest does not cover every distribution file.")
    for name, path in actual.items():
        if digest(path) != listed[name]:
            raise ValueError("Distribution checksum does not match actual bytes.")
    budget = _ArchiveBudget()
    binary_files = 0
    for rid in RIDS:
        stem = f"opscope-{version}-{rid}"
        payload = _archive_members(root / (stem + (".zip" if rid.startswith("win-") else ".tar.gz")), budget)
        _verify_binary(payload, rid)
        _verify_sbom(root / (stem + ".spdx.json"), payload, version, rid)
        binary_files += len(payload)
    tool_name = f"Opscope.{version}.nupkg"
    tool = _archive_members(root / tool_name, budget)
    _verify_tool(tool, version)
    _verify_sbom(root / "opscope-dotnet-tool.spdx.json", {tool_name: {"sha256": digest(root / tool_name), "sha1": digest(root / tool_name, "sha1")}}, version, "dotnet-tool")
    with tempfile.TemporaryDirectory(prefix="opscope-manifests-") as temporary:
        expected = Path(temporary)
        manifests(root, expected, version, repository)
        expected_files = {path.relative_to(expected).as_posix(): path for path in expected.rglob("*") if path.is_file()}
        actual_files = {path.relative_to(root / "manifests").as_posix(): path for path in (root / "manifests").rglob("*") if path.is_file()}
        if set(actual_files) != set(expected_files) or any(_bounded_bytes(actual_files[name]) != _bounded_bytes(path) for name, path in expected_files.items()):
            raise ValueError("Package manifests do not match actual archives, version and repository.")
        packed_manifests = _archive_members(root / f"opscope-{version}-package-manifests.tar.gz", budget)
        if set(packed_manifests) != set(expected_files) or any(packed_manifests[name]["sha256"] != digest(path) for name, path in expected_files.items()):
            raise ValueError("Package-manifest archive does not match verified manifests.")
    return {"version": version, "binaryArchivesVerified": len(RIDS), "binaryFilesVerified": binary_files, "toolPackagesVerified": 1,
            "checksummedFiles": len(actual), "archiveEntries": budget.entries, "expandedBytes": budget.expanded, "publisherSignatureVerified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("archive", "sbom", "manifests", "checksums"):
        command = commands.add_parser(name)
        command.add_argument("--input", required=True)
        command.add_argument("--output", required=True)
        if name in ("sbom", "manifests"):
            command.add_argument("--version", required=True)
        if name == "sbom":
            command.add_argument("--rid", required=True, choices=RIDS + ("dotnet-tool",))
            command.add_argument("--assets")
        if name == "manifests":
            command.add_argument("--repository", required=True)
    candidate = commands.add_parser("candidate-version")
    candidate.add_argument("--project", required=True)
    candidate.add_argument("--suffix", required=True)
    verification = commands.add_parser("verify")
    verification.add_argument("--input", required=True)
    verification.add_argument("--version", required=True)
    verification.add_argument("--repository", required=True)
    archive_verification = commands.add_parser("verify-archive")
    archive_verification.add_argument("--input", required=True)
    archive_verification.add_argument("--sbom", required=True)
    archive_verification.add_argument("--rid", required=True, choices=RIDS)
    archive_verification.add_argument("--version", required=True)
    args = parser.parse_args()
    if args.command == "archive": archive(args.input, args.output)
    elif args.command == "sbom": sbom(args.input, args.output, args.version, args.rid, args.assets)
    elif args.command == "manifests": manifests(args.input, args.output, args.version, args.repository)
    elif args.command == "checksums": checksums(args.input, args.output)
    elif args.command == "candidate-version": print(candidate_version(args.project, args.suffix))
    elif args.command == "verify": print(json.dumps(verify_assets(args.input, args.version, args.repository), sort_keys=True))
    elif args.command == "verify-archive": print(json.dumps(verify_archive(args.input, args.sbom, args.rid, args.version), sort_keys=True))


if __name__ == "__main__":
    main()
