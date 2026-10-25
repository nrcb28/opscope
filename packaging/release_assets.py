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
import tarfile
import uuid
import zipfile

RIDS = ("linux-x64", "linux-arm64", "win-x64", "win-arm64", "osx-x64", "osx-arm64")


def digest(path, algorithm="sha256"):
    value = hashlib.new(algorithm)
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def validate_version(version):
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", version):
        raise ValueError("Version must be a concrete semantic version.")
    return version


def files_in(directory):
    directory = Path(directory).resolve()
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
    directory, output = Path(directory), Path(output)
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
    root = Path(directory).resolve()
    output = Path(output).resolve()
    lines = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("Checksum input must not contain symlinks.")
        if path.is_file() and path.resolve() != output and not path.name.endswith(".sig"):
            lines.append(f"{digest(path)}  {path.relative_to(root).as_posix()}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


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
    args = parser.parse_args()
    if args.command == "archive": archive(args.input, args.output)
    elif args.command == "sbom": sbom(args.input, args.output, args.version, args.rid, args.assets)
    elif args.command == "manifests": manifests(args.input, args.output, args.version, args.repository)
    else: checksums(args.input, args.output)


if __name__ == "__main__":
    main()
