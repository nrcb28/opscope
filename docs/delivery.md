# Explicit delivery and release packaging

Local collection never sends notifications or cloud log events. `notify` prepares a bounded redacted payload and displays it by default. Any network request or CloudWatch write requires `--confirm-send` on that invocation. The API equivalent is `NotificationSender.SendAsync(report, new NotificationOptions(..., ConfirmSend: true))` in `Opscope.Integrations`.

Delivery includes a summary of at most ten findings and aggregate counts, clipped to 2,500 characters and a 16 KiB JSON body. It excludes the report data object, host snapshot, command lines, log contents, and arbitrary resource properties. Findings pass through the common evidence redactor even when the source report was collected with full identifiers. Review the preview for context-sensitive information before sending.

## Notification targets

Examples below preview only. Add `--confirm-send` after reviewing the displayed payload and confirming the destination.

```sh
# Reuse a saved snapshot rather than collecting again.
opscope notify --input snapshot.json --target slack --credential-env OPSCOPE_SLACK_WEBHOOK
opscope notify --input snapshot.json --target teams --credential-env OPSCOPE_TEAMS_WEBHOOK

# Jira Cloud: variable contains email@example.com:api_token, used as HTTP Basic.
opscope notify --input snapshot.json --target jira --endpoint https://example.atlassian.net \
  --project OPS --issue-type Task --credential-env OPSCOPE_JIRA_CREDENTIAL

# Azure DevOps: variable contains a PAT with the intended work-item permission.
# Endpoint is the organization root; the project and work-item path are appended.
opscope notify --input snapshot.json --target azure-devops --endpoint https://dev.azure.com/example \
  --project Operations --issue-type Issue --credential-env OPSCOPE_ADO_PAT

# Azure Monitor: variable contains an already acquired bearer token for the DCE.
opscope notify --input snapshot.json --target azure-monitor \
  --endpoint https://example.eastus.ingest.monitor.azure.com \
  --dcr dcr-0123456789abcdef0123456789abcdef --stream Custom-Opscope \
  --credential-env OPSCOPE_MONITOR_TOKEN

# CloudWatch: uses existing AWS CLI credentials/SSO/role chain and optional profile.
opscope notify --input snapshot.json --target cloudwatch --profile operations \
  --region us-east-1 --log-group /opscope/reports --log-stream manual
```

Slack and Teams webhook URLs can reside entirely in the named environment variable. An explicit HTTPS `--endpoint` also works when no webhook variable is supplied. Slack text parsing, mentions and link unfurling are disabled; Teams uses an Adaptive Card payload. Jira uses the v3 issue API and Atlassian Document Format; this implementation does not support Jira Server v2 or OAuth acquisition. Azure DevOps uses JSON Patch to create one work item. No ticket is created in preview mode.

HTTP delivery requires HTTPS, rejects URL user information and fragments, disables proxies and redirects, uses a three-second connect/ten-second total deadline, and reads at most 64 KiB of response. Authentication values must come from the explicitly named environment variable; credentials, webhook URLs and response bodies are never returned in delivery results. Automatic retries are disabled because a lost response can occur after a target accepted the request.

Azure Monitor sends one summary record with `TimeGenerated`, `Kind`, `FindingCount`, and `Summary` to an existing Data Collection Endpoint/DCR/stream. The DCR's stream declaration and destination table must accept that schema, and the supplied token must already have the required ingestion authorization. No table, DCR, token, identity or paid service is created or enabled.

CloudWatch executes exactly `aws logs put-log-events` using a trusted AWS CLI path and argument arrays, with a bounded inline JSON event. The existing group and stream must already exist; the current credential chain needs `logs:PutLogEvents`. No shell, login, group/stream creation, profile changes or credential writes occur. The event timestamp is delivery time and the summary retains original collection time. CLI stdout/stderr are discarded from results, and a rejection or unknown delivery outcome is reported explicitly.

## Release artifacts

The reusable [package workflow](../.github/workflows/package-build.yml) builds self-contained single-file archives for `linux-x64`, `linux-arm64`, `win-x64`, `win-arm64`, `osx-x64`, and `osx-arm64`, plus a framework-dependent .NET 8 tool package. It produces actual-output SPDX SBOMs, checksums and package-manager manifests, then verifies the assembled package set. The CLI regression suite runs against published executables when the target architecture matches the runner, and against an installed local .NET tool. The tool test uses a local-only NuGet source and a fresh cache, then checks removal. Cross-built targets receive artifact verification without a native-execution claim. Native platform diagnostic coverage still depends on installed tools and permissions.

### Candidate packages from CI

After the .NET and browser regression jobs succeed, [CI](../.github/workflows/ci.yml) calls the package workflow with read-only repository permissions and no signing secrets. The candidate version comes from the literal `<Version>` in `src/Opscope/Opscope.csproj`, followed by `-ci.<run number>`; a candidate is tied to that source revision and workflow execution.

Open a successful [CI execution](https://github.com/nrcb28/opscope/actions/workflows/ci.yml), download `package-assets` from **Artifacts**, and extract the outer GitHub artifact ZIP. Artifacts are retained for fourteen days and downloads require GitHub access to the repository. The set contains all six platform archives, the `.nupkg`, their SBOMs, `SHA256SUMS` and generated package-manager manifests. These are temporary workflow downloads; the CI workflow creates no tag or public release and publishes to no package registry.

Choose the archive matching your operating system and architecture. Extract that archive into a local directory and launch `./opscope serve` on Linux/macOS, or `.\opscope.exe serve` in PowerShell. The executable prints the authenticated local URL. These self-contained archives include the runtime. To use the `.nupkg` instead, install the .NET 8 ASP.NET Core runtime and install the exact downloaded version from its local directory:

```sh
dotnet tool install Opscope --tool-path ./opscope-tool --add-source ./packages --version <downloaded-version> --ignore-failed-sources
./opscope-tool/opscope serve
dotnet tool uninstall Opscope --tool-path ./opscope-tool
```

In PowerShell, launch the installed tool with `.\opscope-tool\opscope.exe serve`. Replace `./packages` and `<downloaded-version>` with the directory and version actually downloaded. `--tool-path` keeps the tool installation in the selected directory.

From a source checkout, the packaging helper can derive a candidate version without evaluating MSBuild or execute integrity verification against a downloaded set:

```sh
python3 packaging/release_assets.py candidate-version --project src/Opscope/Opscope.csproj --suffix ci.123
python3 packaging/release_assets.py verify --input ./packages --version <downloaded-version> --repository nrcb28/opscope
```

`verify` requires all six archives and their SBOMs, the `Opscope.<version>.nupkg` tool package and its SBOM, generated package-manager manifests and their archive, and a complete `SHA256SUMS`. It checks actual hashes, archive paths and entries, executable headers for the claimed RID, SBOM file hashes, tool package identity/version/command, and manifest contents. Limits are 1 GiB per file, 2 GiB of expanded content and 10,000 archive entries overall, and 16 MiB per metadata document. The project XML used for candidate versions is limited to 256 KiB and read without evaluating MSBuild.

An individual platform archive can also be checked before extraction from a source checkout:

```sh
python3 packaging/release_assets.py verify-archive --input opscope-<downloaded-version>-linux-x64.tar.gz \
  --sbom opscope-<downloaded-version>-linux-x64.spdx.json --rid linux-x64 --version <downloaded-version>
```

The helper performs local checks and no provider or package-registry requests. It does not establish publisher identity, a native signature, notarization or licenses of embedded runtime components. The run number above is an example. Use the version attached to the selected execution for verification. Package-manager manifests contain release URLs calculated from the repository and version; those URLs become installable only after corresponding release assets are published. Candidate downloads can be used directly as archives or local tool packages.

### Versioned releases

Push a semantic version tag such as `v0.2.0`, or run the workflow manually with `version=0.2.0`. A manual run builds downloadable workflow artifacts by default. Tag runs create a **draft** GitHub release; manual runs do so only with `create_draft=true` and an existing matching tag at the selected commit. The workflow refuses to overwrite an already published release. It does not publish to NuGet, submit winget manifests, modify a Homebrew tap, or make a draft public.

Each archive has a standalone SPDX 2.3 SBOM containing the SHA-256/SHA-1 hashes of actual published files and resolved NuGet package identities/checksums. License values that cannot be established from the build are `NOASSERTION`. The SBOM describes shipped file bytes and resolved package metadata; it is not a full decomposition or license audit of components embedded in a single-file runtime. All downloadable assets and generated manifests are covered by `SHA256SUMS`. GitHub build provenance attestations bind archives, tool packages, SBOMs and the checksum manifest to the workflow run on public repositories. For a private repository, set `OPSCOPE_ENABLE_ATTESTATIONS=true` as a repository variable only when the account supports GitHub artifact attestations; otherwise this step is skipped.

`packaging/release_assets.py` generates winget manifests and a Homebrew formula only after all six named archives exist. It computes every hash from those files and fails if an archive is missing. Repository owner/name and semantic version determine the URLs and publisher identifier; review those metadata before submitting to a package manager. The generator performs no network requests and never invents or copies example hashes into generated manifests.

```sh
python3 packaging/release_assets.py manifests --input dist --output dist/manifests \
  --version 0.2.0 --repository YOUR_OWNER/YOUR_REPOSITORY
python3 packaging/release_assets.py checksums --input dist --output dist/SHA256SUMS

# Local package creation and installation without publishing.
dotnet pack src/Opscope/Opscope.csproj -c Release -p:PublishSingleFile=false \
  -p:SelfContained=false -p:Version=0.2.0 -p:PackageVersion=0.2.0 -o artifacts/packages
dotnet tool install Opscope --tool-path ./artifacts/tool \
  --add-source ./artifacts/packages --version 0.2.0
```

## Optional signatures

Signing is performed only with real credentials configured by a repository maintainer. Absent credentials are reported as a skipped signature, never represented as a signed binary.

* `OPSCOPE_WINDOWS_CERTIFICATE_BASE64` and `OPSCOPE_WINDOWS_CERTIFICATE_PASSWORD`: import a real PFX temporarily, Authenticode-sign the Windows executable with SHA-256 and a timestamp, validate the signature, then remove the temporary certificate/file.
* `OPSCOPE_MACOS_CERTIFICATE_BASE64`, `OPSCOPE_MACOS_CERTIFICATE_PASSWORD` and `OPSCOPE_MACOS_SIGN_IDENTITY`: import a real Developer ID certificate into a temporary keychain, sign/verify the macOS binary, then remove the keychain. The supplied entitlements allow .NET JIT and native library loading. Apple notarization is a separate publication step; this workflow does not claim notarization or staple a ticket.
* `OPSCOPE_RELEASE_SIGNING_KEY_PEM` and optional `OPSCOPE_RELEASE_SIGNING_KEY_PASSWORD`: use an actual RSA/ECDSA PEM key to sign `SHA256SUMS`, emit its public key, and verify the resulting detached signature. This key is never generated automatically or stored in artifacts.

On Linux, verify the downloaded files from their artifact directory with `sha256sum -c SHA256SUMS`. When a detached signature is present, first verify it against a separately trusted release public key:

```sh
openssl dgst -sha256 -verify trusted-release-public.pem -signature SHA256SUMS.sig SHA256SUMS
gh attestation verify opscope-0.2.0-linux-x64.tar.gz --repo YOUR_OWNER/YOUR_REPOSITORY
```

A public key downloaded from the same release is useful for inspection, but establishes publisher trust only when its fingerprint is verified through a trusted channel. Package-manager submission, native signing/notarization infrastructure and public release approval remain maintainer actions.

## Validation evidence

Fake HTTP/CLI transport tests exercise previews, all six delivery targets, credential handling, redirect rejection, response bounds, redaction and cancellation without sending notifications or log events. Packaging tests cover actual-file hashes, required archives, file-level SBOMs, archive contents and malformed inputs. [Distribution validation](distribution-validation.md) records the executions and their scope. Native signatures, notarization, live cloud permissions and package-registry ingestion require their corresponding credentials or environments; a successful package build does not certify them.
