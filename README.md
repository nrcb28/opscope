# opscope

`opscope` is a cross-platform systems operations CLI for Linux, Windows and macOS, with an authenticated local web interface. It is designed for the first ten minutes of an incident: capture a reliable host snapshot, spot degraded signals, inspect processes and listening sockets, and produce a shareable support bundle without requiring an agent or third-party runtime.

## What it does

- Host inventory: OS, kernel/runtime, architecture, boot time, uptime and elevation state.
- Health signals: memory pressure, disk pressure, network reachability and failed services.
- Process inventory with CPU time, memory and command line when the OS permits access.
- Listening socket discovery using native `ss`/`netstat` tooling when available.
- Service discovery, including failed units, using `systemctl` on Linux and `sc.exe` on Windows.
- Security posture: host firewall state and wildcard-bound listeners, with actionable exposure findings.
- Firewall reports distinguish enabled state and rules from effective protection, which remains unverified when the collector cannot establish complete coverage.
- Snapshot drift detection across metrics, processes, services, disks, listeners, firewall/tool trust and coverage.
- Stable snapshot JSON plus SARIF, JUnit, HTML/PDF, CSV, JSONL, CEF and real-context ASFF exports.
- Strict YAML policies, declarative plugins and bounded scenario packs.
- Optional Azure/AWS inventory, posture, health, patches, cost and supported baseline drift.
- IoC matching, observed timelines, fleet outliers and contextual triage.
- Authenticated loopback UI, redacted SQLite history, Prometheus, SSE and narrow MCP tools.
- Custody manifests, SHA-256, optional RSA-PSS signatures and AES-GCM/RSA-OAEP encryption.
- Redacted ZIP support bundles containing a snapshot, findings, process list, network data and collection metadata.
- Watch mode for a compact live dashboard.

Collection is read-only: it does not stop processes, change services, modify firewall rules or send telemetry. Explicit cloud queries and confirmed notification delivery are optional separate operations.

## Requirements

- .NET 8 ASP.NET Core runtime for the framework-dependent build (the CLI includes its local API), or a self-contained publish. Source builds require the .NET 8 SDK.
- Source builds use the .NET 8 SDK when available and roll forward to a newer stable SDK when the 8.x SDK is not installed.
- Linux: `ss` and `systemctl` provide core coverage; `lsof`, `journalctl`, `resolvectl`, `ip` and supported firewall tools are optional enrichments. `lsof` is used as a read-only listener fallback.
- Windows: `netstat`, `netsh` and `sc.exe` provide core coverage; `tasklist.exe` and `wevtutil.exe` are optional diagnostics enrichments.

The release workflow targets `linux-x64`, `linux-arm64`, `win-x64`, `win-arm64`, `osx-x64` and `osx-arm64`. The local validation includes an actual Linux self-contained publish; native Windows/macOS execution is covered by the configured CI matrix.

## Build and run

```bash
dotnet build src/Opscope/Opscope.csproj -c Release
dotnet run --project src/Opscope/Opscope.csproj -- snapshot
dotnet run --project src/Opscope/Opscope.csproj -- snapshot --json --out snapshot.json
dotnet run --project src/Opscope/Opscope.csproj -- doctor
dotnet run --project src/Opscope/Opscope.csproj -- bundle --out ./incident-bundle.zip
dotnet run --project src/Opscope/Opscope.csproj -- diff ./baseline.json
dotnet run --project src/Opscope/Opscope.csproj -- tools --json
dotnet run --project src/Opscope/Opscope.csproj -- watch --interval 5
```

For a portable binary:

```bash
dotnet publish src/Opscope/Opscope.csproj -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/linux-x64
dotnet publish src/Opscope/Opscope.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/win-x64
```

## Exit codes

- `0`: requested work completed without a finding at the selected threshold.
- `1`: a finding meets `--fail-on`, or archive verification failed.
- `2`: invalid input or required work could not complete. `--require-complete` also rejects coverage warnings.

## Commands

| Command | Purpose |
| --- | --- |
| `snapshot` | Collect and print a full host snapshot. |
| `doctor` | Collect a snapshot and print only actionable findings. |
| `bundle` | Create a ZIP with redacted JSON evidence for incident handoff. |
| `watch` | Refresh a compact health dashboard until Ctrl+C. |
| `diff <snapshot.json>` | Compare a saved baseline with a fresh collection from the current host. |
| `tools` | Inventory required/enrichment utilities, trusted paths, permissions and versions. |
| `version` | Print build/runtime information. |

Common options: `--json`, `--redact`, `--out <path>`, `--no-processes`, `--no-network`, `--no-services`, `--top <n>`, `--interval <seconds>`, `--help`.

Use `snapshot --redact --json --out safe-snapshot.json` when the output may leave the host. This omits process command lines and redacts host, user, network-address and filesystem-root identifiers. The default snapshot remains detailed for local troubleshooting.

`diff` returns exit code `1` when it detects a significant metric change, a host mismatch, or an added/removed/changed process, service or listener. Save a baseline with `snapshot --json --out baseline.json`, then run `diff baseline.json` during a maintenance window or incident investigation.

`tools` checks the native utilities used for enrichment (`ss`, `systemctl`, `lsof`, `journalctl`, `resolvectl`, `netstat`, `netsh`, `sc.exe`, `tasklist.exe`, `wevtutil.exe`, firewall utilities and `ip`). It reports missing coverage and fails if an available utility is outside the trusted system locations, writable by a non-owner, non-executable or otherwise not securely inspected. Every optional tool uses the same fixed-path, owner, permission, ACL and reparse-point validation before execution.

The regression suite covers localized UFW parsing, nftables inbound-scope verification, unsafe executable blocking, private output permissions, typed redaction of addresses/ports/paths/identities, preservation of incomplete collection state, and diff detection before redaction.

## Security and privacy

Collection is local and read-only. External commands are launched without a shell, with fixed executable resolution and bounded output. Support bundles omit process command lines and redact host, user, network-address and filesystem-root identifiers. Treat snapshots and bundles as operational evidence: service names, listener counts and package/runtime versions can still be sensitive. See [SECURITY.md](SECURITY.md) for the reporting policy.

## Repository layout

```text
src/Opscope/       CLI and command dispatch
src/Opscope.Core/  Collection, models, drift, redaction and bounded input
src/Opscope.Cloud/ Optional official-CLI-backed Azure/AWS providers
src/Opscope.Reporting/ Policies, packs, exports and protected bundles
src/Opscope.Evidence/ Optional evidence, IoCs, timeline and fleet
src/Opscope.Api/   Embedded local UI, history, metrics and MCP
src/Opscope.Integrations/ Explicit opt-in delivery
tests/             Cross-platform smoke scripts
.github/workflows/ Build matrix for Linux and Windows
tests/Opscope.Tests/ Deterministic parser and security regression tests
.gitattributes       Cross-platform line-ending policy
SECURITY.md          Vulnerability reporting and data-handling notes
```



## Implemented proposal commands

```sh
opscope policy validate examples/policies/opscope.yml
opscope snapshot --policy examples/policies/opscope.yml --json --out policy-baseline.json
opscope doctor --policy examples/policies/opscope.yml --format sarif --out findings.sarif
opscope plugins check examples/policies/plugin-exposure.yml
opscope pack validate examples/packs/ssh-comprometido.yml
opscope snapshot --pack examples/packs/disk-full.yml --redact --json --out scenario.json
opscope report baseline.json --format html --out handoff.html --quiet
opscope report baseline.json --format pdf --out handoff.pdf --quiet
opscope triage --scenario disk-full
opscope ioc examples/iocs/sample.csv
opscope timeline baseline.json --evidence logs --format csv --out timeline.csv
opscope fleet host-a.json host-b.json --format json
opscope tui --page services --interval 5
opscope environment
```

An explicit `--policy` or a local `opscope.yml` applies configurable CPU/memory/disk thresholds, allowed ports, required services and numeric rules. Custom thresholds replace the stock health thresholds. Plugins are declarative; packs select existing collectors and cannot launch arbitrary commands or read arbitrary files. Examples cover high CPU, disk pressure, exposed ports, SSH and service incidents.

`snapshot --json` stays a flat snapshot, including with policies/packs. Additional evidence is stored in optional `reports`; legacy snapshots remain readable. `report` and extended analysis commands use an analysis envelope. Detailed local snapshots preserve their original default; use `--redact` before sharing. New report formats redact by default and accept explicit `--full`. Bundles and history always redact.

Use `--fail-on info|warning|critical|none` (default `warning`). Required cloud failures set `operationSucceeded=false`; legitimate empty inventories remain successful. Optional service/permission gaps remain warnings unless `--require-complete` is used. Redacted baselines cannot prove exact host, disk, service or listener identity changes: count/state comparisons carry explicit coverage warnings.

## Custody bundles and handoff

```sh
opscope bundle --pack examples/packs/base.yml --evidence security --out incident.zip
opscope verify incident.zip
opscope report baseline.json --bundle incident.zip --format html --out handoff.html --quiet
opscope bundle --out incident.bundle.enc --sign-private-key signer-private.pem --encrypt-public-key recipient-public.pem
opscope verify incident.bundle.enc --public-key trusted-signer.pem --private-key recipient-private.pem
opscope decrypt incident.bundle.enc --private-key recipient-private.pem --out decrypted.zip
```

`bundle` and `offline` create a redacted entry-hash manifest and detached whole-file SHA-256 checksum. Optional RSA-PSS signatures require a separately trusted public key; hashes alone do not authenticate a signer. Optional encryption uses AES-GCM and RSA-OAEP-SHA256. Keys never enter the evidence. Verification bounds archive sizes and validates names, hashes, encryption authentication and supplied signature trust.

A report's `--bundle` option includes the actual file digest and verification result. Native extra evidence requires a fresh local collection; omit `--input` when asking to collect logs or account metadata. Saved evidence remains available to offline reports and analyzers. Platform coverage and supported IoC patterns are documented in [Evidence](src/Opscope.Evidence/README.md).

## Local interface, history and cloud

```sh
opscope serve
opscope serve --history ./private/history.sqlite --retention 100 --retention-days 30
opscope serve --cloud azure,aws --subscriptions <id-a>,<id-b> --profiles account-a,account-b --regions eu-west-1
opscope history list --history ./private/history.sqlite
opscope mcp
opscope azure inventory --subscription <subscription-id>
opscope aws posture --profile audit --region eu-west-1
opscope cloud patches --provider aws --profile audit --region eu-west-1
```

The embedded English/Spanish UI has light/dark themes, keyboard search, findings, processes/ports, services, drift, observed timeline, history/trends, fleet upload, policy validation/download and verified report/bundle downloads. No assets come from a CDN. Policy editing is preview/download only and never applies host configuration. The server listens only on `127.0.0.1`, on a random port by default, with a fresh session token, exact Host/Origin checks and no CORS grant. Full identifiers require an explicit toggle; history and exports stay redacted.

For SSH forwarding, preserve the same local and remote port so Host/Origin checks remain valid: for example, `serve --port 48321` and `ssh -L 48321:127.0.0.1:48321 host`. Prometheus, SSE and HTTP MCP require the session token. Stdio MCP exposes only snapshots/findings. [API details](src/Opscope.Api/README.md).

Cloud queries require an installed authenticated Azure CLI (Resource Graph extension preinstalled) or AWS CLI v2. The implementation uses official CLIs instead of adding the proposed modular cloud SDKs. It disables telemetry, dynamic extension installation, auto-upgrade and interactive prompts in child processes. Existing authentication caches remain under the CLIs' control and are not included in evidence.

Cloud operations are inventory, posture, health, VM/instance context, bundle, drift, patches and cost; Azure also exposes Arc. Multiple scopes are fixed when a UI session starts and appear as anonymous numbered choices. Identity-only IMDS/IMDSv2 lookup occurs only through explicit cloud commands or `--cloud-context`. Local-to-cloud identity is asserted only when metadata matches the selected resource; SSM service state never proves cloud Online status. No agent or paid service is enabled.

See [cloud commands, permissions and limits](docs/cloud.md), [Azure drift formats](docs/azure-drift.md), and the [read-only AWS IAM policy example](docs/cloud-readonly-iam.json). Raw Bicep/HCL is not executed; use compiled ARM or supported Terraform JSON. Cost evidence is observational and does not delete/resize resources or promise savings.

`notify` previews bounded redacted summaries for Slack, Teams, Jira, Azure DevOps, Azure Monitor or CloudWatch. Only `--confirm-send` enables delivery to an existing destination with separately supplied credentials. Neither local collection nor the web UI sends notifications. [Delivery and release setup](docs/delivery.md).

For ASFF import, supply `--format asff --account <12-digit-id> --region <region>`. Generic library ASFF without context is explicitly marked as an offline placeholder.

## Validation and packaging

```sh
dotnet build src/Opscope/Opscope.csproj -c Release
# Run every tests/*/*.csproj regression project.
python3 tests/cli_smoke.py
python3 -m unittest discover -s packaging -p 'test_*.py'
dotnet pack src/Opscope/Opscope.csproj -c Release -p:PublishSingleFile=false -o artifacts/tool
```

CI runs .NET checks on Linux/Windows/macOS and Playwright on Linux/Windows. Provider, identity and notification tests use injected transports, with no live tenant/account, real messages or infrastructure changes. Release tooling creates six-RID archives, actual-output SBOMs/checksums, optional real signatures/provenance, and winget/Homebrew manifests derived from real artifact hashes. Publication is a separate operator action; unsigned artifacts are not labelled signed.

The [proposal matrix](docs/proposals.md) maps all 60 items to code, supported scopes and explicit limitations. The recommended local web interface was selected; optional native-window alternatives are not required to run it. Review operational evidence before sharing it.
