# opscope

`opscope` is a cross-platform systems operations CLI for Linux and Windows. It is designed for the first ten minutes of an incident: capture a reliable host snapshot, spot degraded signals, inspect processes and listening sockets, and produce a shareable support bundle without requiring an agent or third-party runtime.

## What it does

- Host inventory: OS, kernel/runtime, architecture, boot time, uptime and elevation state.
- Health signals: memory pressure, disk pressure, network reachability and failed services.
- Process inventory with CPU time, memory and command line when the OS permits access.
- Listening socket discovery using native `ss`/`netstat` tooling when available.
- Running service discovery using `systemctl` on Linux and `sc.exe` on Windows.
- Security posture: host firewall state and wildcard-bound listeners, with actionable exposure findings.
- Snapshot drift detection across metrics, processes, services, disks and listeners.
- Stable JSON output for automation and human-readable output for operators.
- Redacted ZIP support bundles containing a snapshot, findings, process list, network data and collection metadata.
- Watch mode for a compact live dashboard.

The collector is intentionally read-only. It does not stop processes, change services, modify firewall rules or send telemetry.

## Requirements

- .NET 8 runtime for the framework-dependent build, or a self-contained publish.
- Source builds use the .NET 8 SDK when available and roll forward to a newer stable SDK when the 8.x SDK is not installed.
- Linux: `ss` and `systemctl` are optional enrichments. The core collector works without them.
- Windows: `sc.exe` is an optional enrichment and ships with Windows.

The self-contained publish has been checked for `linux-x64`, `linux-arm64`, `win-x64` and `win-arm64`. Framework-dependent builds still require the .NET 8 runtime on the target host.

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

- `0`: command completed and no high-severity finding was observed.
- `1`: command completed and at least one warning/error finding was observed.
- `2`: invalid command line or an operational error prevented collection.

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

`tools` checks the native utilities used for enrichment (`ss`, `systemctl`, `netstat`, `netsh`, `sc.exe`, firewall utilities and `ip`). It reports missing coverage and fails if an available utility is outside the trusted system locations, writable by a non-owner, non-executable or otherwise not securely inspected.

## Security and privacy

Collection is local and read-only. External commands are launched without a shell, with fixed executable resolution and bounded output. Support bundles omit process command lines and redact host, user, network-address and filesystem-root identifiers. Treat snapshots and bundles as operational evidence: service names, listener counts and package/runtime versions can still be sensitive. See [SECURITY.md](SECURITY.md) for the reporting policy.

## Repository layout

```text
src/Opscope/       Application source
tests/             Cross-platform smoke scripts
.github/workflows/ Build matrix for Linux and Windows
.gitattributes       Cross-platform line-ending policy
SECURITY.md          Vulnerability reporting and data-handling notes
```

