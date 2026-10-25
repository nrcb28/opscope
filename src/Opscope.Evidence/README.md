# Evidence and offline analysis

`Opscope.Evidence` references `Opscope.Core` only. It never installs agents, changes services or firewall rules, contacts IoCs, executes pack commands, refreshes package metadata, or opens Docker/Podman/Kubernetes sockets. Serialize analysis with `ReportSecurity.Serialize` or the reporting exporter to preserve default redaction of structured identity fields.

Public entry points:

- `EvidenceCollector.CollectAsync(snapshot, groups, cancellationToken)` collects bounded optional evidence. Empty groups or `all` select `logs`, `packages`, `users`, `tasks`, `certificates`, `security`, `environment`. `EvidenceData.Records` includes source/status; `Coverage` uses `pass`, `fail`, `not_evaluated`.
- `IocAnalyzer.AnalyzeAsync(snapshot, path, cancellationToken)` imports CSV or STIX JSON using bounded regular-file reads. `Parse` and `Analyze` support fully offline analysis. CSV header: `type,value,label`; supported types: IP, domain, process, MD5, SHA-1, SHA-256. STIX 2.x observable objects and simple equality indicators are supported; compound patterns are explicitly skipped with warnings. No DNS/network lookup occurs. Process names match exactly with platform case rules; domain matching uses exact textual tokens.
- Executable hash matching is available for recent same-host Linux snapshots only: a positive observed PID and matching live process identity identify `/proc/PID/exe`. Reads are bounded to 64 MiB per file, 128 processes, and five seconds overall. Saved snapshots have no trustworthy file hashes and produce an explicit coverage warning. MD5/SHA-1 serve legacy indicator comparison only, never custody signatures or integrity guarantees.
- `TimelineBuilder.Build(snapshot, baseline, records)` merges boot, snapshot, failed-service observations, drift, and timestamped logs. Drift uses the current observation timestamp with an explicit interval warning. `ToCsv` emits UTC ISO 8601 and escapes spreadsheet formulas.
- `FleetAnalyzer.Compare(snapshots)` supports 2–256 snapshots with at least two host identities; duplicate host histories use the latest snapshot. An outlier requires utilization >=85% and >=20 percentage points above the median. Mixed platforms, stale observations and role differences are caveats, not evidence of compliance.
- `TriageAdvisor.Analyze(snapshot, scenario)` supports `high-cpu`, `disk-full`, `port-exposed` and returns contextual, observational steps. Cumulative process CPU is never labeled an instantaneous percentage.
- `PlatformInspector.CollectAsync` reports Docker/Podman/Kubernetes/local container signals without reading environment values or service-account tokens. `EnrichSnapshotAsync` provides macOS host memory and CPU using fixed trusted native tools. Memory availability is explicitly an approximation based on free+inactive+speculative pages.

Platform coverage:

| Evidence | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Recent error logs | journalctl, 24h/200 records | System/Application Event Log, 24h/100 each | Unified log, 1h/200 records |
| Packages | dpkg-query/rpm | Machine uninstall registry (partial inventory) | pkgutil |
| Local accounts/admins | passwd/group metadata, readable sudoers; no shadow | net user and localized Administrators group | dscl |
| Schedules | Current-user cron, readable system cron, systemd timers | Task Scheduler | Current-user cron, launchctl |
| Certificates | Readable personal X509 stores | Readable personal X509 stores | Readable personal X509 stores |
| Security | Non-loopback SSH/RDP, passwd NP status, auditd state, explicit Samba minimum, static SSH config, cached apt/dnf updates | Non-loopback SSH/RDP, explicit SMB1 registry value, Defender service/policy signals, reboot indicators | Non-loopback SSH/RDP and static SSH config |

Missing tools/privileges and unsupported checks remain `not_evaluated`. Windows reboot indicators do not prove pending patch counts, and Defender service state does not prove complete protection health. macOS does not claim offline patch, SMB1, auditd, Defender or password assessment coverage. CIS-inspired checks cover selected firewall/SSH settings only; no benchmark edition or certification is claimed. Static SSH configs containing Include/Match are not treated as effective configuration. Application PEM files, arbitrary files, remote TLS endpoints, established connections and DNS history are outside the implemented evidence sources.

Run regression checks:

```sh
dotnet run --project tests/Opscope.EvidenceTests
```

Example feeds are in `examples/iocs/` and use documentation-only addresses/domains.
