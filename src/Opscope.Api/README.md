# Local interface and read-only integrations

`LocalServer.RunAsync(new ServerOptions(), cancellationToken)` runs Kestrel only on
`127.0.0.1`, with an OS-assigned port by default. The CLI's `serve` command uses
this entry point. There is no remote listener, shell endpoint, host modification,
telemetry, notification, or credential-entry flow.

The bootstrap URL contains a fresh 256-bit session token in its fragment. The
browser removes that fragment immediately and keeps the token only in memory.
Reload by reopening the bootstrap URL. Every evidence endpoint, including
Prometheus `/metrics`, SSE `/api/events`, and JSON-RPC `/mcp`, requires the
`X-Opscope-Token` header. Exact Host, Origin, referrer, and Fetch Metadata checks
also apply to static resources. External origins, DNS aliases, and forwarded
host headers cannot extend the listener's trust boundary. There is no CORS grant.

All resources are embedded and use a strict CSP, without inline scripts, remote
fonts, or a CDN. Displayed evidence uses DOM text nodes. Full identifiers require
the explicit session toggle; history, events, MCP, bundles, and exports remain
redacted. Switching back immediately removes the full view and discards stale
full-view requests.

History uses Microsoft.Data.Sqlite with a versioned schema, redaction before
insertion, count and age retention, secure deletion, a 2 MiB snapshot bound, a 64 MiB
retained-payload budget, and a 256 MiB database page bound. New Unix files use mode 0600 and newly created
history directories use 0700. Windows files use the shared private-file creator.
Prefer the default per-user application-data location. The retention API is
`HistoryStore(path, retentionCount, retentionDays)`, `Add`, `List`, `Get`, `Prune`.
It rejects symbolic-link paths and unsupported schema versions.

Collection is centralized through `SystemProbe` or an explicitly supplied shared
collector callback. A single collection/cloud gate prevents overlapping work and
applies a two-second cooldown. Collection has a 60-second cancellation deadline;
automatic refresh defaults to 30 seconds. The server accepts bounded requests,
limits connection/header counts, and permits at most four bounded SSE streams.
JSON uploads require strict UTF-8 and complete within ten seconds. Collection
failures return HTTP 503 while preserving the last successful snapshot; HTTP 429
indicates an actual cooldown or concurrency limit. Failed cloud reports return
HTTP 502 with their redacted report and `operationSucceeded: false`; coverage
warnings alone do not turn a successful operation into a failure.
Cloud callbacks are allowlisted provider/operation pairs and their reports pass
through `ReportSecurity` before being returned. A policy callback supplies only a
read-only view; no editor writes configuration or host state.

The web interface provides English/Spanish, light/dark themes, keyboard navigation
and Ctrl+K global search, findings filters, process sorting and port evidence,
services, uploaded or historical drift baselines, stateless fleet comparison, SQLite trends and a snapshot
and boot timeline, configured cloud queries, a policy preview editor, and read-only settings.
Unavailable optional integrations are described explicitly. The strict policy YAML editor evaluates drafts through the shared policy engine
and downloads validated YAML without applying it or persisting it in history or
browser storage. Native event-log collection and applying a policy remain CLI
workflows. The observed timeline uses the shared evidence timeline builder for
boot, snapshot, failed-service observations, and baseline drift. Redacted drift
coverage limitations are shown alongside the result.

The saved-evidence workspace uses authenticated `POST /api/analyze`, with a
2 MiB total JSON bound and exact, case-sensitive request fields:

```json
{"snapshot": {"...": "complete saved snapshot"}, "operation": "inspect"}
{"snapshot": {"...": "complete saved snapshot"}, "operation": "triage", "scenario": "high-cpu"}
{"snapshot": {"...": "complete saved snapshot"}, "operation": "ioc", "indicators": {"format": "csv", "text": "type,value\nprocess,worker\n"}}
{"snapshot": {"...": "complete saved snapshot"}, "operation": "timeline", "baseline": {"...": "optional complete earlier snapshot"}}
```

Every snapshot passes `Reporter.ParseSnapshot`. Inspection returns a flat redacted
Snapshot; the other operations return a redacted AnalysisReport. Triage scenarios
are `high-cpu`, `disk-full`, and `port-exposed`; indicator formats are `csv` and
`stix`, with at most 128 KiB of UTF-8 indicator text. Import warnings remain in the
IoC report. Offline comparison never reads executable hashes, paths, native logs,
DNS, or remote feeds. Unknown, duplicate, and operation-incompatible fields are
rejected. At most two saved-analysis/export requests run concurrently; additional
requests return HTTP 429. These operations have no collection cooldown, invoke no host collectors,
and never overwrite cached live evidence or write uploaded snapshots to history.

Authenticated `POST /api/report` accepts exactly `snapshot` and `format` under
the same 2 MiB request bound. It exports the chosen validated snapshot as a
redacted attachment in `json`, `html`, `pdf`, `sarif`, `junit`, `csv`, `jsonl`, or
`cef` format. JSON remains a flat Snapshot. Existing `GET /api/report` continues
to export current live evidence. Session secrets observed in supplied snapshot
text or analysis results are removed before publication and export.

Reports download as redacted JSON, SARIF, HTML, or an actual PDF. The print view
supports the browser's PDF workflow. Bundle downloads use `CustodyBundle`,
contain SHA-256 entry hashes, and return an authenticated archive digest; the
browser verifies that digest before saving the ZIP. The separate checksum button
downloads the matching detached `.sha256` file for that ZIP. The CLI bundle verifier checks downloaded artifacts. Unsigned checksums
provide integrity, not signer authentication.

MCP supports newline-delimited JSON-RPC over stdio with
`McpServer.RunAsync(readLatest, cancellationToken)` and the same handler over
session-authenticated HTTP POST `/mcp`. Supported methods are `initialize`,
`ping`, `tools/list`, and `tools/call`; only `opscope_snapshot` and
`opscope_findings` are listed, both with empty argument schemas. No arbitrary
file, command, or collection tool is exposed. The stdio host caches its first
snapshot and writes protocol responses only to stdout.

Run verification with:

```sh
dotnet run --project tests/Opscope.ApiTests
npm ci --prefix tests/Opscope.ApiTests
# If Chromium is not installed, run: npx --prefix tests/Opscope.ApiTests playwright install chromium
npm test --prefix tests/Opscope.ApiTests
```

The browser suite launches the isolated fixture server, checks keyboard and
privacy behavior, full-view response races, drift and downloads, both themes
with axe WCAG A/AA rules, mobile overflow, and local-only requests. It writes
screenshots and accessibility results to ignored `test-results/`. Set `DOTNET_BIN`
and `CHROMIUM_PATH` when using nonstandard executable locations.

Fleet comparison accepts 2–100 snapshot files with a combined request limit of
2 MiB. Each snapshot passes the shared validator before the shared fleet analyzer
calculates latest observations, medians, and outliers. Distinct original host
identities or distinct local pseudonyms are required; generic redacted host names
cannot establish whether observations came from separate hosts. Responses always
replace host identities with indexed redacted labels. Uploads and fleet results
are processed only in this loopback session and never enter history or a cloud
service. The optional native desktop shell remains an alternative presentation
choice; the embedded local web interface is the implemented presentation.
