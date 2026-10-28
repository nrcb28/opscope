# Local interface and read-only integrations

`LocalServer.RunAsync(new ServerOptions(), cancellationToken)` runs Kestrel only on
`127.0.0.1`, with an OS-assigned port by default. The CLI's `serve` command uses
this entry point. There is no remote listener, shell endpoint, host modification,
telemetry, notification, or credential-entry flow.

In default local mode the bootstrap URL contains a fresh 256-bit session token
in its fragment. The browser removes that fragment immediately and keeps the
token only in memory. Reload by reopening the bootstrap URL. Every evidence
endpoint, including Prometheus `/metrics`, SSE `/api/events`, and JSON-RPC `/mcp`,
requires the `X-Opscope-Token` header. Exact Host, Origin, referrer, and Fetch
Metadata checks also apply to static resources. There is no CORS grant.

Explicit proxy mode sets `ServerOptions.PublicOrigin` to one canonical HTTPS
origin and `ProxyToken` to a separately provisioned 64-hex-character upstream
secret. Both must be valid before collection or history initialization. The CLI
uses `--public-origin` and `--proxy-token-env`; only the environment variable's
name appears in arguments. Kestrel still accepts only loopback peers. An
authenticated same-host proxy protects every route, overwrites the upstream
header and strips browser authorization/cookies. The public bootstrap URL has
no fragment. Forwarded headers do not alter the configured Host/origin checks.
The secret is excluded from options JSON and `ToString()` and never returned
to the browser. [Remote hosting](../../docs/remote-hosting.md) provides the
HTTPS/authentication template and an SSH-tunnel alternative.

Protected `GET /api/session` returns only
`{ "authenticationMode": "local" | "proxy", "authenticated": true, "readOnly": true }`.
Without a local fragment, the browser trusts proxy mode only after this request
succeeds. Proxy browser requests, including SSE, use same-origin credentials;
the proxy injects the upstream header. Local browser requests retain their
in-memory header and omit browser credentials. Neither mode returns cloud or
browser user identities. All operators admitted to one instance share its
configured evidence and cloud scopes.

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
indicates an actual cooldown or concurrency limit, with `Retry-After` where supplied.
Cloud responses preserve their redacted report, `operationSucceeded` and coverage.
Missing setup, denied provider access, quotas and timeouts have distinct statuses
described below. Provider denial remains separate from Opscope session
authorization. Cloud callbacks are allowlisted provider/operation pairs and their
reports pass through `ReportSecurity` before being returned. A policy callback
supplies only a read-only view; no editor writes configuration or host state.

## Cloud catalog, fixed scopes and report cache

`GET /api/cloud/catalog` returns version 2 of the closed catalog of eleven
infrastructure providers and a separate Kubernetes cluster adapter:
`providers[]` contain an `id`, display name, category, adapter version, anonymous
configured `scopes[]` and actually supported `operations[]`. Operations identify
read-only status, experimental coverage, resource types, required permissions,
minimum freshness and whether an action is configured. `actions[]` supplies exact
`actionKey`, `providerId`, `scopeAlias` and `operation` values that the UI may call.
The catalog does not query credentials, expand scopes or contact providers.

`GET /api/cloud/coverage` returns schema version 1 and the last observed status of
each configured action: initially `not-requested`, then successful/partial, failed
or timed out. This observation does not certify all services in an account.
`GET /api/capabilities` remains compatible and includes the configured action keys.

`GET /api/cloud/connections` returns version 1 of the guided local setup view for
the twelve sources. It makes no provider requests, runs no process and performs
no login (`remoteRequestsMade=false`, `authenticationActionsAvailable=false`).
Each provider has independent `scopeStatus`, `credentialStatus`, `toolStatus` and
`accessStatus` fields. A present environment credential or available trusted CLI
does not prove authentication. CLI sessions, ADC and workload identities remain
`external-unverified`; a configured read records a separate access observation.
The historical read status includes its action key and observation time; it
does not establish current account-wide access.

The view includes fixed official signup/console/documentation links, host-side
command templates, required scope fields and safe diagnostic/remediation text.
It returns no credential values, tool paths or account identities. Its test
actions refer only to callbacks already configured in the catalog, preferring
inventory, health, networks, then metrics for each alias. The browser cannot
submit arbitrary scopes, endpoints, credentials or commands. Provider account
creation and authentication remain external setup on the Opscope host; GCP CLI
login and ADC are separate requirements.

`POST /api/cloud/{scopeAlias}/{operation}` accepts no body. The alias is either a
configured provider ID or an anonymous `provider-scope-N`, never a raw remote
account or project. Provider and operation must be in the registry, and the exact
action must already be bound in `ServerOptions.CloudActions`. The server rejects
unknown providers with 404, unsupported operations with **501**
(`OPERATION_UNSUPPORTED`), and supported operations without a configured action
with **409** (`SCOPE_NOT_CONFIGURED`). A completed report has these HTTP statuses:

| Coverage/result | Status |
| --- | --- |
| Required provider setup missing | 409 |
| Provider denied the read | 424 |
| Provider quota limit | 429 |
| Provider read deadline | 504 |
| Unsupported adapter read | 501 |
| Failed or unavailable read | 502 |
| Successful read (including no-data), or useful partial evidence | 200 |

The existing report fields remain at the response root, with additive
`cloudProblem` metadata: `httpStatus`, `code`, fixed `message` and `remediation`,
`nextStep`, and a known `providerId` where available. Read the report's coverage
and success flag even on HTTP 200; partial evidence is not complete coverage.
Provider responses do not invalidate the Opscope session. Its own missing/invalid
upstream header returns 401; source/Host checks return 403.

An exception before a report is available returns a sanitized 502 error; the
server-side sixty-second cancellation deadline returns 504. The existing
gate/cooldown returns 429. These responses remain distinct from a successful
empty inventory.

Completed report responses are cached **after redaction and session-token
scrubbing** in this server session only. The cache holds at most 32 entries of
512 KiB each (16 MiB payload ceiling); larger reports are returned but not cached.
TTL is thirty seconds for HTTP 200 ordinary reads, sixty seconds for HTTP 200
`metrics` reads, and fifteen seconds for non-200 report responses. A cache hit
returns the original status/report and observation time; it does not imply a new
provider query. `X-Opscope-Cache: hit|miss` identifies reuse, and hits include
`X-Opscope-Cache-Age-Seconds`. Timeout/exception responses are not report-cache
entries. The cache is not written to SQLite or browser storage.

## Aggregate host metrics and SSE

One lightweight sampler per server observes aggregate host CPU and RAM every
five seconds independently of full snapshots. It does not enumerate processes,
services, disks or network interfaces. CPU uses deltas of cumulative counters;
the first CPU value and unavailable/reset readings are `null`, not zero.
Linux `/proc` and Windows native counters are supported; unsupported platforms
remain explicitly unavailable. The session retains at most 720 identity-free
observations in RAM, with sequence and elapsed-monotonic time ordering and a
`clockAdjusted` marker for UTC corrections.

`GET /api/metrics/capabilities` describes schema version, source, interval,
capacity, supported windows and memory-only persistence.
`GET /api/metrics/history` accepts only `window`, `limit`, and `afterSequence`:

```text
/api/metrics/history?window=15m&limit=720&afterSequence=0
```

Windows are `5m`, `15m`, `30m` or `1h` (default); `limit` is 1–720 (default 720),
and `afterSequence` is a nonnegative integer (default 0). Unknown or repeated
fields and invalid bounds return 400. Results contain only retained observations,
with nullable CPU/RAM values, timestamps, source and coverage. Both routes use
the same session/header checks as evidence endpoints. `/metrics` remains the
existing Prometheus snapshot endpoint, separate from the in-memory series.

The single authenticated `GET /api/events` connection carries these SSE events:

| Event | Meaning |
| --- | --- |
| `snapshot` | Latest redacted full snapshot, preserving the existing contract. |
| `metrics` | Latest identity-free aggregate sample with a monotonic `id`. |
| `metrics-gap` | `{ "droppedSamples": N }` reports skipped metric observations. |
| Comment heartbeat | Keeps idle transport observable without fabricating a sample. |

Reconnect with `Last-Event-ID` in a header, not a token/sequence URL parameter.
It must be one nonnegative integer no greater than the current sample sequence;
invalid values return 400. A reconnect continues with the latest observation and
explicit gap count; it does not promise an unlimited replay. Use bounded history
for retained points. At most four streams run concurrently; each stream reconnects
after two minutes, and **every write/flush has a ten-second cancellation deadline**.
Slow readers receive only the latest available aggregate rather than building an
unbounded pending queue. The local client keeps its session token in the fetch
header; a proxy client uses same-origin authentication and receives no upstream
token. Both use one stream for full snapshots and lightweight metrics.

The web interface provides English/Spanish, light/dark themes, keyboard navigation
and Ctrl+K global search, findings filters, process sorting and port evidence,
services, uploaded or historical drift baselines, stateless fleet comparison, SQLite trends and a snapshot
and boot timeline, configured cloud queries and connection guidance, a policy preview editor, and read-only settings.
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
dotnet run --project tests/Opscope.CloudConnectionTests
dotnet run --project tests/Opscope.RemoteHostingTests
npm ci --prefix tests/Opscope.ApiTests
# If Chromium is not installed, run: npx --prefix tests/Opscope.ApiTests playwright install chromium
npm test --prefix tests/Opscope.ApiTests
```

The browser suite launches the isolated fixture server, checks keyboard and
privacy behavior, full-view response races, drift and downloads, both themes
with axe WCAG A/AA rules, mobile overflow, and same-origin request behavior. It writes
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
