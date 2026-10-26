namespace Opscope.Api;

internal static class OpenApiContract
{
    internal static object Create() => new
    {
        openapi = "3.0.3",
        info = new { title = "Opscope local read-only API", version = "1.0.0", description = "Loopback-only local evidence. Every listed operation requires the session header and exact Host/origin validation. All responses are redacted except an explicit full=true snapshot view." },
        security = new[] { new Dictionary<string, string[]> { ["sessionToken"] = [] } },
        components = new { securitySchemes = new { sessionToken = new { type = "apiKey", @in = "header", name = "X-Opscope-Token" } } },
        paths = new Dictionary<string, object>
        {
            ["/api/snapshot"] = new { get = Operation("Latest snapshot", "application/json", parameters: [Parameter("full", "query", false, "boolean", "Explicit session-only full identifiers; defaults to false.")]) },
            ["/api/findings"] = new { get = Operation("Redacted latest findings", "application/json") },
            ["/api/history"] = new { get = Operation("Retained redacted snapshot metadata, newest first", "application/json") },
            ["/api/history/{id}"] = new { get = Operation("Retained redacted snapshot", "application/json", parameters: [Parameter("id", "path", true, "integer", "SQLite snapshot identifier.")]) },
            ["/api/collect"] = new { post = Operation("Collect through the shared read-only collector; no request body", "application/json") },
            ["/api/diff"] = new { post = Operation("Compare a validated baseline with current evidence; redacted result", "application/json", body: JsonBody("A complete Opscope snapshot JSON, bounded to 2 MiB and validated by the shared parser.")) },
            ["/api/analyze"] = new { post = Operation("Stateless saved-snapshot inspection, triage, offline IoC comparison, or timeline; always redacted", "application/json", body: AnalyzeBody()) },
            ["/api/fleet"] = new { post = Operation("Stateless local fleet comparison; redacted indexed host labels and observed outliers", "application/json", body: JsonBody("An object with only snapshots: an array of 2–100 validated snapshots. Total request limit 2 MiB. Distinct host identities are required; generic redacted host labels cannot establish identity. No uploads or results are stored.")) },
            ["/api/settings"] = new { get = Operation("Read-only configuration without tokens or host paths", "application/json") },
            ["/api/capabilities"] = new { get = Operation("Configured cloud operation keys and policy-view availability", "application/json") },
            ["/api/cloud/catalog"] = new { get = Operation("Version 2 closed provider catalog with implemented read capabilities and anonymous configured action aliases; no remote credential discovery", "application/json") },
            ["/api/cloud/coverage"] = new { get = Operation("Per-action last execution state and observation timestamp; not-requested is distinct from succeeded or partial", "application/json") },
            ["/api/metrics/capabilities"] = new { get = Operation("Lightweight aggregate host metrics support, sampling interval, and memory-only retention bounds", "application/json") },
            ["/api/metrics/history"] = new { get = Operation("At most 720 aggregate samples from the in-memory host ring; unknown or repeated query fields rejected", "application/json", parameters: [Parameter("window", "query", false, "string", "5m, 15m, 30m, or 1h (default); only available observations are returned."), Parameter("limit", "query", false, "integer", "1–720; default 720."), Parameter("afterSequence", "query", false, "integer", "Nonnegative monotonic sequence cursor.")]) },
            ["/api/policy"] = new { get = Operation("Configured read-only policy view; 404 when unavailable", "application/json") },
            ["/api/policy/preview"] = new { post = Operation("Validate and evaluate in-memory YAML against current evidence; no policy or host writes", "application/json", body: JsonBody("An object with only a text string containing at most 128 KiB of strict policy YAML. The JSON body is capped at 512 KiB.")) },
            ["/api/timeline"] = new { get = Operation("Redacted observed boot, snapshot, failed-service observations, and retained-baseline drift; no invented event times", "application/json") },
            ["/api/cloud/{provider}/{operation}"] = new { post = Operation("Run an explicitly configured read-only cloud query; no request body", "application/json", parameters: [Parameter("provider", "path", true, "string", "Configured provider."), Parameter("operation", "path", true, "string", "Configured operation; arbitrary commands and options are not accepted.")]) },
            ["/api/bundle"] = new { get = Operation("Redacted custody ZIP; X-Checksum-Sha256 contains the archive digest", "application/zip") },
            ["/api/report"] = new
            {
                get = Operation("Redacted HTML, PDF, or SARIF handoff report", "text/html", parameters: [Parameter("format", "query", false, "string", "html (default), pdf, or sarif.")]),
                post = Operation("Export the supplied saved snapshot as a redacted attachment; no collection or persistence", "application/octet-stream", body: new
                {
                    required = true,
                    description = "Strict UTF-8 JSON, at most 2 MiB and a ten-second upload deadline. Unknown and duplicate fields are rejected. JSON output is a flat redacted Snapshot.",
                    content = new Dictionary<string, object>
                    {
                        ["application/json"] = new { schema = ObjectSchema(["snapshot", "format"], new()
                        {
                            ["snapshot"] = SnapshotSchema(),
                            ["format"] = new { type = "string", @enum = new[] { "json", "html", "pdf", "sarif", "junit", "csv", "jsonl", "cef" } }
                        }) }
                    }
                })
            },
            ["/metrics"] = new { get = Operation("Prometheus gauges from cached evidence; no identity labels", "text/plain") },
            ["/api/events"] = new { get = Operation("Single authenticated SSE stream: redacted snapshot and aggregate metrics events, monotonic metric IDs, metrics-gap dropped-sample notices and comment heartbeats. At most four streams, two-minute reconnect and ten-second write deadlines; optional Last-Event-ID cursor", "text/event-stream") },
            ["/mcp"] = new { post = Operation("Read-only MCP JSON-RPC; initialize, ping, tools/list, tools/call", "application/json", body: JsonBody("One JSON-RPC 2.0 object bounded to 64 KiB. Only opscope_snapshot and opscope_findings accept tool calls, with empty arguments.")) },
            ["/api/openapi.json"] = new { get = Operation("This authenticated OpenAPI contract", "application/json") }
        }
    };
    private static object SnapshotSchema() => new { type = "object", description = "Complete Opscope snapshot validated by Reporter.ParseSnapshot. No host paths, URLs, commands, or native-evidence requests are accepted as alternatives to snapshot data." };
    private static object ObjectSchema(string[] required, Dictionary<string, object> properties) => new { type = "object", additionalProperties = false, required, properties };
    private static object AnalyzeBody()
    {
        object Variant(string operation, params (string Name, object Schema, bool Required)[] fields)
        {
            var properties = new Dictionary<string, object> { ["snapshot"] = SnapshotSchema(), ["operation"] = new { type = "string", @enum = new[] { operation } } };
            foreach (var field in fields) properties[field.Name] = field.Schema;
            return ObjectSchema(new[] { "snapshot", "operation" }.Concat(fields.Where(field => field.Required).Select(field => field.Name)).ToArray(), properties);
        }
        var indicators = ObjectSchema(["format", "text"], new()
        {
            ["format"] = new { type = "string", @enum = new[] { "csv", "stix" } },
            ["text"] = new { type = "string", description = "At most 128 KiB of UTF-8 indicator text; only recorded observables are compared. No live executable hashes, file scans, DNS queries, or remote feeds." }
        });
        return new
        {
            required = true,
            description = "Strict UTF-8 JSON with a 2 MiB total limit and ten-second upload deadline. Unknown, duplicate, and operation-incompatible fields are rejected. Inspect returns a flat redacted Snapshot; all other operations return a redacted AnalysisReport. Uploads and results never overwrite live evidence or enter history.",
            content = new Dictionary<string, object>
            {
                ["application/json"] = new { schema = new { oneOf = new[]
                {
                    Variant("inspect"),
                    Variant("triage", ("scenario", new { type = "string", @enum = new[] { "high-cpu", "disk-full", "port-exposed" } }, true)),
                    Variant("ioc", ("indicators", indicators, true)),
                    Variant("timeline", ("baseline", SnapshotSchema(), false))
                } } }
            }
        };
    }
    private static object Parameter(string name, string location, bool required, string type, string description) => new { name, @in = location, required, description, schema = new { type } };
    private static object JsonBody(string description) => new { required = true, description, content = new Dictionary<string, object> { ["application/json"] = new { schema = new { type = "object", additionalProperties = true } } } };
    private static object Operation(string summary, string contentType, object[]? parameters = null, object? body = null)
    {
        var operation = new Dictionary<string, object> { ["summary"] = summary, ["responses"] = new Dictionary<string, object>
        {
            ["200"] = new { description = "Authenticated evidence response", content = new Dictionary<string, object> { [contentType] = new { } } },
            ["400"] = new { description = "Invalid or oversized input" },
            ["401"] = new { description = "Missing or invalid session token" },
            ["403"] = new { description = "Invalid Host, Origin, referrer, or Fetch Metadata" },
            ["404"] = new { description = "Unknown record or unconfigured capability" },
            ["408"] = new { description = "Request upload deadline exceeded" },
            ["429"] = new { description = "Request, stream, or collection limit reached" },
            ["502"] = new { description = "Cloud operation failed; the redacted AnalysisReport retains failure and coverage details" },
            ["504"] = new { description = "Cloud operation exceeded its deadline" },
            ["409"] = new { description = "Known cloud operation has no configured scope in this session" },
            ["501"] = new { description = "Known provider does not support the requested operation" },
            ["503"] = new { description = "Evidence is unavailable" }
        } };
        if (parameters is not null) operation["parameters"] = parameters;
        if (body is not null) operation["requestBody"] = body;
        return operation;
    }
}
