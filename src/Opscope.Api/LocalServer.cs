using System.Globalization;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;
using Opscope.Evidence;

namespace Opscope.Api;

public sealed record ServerOptions
{
    public int Port { get; init; }
    public string? HistoryPath { get; init; }
    public int RetentionCount { get; init; } = 100;
    public int RetentionDays { get; init; } = 30;
    public TimeSpan RefreshInterval { get; init; } = TimeSpan.FromSeconds(30);
    public CollectorOptions CollectorOptions { get; init; } = new();
    public Func<CancellationToken, Task<Snapshot>>? CollectAsync { get; init; }
    /// <summary>Receives the secret bootstrap URL once. Do not log or persist it elsewhere.</summary>
    public Action<Uri>? OnStarted { get; init; }
    /// <summary>Allowlisted provider/operation callbacks. Results must already be redacted by the shared cloud layer.</summary>
    public IReadOnlyDictionary<string, Func<CancellationToken, Task<AnalysisReport>>>? CloudActions { get; init; }
    /// <summary>Optional read-only policy description, without secret values or host paths.</summary>
    public Func<object>? PolicyView { get; init; }
}

public static class LocalServer
{
    public static async Task RunAsync(ServerOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Port is < 0 or > 65535 || options.RefreshInterval < TimeSpan.FromSeconds(5) || options.RefreshInterval > TimeSpan.FromDays(1))
            throw new ArgumentOutOfRangeException(nameof(options), "Port must be 0–65535 and refresh interval 5 seconds–1 day.");
        var historyPath = options.HistoryPath ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Opscope", "history.sqlite");
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        using var store = new HistoryStore(historyPath, options.RetentionCount, options.RetentionDays);
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var state = new EvidenceState(options, store, token);
        await state.RefreshAsync(lifetime.Token, force: true);
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [], ApplicationName = typeof(LocalServer).Assembly.FullName });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(server =>
        {
            server.AddServerHeader = false;
            server.Limits.MaxRequestBodySize = HistoryStore.MaximumSnapshotBytes;
            server.Limits.MaxRequestHeadersTotalSize = 16 * 1024;
            server.Limits.MaxRequestLineSize = 4096;
            server.Limits.MaxConcurrentConnections = 32;
            server.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
            server.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(30);
            server.Listen(IPAddress.Loopback, options.Port);
        });
        await using var app = builder.Build();
        string? origin = null;
        var requests = new RequestWindow();
        app.Use(async (context, next) =>
        {
            context.Response.Headers["Content-Security-Policy"] = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.Headers["X-Frame-Options"] = "DENY";
            context.Response.Headers["Cross-Origin-Resource-Policy"] = "same-origin";
            context.Response.Headers["Cross-Origin-Opener-Policy"] = "same-origin";
            context.Response.Headers["Cache-Control"] = "no-store";
            if (origin is null || context.Connection.RemoteIpAddress is not { } remote || !IPAddress.IsLoopback(remote) ||
                !string.Equals(context.Request.Host.Value, origin[7..], StringComparison.Ordinal) ||
                !ValidSource(context.Request, origin))
            { context.Response.StatusCode = 403; return; }
            var shell = context.Request.Method == "GET" && context.Request.Path.Value is "/" or "/app.js" or "/app.css";
            if (!shell && !ValidToken(context.Request.Headers["X-Opscope-Token"].ToString(), token))
            { context.Response.StatusCode = 401; return; }
            if (!requests.Allow()) { context.Response.StatusCode = 429; context.Response.Headers.RetryAfter = "1"; return; }
            try { await next(context); }
            catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested || lifetime.IsCancellationRequested) { }
            catch (Exception error) when (error is InvalidDataException or JsonException or BadHttpRequestException or ArgumentException)
            { if (!context.Response.HasStarted) { context.Response.StatusCode = 400; await context.Response.WriteAsJsonAsync(new { error = "Invalid or oversized request." }, context.RequestAborted); } }
            catch (Exception)
            { if (!context.Response.HasStarted) { context.Response.StatusCode = 500; await context.Response.WriteAsJsonAsync(new { error = "The local operation could not complete. No host changes were made." }, context.RequestAborted); } }
        });
        app.MapGet("/", () => Asset("index.html", "text/html; charset=utf-8"));
        app.MapGet("/app.js", () => Asset("app.js", "text/javascript; charset=utf-8"));
        app.MapGet("/app.css", () => Asset("app.css", "text/css; charset=utf-8"));
        app.MapGet("/api/snapshot", (HttpContext context) => state.Latest is { } snapshot
            ? Results.Text(Reporter.ToJson(snapshot, redact: context.Request.Query["full"] != "true"), "application/json") : Results.StatusCode(503));
        app.MapGet("/api/findings", () => state.Latest is { } snapshot ? Results.Json(Reporter.RedactForOutput(snapshot).Findings) : Results.StatusCode(503));
        app.MapPost("/api/collect", async (HttpContext context) =>
        {
            if (context.Request.ContentLength is > 0 || context.Request.Headers.ContainsKey("Transfer-Encoding")) return Results.BadRequest(new { error = "Collection takes no request body." });
            if (!await state.RefreshAsync(context.RequestAborted)) return Results.StatusCode(429);
            return state.Latest is { } snapshot ? Results.Text(Reporter.ToJson(snapshot, true), "application/json") : Results.StatusCode(503);
        });
        app.MapGet("/api/history", () => Results.Json(store.List()));
        app.MapGet("/api/history/{id:long}", (long id) => store.Get(id) is { } snapshot ? Results.Text(Reporter.ToJson(snapshot, true), "application/json") : Results.NotFound());
        app.MapPost("/api/diff", async (HttpContext context) =>
        {
            RequireJson(context);
            var baseline = Reporter.ParseSnapshot(await ReadBoundedAsync(context.Request.Body, HistoryStore.MaximumSnapshotBytes, context.RequestAborted));
            return state.Latest is { } snapshot
                ? Results.Text(Reporter.ToJson(Reporter.RedactForOutput(DiffEngine.Compare(baseline, snapshot))), "application/json") : Results.StatusCode(503);
        });
        app.MapPost("/api/fleet", async (HttpContext context) =>
        {
            RequireJson(context);
            using var document = JsonDocument.Parse(await ReadBoundedAsync(context.Request.Body, HistoryStore.MaximumSnapshotBytes, context.RequestAborted), new JsonDocumentOptions { MaxDepth = 64 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 1 || !root.TryGetProperty("snapshots", out var array) || array.ValueKind != JsonValueKind.Array || array.GetArrayLength() is < 2 or > 100)
                return Results.BadRequest(new { error = "Fleet comparison requires 2–100 snapshots in a snapshots array." });
            var snapshots = array.EnumerateArray().Select(item => Reporter.ParseSnapshot(item.GetRawText())).ToArray();
            if (snapshots.Any(item => item.Host.Hostname.StartsWith("[redacted-", StringComparison.OrdinalIgnoreCase)))
                return Results.BadRequest(new { error = "Fleet comparison needs distinct host identities; generic redacted host labels cannot establish which observations belong to a host. Use distinct local pseudonyms or original snapshots; results remain redacted." });
            var report = FleetAnalyzer.Compare(snapshots);
            var data = (FleetData)report.Data!;
            report = report with { Data = data with { Hosts = data.Hosts.Select((host, index) => host with { Host = $"[redacted-host-{index + 1}]" }).ToArray() } };
            return Results.Text(ReportSecurity.Serialize(report), "application/json");
        });
        app.MapGet("/api/settings", () => Results.Json(new { readOnly = true, redactedByDefault = true, historyRedacted = true, retentionCount = options.RetentionCount, retentionDays = options.RetentionDays, refreshSeconds = options.RefreshInterval.TotalSeconds, maxUploadBytes = HistoryStore.MaximumSnapshotBytes, telemetry = false, notifications = false, listener = "127.0.0.1", mcpTransport = "authenticated HTTP JSON-RPC at /mcp; stdio through opscope mcp" }));
        app.MapGet("/api/capabilities", () => Results.Json(new { cloud = options.CloudActions?.Keys.Order(StringComparer.Ordinal).ToArray() ?? [], policy = options.PolicyView is not null }));
        app.MapGet("/api/policy", () => options.PolicyView is null ? Results.NotFound() : Results.Json(options.PolicyView()));
        app.MapPost("/api/policy/preview", async (HttpContext context) =>
        {
            RequireJson(context);
            using var document = JsonDocument.Parse(await ReadBoundedAsync(context.Request.Body, 512 * 1024, context.RequestAborted), new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 1 || !root.TryGetProperty("text", out var text) || text.ValueKind != JsonValueKind.String)
                return Results.BadRequest(new { error = "Only a policy text string is accepted." });
            if (state.Latest is not { } snapshot) return Results.StatusCode(503);
            try
            {
                var policy = PolicyEngine.Parse(text.GetString()!);
                return Results.Text(ReportSecurity.Serialize(policy.Evaluate(snapshot)), "application/json");
            }
            catch (InvalidDataException error)
            {
                var detail = Reporter.RedactEvidenceText(error.Message);
                return Results.BadRequest(new { error = "Policy validation failed.", detail = detail.Length > 4096 ? detail[..4096] : detail });
            }
        });
        app.MapGet("/api/timeline", () =>
        {
            if (state.Latest is not { } snapshot) return Results.StatusCode(503);
            var entry = store.List().LastOrDefault(item => item.CollectedAtUtc < snapshot.CollectedAtUtc);
            var baseline = entry is null ? null : store.Get(entry.Id);
            var redacted = Reporter.RedactForOutput(snapshot);
            return Results.Text(ReportSecurity.Serialize(TimelineBuilder.Build(redacted, baseline)), "application/json");
        });
        app.MapPost("/api/cloud/{provider}/{operation}", async (string provider, string operation, HttpContext context) =>
        {
            if (context.Request.ContentLength is > 0 || context.Request.Headers.ContainsKey("Transfer-Encoding")) return Results.BadRequest();
            if (options.CloudActions is null || !options.CloudActions.TryGetValue($"{provider}/{operation}", out var action)) return Results.NotFound();
            if (!await state.TryEnterActionAsync(context.RequestAborted)) return Results.StatusCode(429);
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
                timeout.CancelAfter(TimeSpan.FromSeconds(60));
                return Results.Text(ReportSecurity.Serialize(await action(timeout.Token)), "application/json");
            }
            finally { state.ExitAction(); }
        });
        app.MapGet("/api/bundle", async (HttpContext context) =>
        {
            if (state.Latest is not { } snapshot) return Results.StatusCode(503);
            var temporary = Path.Combine(Path.GetTempPath(), $"opscope-ui-{Guid.NewGuid():N}.zip");
            try
            {
                await CustodyBundle.WriteAsync(temporary, snapshot, cancellationToken: context.RequestAborted);
                var bytes = await File.ReadAllBytesAsync(temporary, context.RequestAborted);
                context.Response.Headers["X-Checksum-Sha256"] = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
                return Results.File(bytes, "application/zip", "opscope-redacted-bundle.zip");
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); if (File.Exists(temporary + ".sha256")) File.Delete(temporary + ".sha256"); }
        });
        app.MapGet("/api/report", (HttpContext context) =>
        {
            if (state.Latest is not { } snapshot) return Results.StatusCode(503);
            var format = context.Request.Query["format"].ToString();
            if (format is "pdf") return Results.File(Encoding.Latin1.GetBytes(ReportExporter.Export(snapshot, "pdf")), "application/pdf", "opscope-redacted-report.pdf");
            if (format is "sarif") return Results.File(Encoding.UTF8.GetBytes(ReportExporter.Export(snapshot, "sarif")), "application/sarif+json", "opscope-findings.sarif");
            if (format is not ("" or "html")) return Results.BadRequest();
            return Results.Text(BuildReport(snapshot), "text/html; charset=utf-8");
        });
        app.MapGet("/metrics", () => state.Latest is { } snapshot ? Results.Text(BuildMetrics(snapshot), "text/plain; version=0.0.4; charset=utf-8") : Results.StatusCode(503));
        app.MapPost("/mcp", async (HttpContext context) =>
        {
            RequireJson(context);
            var request = await ReadBoundedAsync(context.Request.Body, 64 * 1024, context.RequestAborted);
            var response = await McpServer.HandleAsync(request, _ => Task.FromResult(state.Latest ?? throw new InvalidOperationException("No evidence is available.")), context.RequestAborted);
            return response is null ? Results.NoContent() : Results.Text(response, "application/json");
        });
        var streams = 0;
        app.MapGet("/api/events", async (HttpContext context) =>
        {
            if (Interlocked.Increment(ref streams) > 4) { Interlocked.Decrement(ref streams); context.Response.StatusCode = 429; return; }
            try
            {
                context.Response.ContentType = "text/event-stream";
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted, lifetime.Token);
                timeout.CancelAfter(TimeSpan.FromMinutes(2));
                DateTimeOffset? previous = null;
                using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
                do
                {
                    var snapshot = state.Latest;
                    if (snapshot is not null && previous != snapshot.CollectedAtUtc)
                    {
                        previous = snapshot.CollectedAtUtc;
                        var json = JsonSerializer.Serialize(Reporter.RedactForOutput(snapshot), JsonOptions);
                        await context.Response.WriteAsync($"event: snapshot\ndata: {json}\n\n", timeout.Token);
                    }
                    else await context.Response.WriteAsync(": heartbeat\n\n", timeout.Token);
                    await context.Response.Body.FlushAsync(timeout.Token);
                } while (await timer.WaitForNextTickAsync(timeout.Token));
            }
            catch (OperationCanceledException) { }
            finally { Interlocked.Decrement(ref streams); }
        });
        app.MapGet("/api/openapi.json", () => Results.Json(OpenApiContract.Create()));
        await app.StartAsync(cancellationToken);
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        origin = address.TrimEnd('/');
        var bootstrap = new Uri($"{origin}/#token={token}");
        if (options.OnStarted is { } started) started(bootstrap);
        else Console.WriteLine(bootstrap.AbsoluteUri);
        var refresh = RefreshLoopAsync(state, options.RefreshInterval, lifetime.Token);
        try { await app.WaitForShutdownAsync(cancellationToken); }
        finally
        {
            await lifetime.CancelAsync();
            try { await refresh; } catch (OperationCanceledException) { }
            await app.StopAsync(CancellationToken.None);
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { MaxDepth = 64 };
    private static IResult Asset(string name, string contentType)
    {
        using var stream = typeof(LocalServer).Assembly.GetManifestResourceStream($"Opscope.Api.Web.{name}")!;
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return Results.Text(reader.ReadToEnd(), contentType);
    }
    private static bool ValidToken(string candidate, string token) => candidate.Length == token.Length && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(candidate), Encoding.ASCII.GetBytes(token));
    private static bool ValidSource(HttpRequest request, string origin)
    {
        if (request.Headers.TryGetValue("Origin", out var supplied) && !string.Equals(supplied.ToString(), origin, StringComparison.Ordinal)) return false;
        if (request.Headers.TryGetValue("Referer", out var referer) && (!Uri.TryCreate(referer.ToString(), UriKind.Absolute, out var uri) || uri.GetLeftPart(UriPartial.Authority) != origin || !string.IsNullOrEmpty(uri.UserInfo))) return false;
        if (request.Headers.TryGetValue("Sec-Fetch-Site", out var site) && site.ToString() is not ("same-origin" or "none")) return false;
        return true;
    }
    private static void RequireJson(HttpContext context)
    {
        if (!context.Request.HasJsonContentType()) throw new InvalidDataException("JSON content type is required.");
    }
    private static async Task<string> ReadBoundedAsync(Stream input, int maxBytes, CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken);
            if (read == 0) break;
            if (output.Length + read > maxBytes) throw new InvalidDataException("Request is too large.");
            output.Write(buffer, 0, read);
        }
        return new UTF8Encoding(false, true).GetString(output.ToArray());
    }
    private static async Task RefreshLoopAsync(EvidenceState state, TimeSpan interval, CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(interval);
        while (await timer.WaitForNextTickAsync(cancellationToken)) await state.RefreshAsync(cancellationToken);
    }
    private static string BuildMetrics(Snapshot snapshot)
    {
        var values = new (string Name, string Help, double Value)[]
        {
            ("opscope_cpu_used_percent", "CPU utilization percent", snapshot.CpuUsedPercent),
            ("opscope_memory_used_percent", "Memory utilization percent", snapshot.Memory.UsedPercent),
            ("opscope_listener_count", "Observed listening socket count", snapshot.Listeners.Count),
            ("opscope_findings_count", "Observed findings count", snapshot.Findings.Count),
            ("opscope_snapshot_timestamp_seconds", "Snapshot Unix timestamp in seconds", snapshot.CollectedAtUtc.ToUnixTimeSeconds()),
            ("opscope_collection_duration_seconds", "Evidence collection duration", snapshot.CollectionDuration.TotalSeconds)
        };
        return string.Join("", values.Select(metric => $"# HELP {metric.Name} {metric.Help}\n# TYPE {metric.Name} gauge\n{metric.Name} {metric.Value.ToString("R", CultureInfo.InvariantCulture)}\n"));
    }
    private static string BuildReport(Snapshot snapshot)
    {
        var view = Reporter.RedactForOutput(snapshot);
        static string E(object? value) => WebUtility.HtmlEncode(Convert.ToString(value, CultureInfo.InvariantCulture)) ?? string.Empty;
        var findings = string.Join("", view.Findings.OrderByDescending(f => f.Severity).Select(f => $"<li><h3>{E(f.Severity)} · {E(f.Title)}</h3><p>{E(f.Detail)}</p><p>{E(f.Recommendation)}</p></li>"));
        return $"<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Opscope handoff report</title><body><main><h1>Opscope · Read-only evidence</h1><p>Redacted report · {E(view.CollectedAtUtc.ToString("u"))}</p><p>Use your browser Print → Save as PDF to export this self-contained evidence view.</p><h2>Summary</h2><p>CPU {E(view.CpuUsedPercent)}% · Memory {E(view.Memory.UsedPercent)}% · Listeners {view.Listeners.Count}</p><h2>Prioritized findings</h2><ol>{findings}</ol><h2>Collection warnings</h2><ul>{string.Join("", view.CollectionWarnings.Select(w => $"<li>{E(w)}</li>"))}</ul><h2>Redacted evidence</h2><pre>{E(Reporter.ToJson(view))}</pre></main></body></html>";
    }
    private sealed class EvidenceState(ServerOptions options, HistoryStore store, string sessionToken) : IDisposable
    {
        private readonly SemaphoreSlim collector = new(1, 1);
        private long lastStart;
        private Snapshot? latest;
        public Snapshot? Latest => Volatile.Read(ref latest);
        public async Task<bool> TryEnterActionAsync(CancellationToken cancellationToken)
        {
            if (!await collector.WaitAsync(0, cancellationToken)) return false;
            var now = Environment.TickCount64;
            if (now - Interlocked.Read(ref lastStart) < 2000) { collector.Release(); return false; }
            Interlocked.Exchange(ref lastStart, now);
            return true;
        }
        public void ExitAction() => collector.Release();
        public async Task<bool> RefreshAsync(CancellationToken cancellationToken, bool force = false)
        {
            if (force) await collector.WaitAsync(cancellationToken);
            else if (!await TryEnterActionAsync(cancellationToken)) return false;
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(60));
                var snapshot = await (options.CollectAsync?.Invoke(timeout.Token) ?? SystemProbe.CollectAsync(options.CollectorOptions, timeout.Token));
                // A browser launched with the bootstrap URL can expose that URL in its process arguments.
                // Never admit the session secret to either the full in-memory view or persisted evidence.
                var json = Reporter.ToJson(snapshot);
                if (json.Contains(sessionToken, StringComparison.Ordinal))
                    snapshot = Reporter.ParseSnapshot(json.Replace(sessionToken, "[redacted-session-token]", StringComparison.Ordinal));
                store.Add(snapshot);
                Volatile.Write(ref latest, snapshot);
                return true;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception) when (!force) { return false; }
            finally { Interlocked.Exchange(ref lastStart, Environment.TickCount64); collector.Release(); }
        }
        public void Dispose() => collector.Dispose();
    }
    private sealed class RequestWindow
    {
        private readonly object gate = new();
        private long second = Environment.TickCount64 / 1000;
        private int count;
        public bool Allow() { lock (gate) { var now = Environment.TickCount64 / 1000; if (now != second) { second = now; count = 0; } return ++count <= 100; } }
    }
}
