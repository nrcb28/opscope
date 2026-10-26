using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Opscope;
using Opscope.Api;
using Opscope.Cloud;

internal static class Program
{
    private static int assertions;
    private static readonly string Root = Path.Combine(Path.GetTempPath(), "opscope-api-tests-" + Guid.NewGuid().ToString("N"));

    private static async Task<int> Main(string[] args)
    {
        Directory.CreateDirectory(Root);
        try
        {
            if (args is ["--serve"])
            {
                using var shutdown = new CancellationTokenSource();
                Console.CancelKeyPress += (_, eventArgs) => { eventArgs.Cancel = true; shutdown.Cancel(); };
                await LocalServer.RunAsync(new ServerOptions
                {
                    HistoryPath = Path.Combine(Root, "browser.sqlite"),
                    CollectAsync = _ =>
                    {
                        var evidence = Fixture();
                        return Task.FromResult(evidence with
                        {
                            Services = [.. evidence.Services, new ServiceInfo("private-failed.service", "failed", "Fixture failed service", "test")]
                        });
                    },
                    RefreshInterval = TimeSpan.FromSeconds(5),
                    CloudActions = new Dictionary<string, Func<CancellationToken, Task<AnalysisReport>>>
                    {
                        ["azure-scope-1/inventory"] = _ => Task.FromResult(new AnalysisReport("cloud/azure/inventory", DateTimeOffset.UtcNow, [], new { resourceCount = 3 })),
                        ["aws-scope-20/health"] = _ => Task.FromResult(new AnalysisReport("cloud/aws/health", DateTimeOffset.UtcNow, [], new { resourceCount = 5 })),
                        ["gcp-scope-1/metrics"] = _ => Task.FromResult(CloudMetricFixture("gcp")),
                        ["hetzner-scope-1/metrics"] = _ => Task.FromResult(CloudMetricFixture("hetzner"))
                    }
                }, shutdown.Token);
                return 0;
            }
            TestHistory();
            TestHistoryByteBudget();
            await TestMcpAsync();
            await TestServerAsync();
            Console.WriteLine($"PASS: {assertions} API, storage, and MCP security assertions.");
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error);
            return 1;
        }
        finally { try { Directory.Delete(Root, recursive: true); } catch (IOException) { } }
    }

    private static Snapshot Fixture() => new(
        DateTimeOffset.UtcNow,
        new HostInfo("api-private-host", "Test OS", "Linux", "X64", ".NET 8", "test-kernel", DateTimeOffset.UtcNow.AddDays(-2), TimeSpan.FromDays(2), false, 4, "private-user"),
        17.5,
        new MemoryInfo(8_000_000_000, 6_000_000_000, 2_000_000_000, 25, "test"),
        [new DiskInfo("disk", "/private-volume", "ext4", 10_000, 5000, 50, true)],
        [new NetworkAdapter("eth-test", "Test adapter", "Ethernet", "Up", ["192.0.2.35"], 1000000)],
        [new ProcessInfo(123, "worker", "private-user", 1024 * 1024, 1, TimeSpan.FromSeconds(4), "worker --password=private-argument", false)],
        [new ListenerInfo("TCP", "192.0.2.35:8443", "worker", "test")],
        [new ServiceInfo("worker.service", "running", "Fixture service", "test")],
        new SecurityPosture([], false, false, 1),
        new ToolingPosture([]),
        [new Finding(FindingSeverity.Warning, "TEST_WARNING", "Test evidence", "Check api-private-host and 192.0.2.35", "Review the evidence.")],
        [], TimeSpan.FromMilliseconds(150));

    private static AnalysisReport CloudMetricFixture(string provider)
    {
        var now = DateTimeOffset.UtcNow;
        object series = provider == "gcp"
            ? new GcpCpuSeries("[redacted-account]", "[redacted-id]", "[redacted-region]", "cpu_utilization", "percent", "ALIGN_MEAN", 60, "Google Cloud Monitoring",
                [new GcpMetricPoint(now.AddMinutes(-2), 37.5), new GcpMetricPoint(now.AddMinutes(-1), 42)])
            : new { resourceId = "[redacted-id]", metric = "cpu", unit = "percent", aggregation = "provider", periodSeconds = 60, source = "Hetzner Cloud server metrics", observedAtUtc = now, state = "available",
                samples = new[] { new { timestampUtc = now.AddMinutes(-2), value = 67.125 }, new { timestampUtc = now.AddMinutes(-1), value = 61.5 } } };
        return new AnalysisReport($"cloud/{provider}/metrics", now, [], new
        {
            provider, metrics = new[] { series },
            coverage = new CloudCoverage(CoverageState.Complete, now, 1, 1, 1, [])
        });
    }

    private static void TestHistory()
    {
        var path = Path.Combine(Root, "history", "history.sqlite");
        var snapshot = Fixture();
        using (var store = new HistoryStore(path, retentionCount: 2, retentionDays: 30))
        {
            store.Add(snapshot with { CollectedAtUtc = snapshot.CollectedAtUtc.AddSeconds(-2) });
            var firstId = store.List().Single().Id;
            store.Add(snapshot with { CollectedAtUtc = snapshot.CollectedAtUtc.AddSeconds(-1), CpuUsedPercent = 25 });
            store.Add(snapshot with { CpuUsedPercent = 35 });
            var rows = store.List();
            Assert(rows.Count == 2, "History applies snapshot-count retention");
            Assert(rows[0].CpuUsedPercent == 35 && rows[1].CpuUsedPercent == 25, "History orders actual metrics newest first");
            Assert(store.Get(firstId) is null, "Pruned snapshot cannot be retrieved");
            Assert(store.Get(rows[0].Id)?.Host.Hostname == "[redacted-host]", "History always stores redacted host identity");
            Assert(store.Get(long.MaxValue) is null, "Unknown history id returns no evidence");
        }
        var bytes = File.ReadAllBytes(path);
        Assert(Encoding.ASCII.GetString(bytes.AsSpan(0, 16)).StartsWith("SQLite format 3", StringComparison.Ordinal), "History is an actual SQLite database");
        var databaseText = Encoding.UTF8.GetString(bytes);
        Assert(!databaseText.Contains("api-private-host", StringComparison.Ordinal), "Database contains no original hostname");
        Assert(!databaseText.Contains("private-user", StringComparison.Ordinal), "Database contains no original username");
        Assert(!databaseText.Contains("private-argument", StringComparison.Ordinal), "Database contains no command argument");
        Assert(!databaseText.Contains("192.0.2.35", StringComparison.Ordinal), "Database contains no original address");
        if (!OperatingSystem.IsWindows())
        {
            Assert(File.GetUnixFileMode(path) == (UnixFileMode.UserRead | UnixFileMode.UserWrite), "Database permissions are 0600");
            Assert(File.GetUnixFileMode(Path.GetDirectoryName(path)!) == (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute), "New history directory permissions are 0700");
        }
        using (var store = new HistoryStore(path, 2, 30)) Assert(store.List().Count == 2, "History survives a store restart");
        var agePath = Path.Combine(Root, "age.sqlite");
        using (var store = new HistoryStore(agePath, 10, 1))
        {
            store.Add(snapshot with { CollectedAtUtc = snapshot.CollectedAtUtc.AddDays(-2) });
            store.Add(snapshot);
            Assert(store.List().Count == 1, "History applies age retention");
            var clipped = snapshot with { Memory = snapshot.Memory with { Source = new string('x', HistoryStore.MaximumSnapshotBytes + 1) } };
            store.Add(clipped);
            Assert(store.Get(store.List()[0].Id)!.Memory.Source.Length < 20000, "History bounds individual evidence fields through redaction");
            var huge = snapshot with { CollectionWarnings = Enumerable.Repeat(new string('x', 16000), 140).ToArray() };
            Throws<InvalidDataException>(() => store.Add(huge), "History rejects redacted payloads larger than 2 MiB before storage");
        }
        Throws<ArgumentOutOfRangeException>(() => new HistoryStore(Path.Combine(Root, "bad.sqlite"), 1001), "History bounds configured retention");
        using (var connection = new SqliteConnection($"Data Source={agePath};Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand(); command.CommandText = "PRAGMA user_version=99"; command.ExecuteNonQuery();
        }
        Throws<InvalidDataException>(() => new HistoryStore(agePath), "Unknown store schema is rejected");
        if (!OperatingSystem.IsWindows())
        {
            var target = Path.Combine(Root, "link-target.sqlite");
            File.WriteAllText(target, "untouched");
            var link = Path.Combine(Root, "linked.sqlite");
            File.CreateSymbolicLink(link, target);
            Throws<IOException>(() => new HistoryStore(link), "History rejects symbolic-link destinations");
            Assert(File.ReadAllText(target) == "untouched", "Rejected link target remains unchanged");
            var targetDirectory = Path.Combine(Root, "parent-link-target");
            Directory.CreateDirectory(targetDirectory);
            var parentLink = Path.Combine(Root, "parent-link");
            Directory.CreateSymbolicLink(parentLink, targetDirectory);
            Throws<IOException>(() => new HistoryStore(Path.Combine(parentLink, "history.sqlite")), "History rejects user-created symbolic links in parent directories");
            Assert(!File.Exists(Path.Combine(targetDirectory, "history.sqlite")), "Rejected parent link creates no database in target");
        }
        if (OperatingSystem.IsMacOS())
        {
            var systemAliasDirectory = "/tmp/opscope-history-test-" + Guid.NewGuid().ToString("N");
            try
            {
                using var store = new HistoryStore(Path.Combine(systemAliasDirectory, "history.sqlite"));
                store.Add(snapshot);
                Assert(store.List().Count == 1, "History supports the standard protected macOS temporary-directory alias");
            }
            finally { if (Directory.Exists(systemAliasDirectory)) Directory.Delete(systemAliasDirectory, true); }
        }
    }

    private static void TestHistoryByteBudget()
    {
        var path = Path.Combine(Root, "byte-budget.sqlite");
        using var store = new HistoryStore(path, retentionCount: 1000, retentionDays: 30);
        // Raw non-ASCII JSON distinguishes the UTF-8 byte budget from character counts.
        // Every value and collection remains within the public snapshot parser's bounds.
        var largeSnapshot = Reporter.RedactForOutput(Fixture()) with
        {
            CollectionWarnings = Enumerable.Repeat(new string('é', 12000), 45).ToArray()
        };
        var payload = JsonSerializer.Serialize(largeSnapshot, new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        });
        var payloadBytes = Encoding.UTF8.GetByteCount(payload);
        Assert(payloadBytes < HistoryStore.MaximumSnapshotBytes && Reporter.ParseSnapshot(payload).CollectionWarnings.Count == 45, "Byte-budget fixture is valid redacted snapshot JSON within per-snapshot bounds");
        var inserted = HistoryStore.MaximumHistoryBytes / payloadBytes + 2;
        using var connection = new SqliteConnection($"Data Source={path};Pooling=False");
        connection.Open();
        using (var transaction = connection.BeginTransaction())
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO snapshots(created_utc,cpu,memory,findings,payload) VALUES($time,17.5,25,1,$payload)";
            command.Parameters.AddWithValue("$time", DateTimeOffset.UtcNow.ToString("O"));
            command.Parameters.AddWithValue("$payload", payload);
            for (var i = 0; i < inserted; i++) command.ExecuteNonQuery();
            transaction.Commit();
        }
        using var totals = connection.CreateCommand();
        totals.CommandText = "SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM snapshots";
        Assert(Convert.ToInt64(totals.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) > HistoryStore.MaximumHistoryBytes, "Byte-budget fixture exceeds 64 MiB before pruning without hitting count or age retention");
        store.Prune();
        var retainedBytes = Convert.ToInt64(totals.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
        Assert(retainedBytes <= HistoryStore.MaximumHistoryBytes, "History pruning enforces cumulative UTF-8 payload byte budget");
        var entries = store.List();
        Assert(entries.Count == HistoryStore.MaximumHistoryBytes / payloadBytes, "History retains the newest complete samples that fit the byte budget");
        Assert(entries[0].Id == inserted && entries[^1].Id > 1 && store.Get(1) is null, "Byte-budget retention preserves latest sample and removes oldest samples first");
        Assert(store.Get(inserted)?.CollectionWarnings.Count == 45, "Latest retained large snapshot remains readable after byte pruning");
        store.Add(Fixture() with { CpuUsedPercent = 43 });
        Assert(store.List()[0].CpuUsedPercent == 43, "New collection can still be stored after byte-budget pruning");
    }

    private static async Task TestMcpAsync()
    {
        var calls = 0;
        Task<Snapshot> Read(CancellationToken _) { calls++; return Task.FromResult(Fixture()); }
        var initialize = await McpServer.HandleAsync("""{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}""", Read);
        using (var data = JsonDocument.Parse(initialize!)) Assert(data.RootElement.GetProperty("result").GetProperty("serverInfo").GetProperty("name").GetString() == "opscope-read-only", "MCP initialize identifies read-only server");
        var list = await McpServer.HandleAsync("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""", Read);
        using (var data = JsonDocument.Parse(list!))
        {
            var tools = data.RootElement.GetProperty("result").GetProperty("tools").EnumerateArray().ToArray();
            Assert(tools.Length == 2, "MCP exposes exactly two narrow tools");
            Assert(tools.All(tool => tool.GetProperty("annotations").GetProperty("readOnlyHint").GetBoolean()), "Every MCP tool is marked read only");
        }
        Assert(calls == 0, "MCP discovery does not collect evidence");
        var latest = await McpServer.HandleAsync("""{"jsonrpc":"2.0","id":"snapshot","method":"tools/call","params":{"name":"opscope_snapshot","arguments":{}}}""", Read);
        Assert(latest is not null && !latest.Contains("api-private-host", StringComparison.Ordinal) && !latest.Contains("private-argument", StringComparison.Ordinal), "MCP snapshot content is redacted");
        var arbitrary = await McpServer.HandleAsync("""{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"opscope_snapshot","arguments":{"path":"/etc/passwd","command":"id"}}}""", Read);
        Assert(ErrorCode(arbitrary) == -32602, "MCP rejects arbitrary path and command arguments");
        var unknown = await McpServer.HandleAsync("""{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run_command"}}""", Read);
        Assert(ErrorCode(unknown) == -32602, "MCP rejects unlisted tools");
        Assert(ErrorCode(await McpServer.HandleAsync("{", Read)) == -32700, "MCP malformed JSON receives bounded parse error");
        Assert(ErrorCode(await McpServer.HandleAsync("""{"jsonrpc":"2.0","id":5,"method":"shell/exec"}""", Read)) == -32601, "MCP rejects unknown methods");
        Assert(await McpServer.HandleAsync("""{"jsonrpc":"2.0","method":"notifications/initialized"}""", Read) is null, "MCP notifications do not receive responses");
        Assert(ErrorCode(await McpServer.HandleAsync(new string('x', 65537), Read)) == -32600, "MCP rejects oversized HTTP messages");
        var input = new StringReader("""{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"opscope_snapshot"}}""" + "\n" + """{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"opscope_findings"}}""" + "\n");
        using var output = new StringWriter();
        var before = calls;
        await McpServer.RunAsync(Read, input, output);
        Assert(calls == before + 1, "Stdio MCP caches one shared evidence collection");
        Assert(output.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries).Length == 2, "Stdio MCP emits one JSON-RPC line per request");
        Assert(!output.ToString().Contains("api-private-host", StringComparison.Ordinal), "Stdio MCP output stays redacted");
    }

    private static async Task TestServerAsync()
    {
        var ready = new TaskCompletionSource<Uri>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var stop = new CancellationTokenSource();
        var historyPath = Path.Combine(Root, "server.sqlite");
        var collections = 0;
        var successfulCloudCalls = 0;
        var failCollection = false;
        string? reflectedToken = null;
        var serverTask = LocalServer.RunAsync(new ServerOptions
        {
            HistoryPath = historyPath, RetentionCount = 3, RefreshInterval = TimeSpan.FromSeconds(60),
            CollectAsync = _ =>
            {
                var call = Interlocked.Increment(ref collections);
                if (failCollection) throw new InvalidOperationException("Fixture collection failure.");
                var evidence = Fixture();
                return Task.FromResult(evidence with
                {
                    Services = [.. evidence.Services, new ServiceInfo("private-failed.service", call == 1 ? "failed" : "running", "Fixture failed service", "test")],
                    Listeners = call == 1 ? evidence.Listeners : [.. evidence.Listeners, new ListenerInfo("UDP", "0.0.0.0:5353", "worker", "test")],
                    Processes = call == 1 ? evidence.Processes : evidence.Processes.Select(process => process with { CommandLine = "browser http://127.0.0.1/#token=" + reflectedToken }).ToArray(),
                    Findings = call == 1 ? evidence.Findings : evidence.Findings.Select(finding => finding with { Detail = finding.Detail + "; observed launch argument " + reflectedToken }).ToArray()
                });
            },
            OnStarted = address => { reflectedToken = address.Fragment[7..]; ready.TrySetResult(address); },
            PolicyView = () => new { readOnly = true, ruleCount = 1 },
            CloudActions = new Dictionary<string, Func<CancellationToken, Task<AnalysisReport>>>
            {
                ["azure-scope-2/inventory"] = _ =>
                {
                    Interlocked.Increment(ref successfulCloudCalls);
                    return Task.FromResult(new AnalysisReport("cloud/azure", DateTimeOffset.UtcNow, [], new { count = 1 }, ["A coverage limitation is not an operation failure."]));
                },
                ["azure-scope-2/health"] = _ => Task.FromResult(new AnalysisReport("cloud/azure", DateTimeOffset.UtcNow, [], new { detail = "reflected " + reflectedToken }, ["Provider coverage failed."]) { OperationSucceeded = false })
            }
        }, stop.Token);
        try
        {
            var completed = await Task.WhenAny(ready.Task, serverTask, Task.Delay(TimeSpan.FromSeconds(20)));
            if (completed == serverTask) await serverTask;
            Assert(completed == ready.Task, "Local server starts within test deadline");
            var bootstrap = await ready.Task;
            Assert(bootstrap.Host == "127.0.0.1" && bootstrap.Port != 0, "Server binds IPv4 loopback and selects an available port");
            Assert(bootstrap.Fragment.StartsWith("#token=", StringComparison.Ordinal) && bootstrap.Fragment.Length == 71, "Bootstrap token has 256 bits and only appears in fragment");
            var token = bootstrap.Fragment[7..];
            using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false, Expect100ContinueTimeout = TimeSpan.FromSeconds(10) }) { BaseAddress = new Uri(bootstrap.GetLeftPart(UriPartial.Authority)), Timeout = TimeSpan.FromSeconds(15) };
            foreach (var path in new[] { "/api/snapshot", "/api/findings", "/api/history", "/api/history/1", "/api/settings", "/api/capabilities", "/api/cloud/catalog", "/api/cloud/coverage", "/api/metrics/capabilities", "/api/metrics/history", "/api/policy", "/api/timeline", "/api/bundle", "/api/report", "/api/report?format=pdf", "/api/report?format=sarif", "/api/openapi.json", "/api/events", "/metrics" })
            {
                using var response = await client.GetAsync(path, HttpCompletionOption.ResponseHeadersRead);
                Assert(response.StatusCode == HttpStatusCode.Unauthorized, $"Unauthenticated {path} is rejected");
            }
            using (var response = await client.PostAsync("/mcp", new StringContent("{}", Encoding.UTF8, "application/json"))) Assert(response.StatusCode == HttpStatusCode.Unauthorized, "Unauthenticated MCP is rejected");
            using (var response = await client.PostAsync("/api/policy/preview", new StringContent("{}", Encoding.UTF8, "application/json"))) Assert(response.StatusCode == HttpStatusCode.Unauthorized, "Unauthenticated policy preview is rejected");
            using (var response = await client.PostAsync("/api/fleet", new StringContent("{}", Encoding.UTF8, "application/json"))) Assert(response.StatusCode == HttpStatusCode.Unauthorized, "Unauthenticated fleet comparison is rejected");
            foreach (var path in new[] { "/api/analyze", "/api/report" })
            {
                using var response = await client.PostAsync(path, new StringContent("{}", Encoding.UTF8, "application/json"));
                Assert(response.StatusCode == HttpStatusCode.Unauthorized, "Unauthenticated saved-evidence operation is rejected: " + path);
            }
            using (var response = await client.GetAsync("/api/snapshot?token=" + token)) Assert(response.StatusCode == HttpStatusCode.Unauthorized, "Query-string token is not accepted as authentication");
            using (var response = await client.GetAsync("/realtime-charts.js"))
            {
                Assert(response.IsSuccessStatusCode && response.Content.Headers.ContentType?.MediaType == "text/javascript", "Only the explicitly registered local chart asset is available without an evidence token");
                Assert(!(await response.Content.ReadAsStringAsync()).Contains(token, StringComparison.Ordinal), "Local chart source embeds no session secret");
            }
            client.DefaultRequestHeaders.Add("X-Opscope-Token", token);
            await TestCloudCatalogAsync(client, token);
            await TestMetricsHistoryAsync(client, () => collections, token);
            foreach (var cursor in new[] { "-1", "not-a-sequence", "9223372036854775807" })
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, "/api/events");
                request.Headers.Add("Last-Event-ID", cursor);
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
                Assert(response.StatusCode == HttpStatusCode.BadRequest, "SSE rejects malformed and future resume cursors before allocating a stream: " + cursor);
            }
            using (var response = await client.GetAsync("/"))
            {
                Assert(response.IsSuccessStatusCode, "Embedded shell is served locally");
                Assert(response.Headers.GetValues("Content-Security-Policy").Single().Contains("default-src 'none'", StringComparison.Ordinal), "Strict CSP is attached to shell");
                Assert(response.Headers.GetValues("Referrer-Policy").Single() == "no-referrer", "Shell disables referrer leakage");
                Assert(response.Headers.CacheControl?.NoStore == true, "Shell and evidence are not cached");
                Assert(!(await response.Content.ReadAsStringAsync()).Contains(token, StringComparison.Ordinal), "Shell contains no embedded session token");
            }
            foreach (var asset in new[] { "/app.js", "/app.css" })
            {
                using var response = await client.GetAsync(asset);
                Assert(response.IsSuccessStatusCode, "Embedded asset available: " + asset);
            }
            await RejectHeader(client, "Host", "evil.example", "DNS-rebinding Host is rejected");
            await RejectHeader(client, "Host", "localhost:" + bootstrap.Port, "Alternate loopback hostname is rejected");
            await RejectHeader(client, "Origin", "https://evil.example", "Cross-origin request is rejected");
            await RejectHeader(client, "Origin", "null", "Opaque browser origin is rejected");
            await RejectHeader(client, "Referer", "https://evil.example/page", "External referrer is rejected");
            await RejectHeader(client, "Sec-Fetch-Site", "cross-site", "Cross-site browser fetch is rejected");
            await RejectHeader(client, "Sec-Fetch-Site", "same-site", "Same-site different-origin fetch is rejected");
            using (var request = new HttpRequestMessage(HttpMethod.Get, "/api/snapshot"))
            {
                request.Headers.TryAddWithoutValidation("Origin", new[] { client.BaseAddress!.GetLeftPart(UriPartial.Authority), client.BaseAddress.GetLeftPart(UriPartial.Authority) });
                using var response = await client.SendAsync(request);
                Assert(response.StatusCode == HttpStatusCode.Forbidden, "Duplicate Origin headers are rejected");
            }
            using (var request = new HttpRequestMessage(HttpMethod.Get, "/api/snapshot"))
            {
                request.Headers.Add("Origin", client.BaseAddress!.GetLeftPart(UriPartial.Authority));
                using var response = await client.SendAsync(request);
                Assert(response.IsSuccessStatusCode, "Exact same Origin is accepted");
                var json = await response.Content.ReadAsStringAsync();
                Assert(!json.Contains("api-private-host", StringComparison.Ordinal) && !json.Contains("private-argument", StringComparison.Ordinal), "Default API view is redacted");
                Assert(!json.Contains(token, StringComparison.Ordinal), "Snapshot never contains session token");
            }
            using (var response = await client.GetAsync("/api/snapshot?full=true")) Assert((await response.Content.ReadAsStringAsync()).Contains("api-private-host", StringComparison.Ordinal), "Full identity requires explicit full=true toggle");
            using (var response = await client.GetAsync("/metrics"))
            {
                var text = await response.Content.ReadAsStringAsync();
                Assert(text.Contains("opscope_cpu_used_percent 17.5", StringComparison.Ordinal), "Authenticated Prometheus endpoint uses actual metrics");
                Assert(!text.Contains("api-private-host", StringComparison.Ordinal) && !text.Contains(token, StringComparison.Ordinal), "Prometheus output carries no identity or token");
            }
            using (var response = await client.GetAsync("/api/events", HttpCompletionOption.ResponseHeadersRead))
            {
                Assert(response.IsSuccessStatusCode && response.Content.Headers.ContentType?.MediaType == "text/event-stream", "Authenticated SSE stream is available");
                using var stream = await response.Content.ReadAsStreamAsync();
                using var reader = new StreamReader(stream);
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var eventLine = await reader.ReadLineAsync(deadline.Token);
                var dataLine = await reader.ReadLineAsync(deadline.Token);
                Assert(eventLine == "event: snapshot" && dataLine?.StartsWith("data: ", StringComparison.Ordinal) == true, "SSE sends the current evidence sample");
                Assert(!dataLine!.Contains("api-private-host", StringComparison.Ordinal) && !dataLine.Contains(token, StringComparison.Ordinal), "SSE evidence is always redacted");
            }
            using (var response = await client.GetAsync("/api/events", HttpCompletionOption.ResponseHeadersRead))
            {
                using var stream = await response.Content.ReadAsStreamAsync();
                using var reader = new StreamReader(stream);
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                string? eventName = null, eventId = null, metricData = null;
                while (metricData is null)
                {
                    var line = await reader.ReadLineAsync(deadline.Token);
                    Assert(line is not null, "Metrics stream remains open until its current sample is delivered");
                    if (line!.StartsWith("event: ", StringComparison.Ordinal)) eventName = line[7..];
                    else if (line.StartsWith("id: ", StringComparison.Ordinal)) eventId = line[4..];
                    else if (line.StartsWith("data: ", StringComparison.Ordinal) && eventName == "metrics") metricData = line[6..];
                }
                using var metric = JsonDocument.Parse(metricData);
                Assert(eventId == metric.RootElement.GetProperty("sequence").GetInt64().ToString(System.Globalization.CultureInfo.InvariantCulture), "Metrics SSE supplies an ID matching its sample sequence");
                Assert(metric.RootElement.GetProperty("source").GetString() == "local-lightweight" && !metricData.Contains(token, StringComparison.Ordinal) && !metricData.Contains("api-private-host", StringComparison.Ordinal), "Metrics SSE contains only aggregate local counters without fixture identity or token");
            }
            using (var response = await client.GetAsync("/api/timeline"))
            {
                Assert(response.IsSuccessStatusCode, "Authenticated timeline is available");
                var text = await response.Content.ReadAsStringAsync();
                using var timeline = JsonDocument.Parse(text);
                var events = timeline.RootElement.GetProperty("data").GetProperty("events").EnumerateArray().ToArray();
                Assert(timeline.RootElement.GetProperty("kind").GetString() == "timeline" && events.Any(item => item.GetProperty("kind").GetString() == "boot"), "Timeline includes observed host boot");
                Assert(events.Any(item => item.GetProperty("kind").GetString() == "snapshot") && events.Any(item => item.GetProperty("kind").GetString() == "service-observation"), "Timeline includes actual snapshot and failed-service observations");
                Assert(!text.Contains("api-private-host", StringComparison.Ordinal) && !text.Contains("private-failed.service", StringComparison.Ordinal) && !text.Contains(token, StringComparison.Ordinal), "Timeline redacts host, service identity, and session token");
            }
            await TestPolicyPreviewAsync(client, () => collections);
            await TestOfflineAnalysisAsync(client, () => collections, token);
            await TestUploadValidationAsync(client, bootstrap, token);
            using (var response = await client.PostAsync("/api/diff", new StringContent("{}", Encoding.UTF8, "application/json"))) Assert(response.StatusCode == HttpStatusCode.BadRequest, "Invalid baseline is rejected");
            using (var response = await client.PostAsync("/api/diff", new StringContent("{", Encoding.UTF8, "application/json"))) Assert(response.StatusCode == HttpStatusCode.BadRequest, "Malformed baseline JSON is rejected");
            using (var response = await client.PostAsync("/api/diff", new StringContent(Reporter.ToJson(Fixture()), Encoding.UTF8, "text/plain"))) Assert(response.StatusCode == HttpStatusCode.BadRequest, "Baseline upload requires JSON content type");
            await AssertOversizedJsonRejectedAsync(client, "/api/diff", Reporter.ToJson(Fixture()), "Oversized baseline is bounded and rejected");
            using (var response = await client.PostAsync("/api/diff", new StringContent(Reporter.ToJson(Fixture() with { CpuUsedPercent = 80 }), Encoding.UTF8, "application/json")))
            {
                Assert(response.IsSuccessStatusCode, "Valid baseline is compared by shared diff engine");
                using var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                Assert(result.RootElement.GetProperty("significant").GetBoolean(), "Material CPU delta is reported");
                Assert(result.RootElement.GetProperty("baselineHost").GetString() == "[redacted-host]", "Diff output is redacted");
            }
            using (var response = await client.PostAsync("/mcp", new StringContent("""{"jsonrpc":"2.0","id":1,"method":"tools/list"}""", Encoding.UTF8, "application/json")))
            {
                Assert(response.IsSuccessStatusCode, "Authenticated HTTP MCP succeeds");
                using var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                Assert(result.RootElement.GetProperty("result").GetProperty("tools").GetArrayLength() == 2, "HTTP MCP exposes same narrow tool catalog");
            }
            using (var response = await client.GetAsync("/api/bundle"))
            {
                Assert(response.IsSuccessStatusCode, "Authenticated support bundle download succeeds");
                var bytes = await response.Content.ReadAsByteArrayAsync();
                var checksum = response.Headers.GetValues("X-Checksum-Sha256").Single();
                Assert(checksum == Hash(bytes), "Bundle SHA-256 response header matches downloaded bytes");
                using var stream = new MemoryStream(bytes);
                using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
                Assert(archive.GetEntry("manifest.json") is not null && archive.GetEntry("snapshot.json") is not null, "Bundle contains evidence and manifest");
                using var reader = new StreamReader(archive.GetEntry("snapshot.json")!.Open());
                Assert(!(await reader.ReadToEndAsync()).Contains("api-private-host", StringComparison.Ordinal), "Downloaded bundle remains redacted");
                using var manifestReader = new StreamReader(archive.GetEntry("manifest.json")!.Open());
                using var manifest = JsonDocument.Parse(await manifestReader.ReadToEndAsync());
                Assert(manifest.RootElement.GetProperty("format").GetString() == "opscope-custody/v1" && manifest.RootElement.GetProperty("redacted").GetBoolean(), "Bundle uses the versioned redacted custody manifest");
                foreach (var item in manifest.RootElement.GetProperty("files").EnumerateArray())
                {
                    var name = item.GetProperty("name").GetString()!;
                    using var content = archive.GetEntry(name)!.Open();
                    using var buffer = new MemoryStream(); await content.CopyToAsync(buffer);
                    var entryBytes = buffer.ToArray();
                    Assert(item.GetProperty("sha256").GetString() == Hash(entryBytes) && item.GetProperty("size").GetInt64() == entryBytes.Length, "Manifest hash and length match bundle entry: " + name);
                }
                var downloadedPath = Path.Combine(Root, "downloaded-bundle.zip");
                await File.WriteAllBytesAsync(downloadedPath, bytes);
                await File.WriteAllTextAsync(downloadedPath + ".sha256", checksum + "\n");
                var verified = await CustodyBundle.VerifyAsync(downloadedPath);
                Assert(verified.IsValid && !verified.IsSigned, "Downloaded bundle passes the shared CLI verifier with detached checksum");
                var tampered = Path.Combine(Root, "tampered-bundle.zip");
                await File.WriteAllBytesAsync(tampered, bytes);
                using (var changed = new ZipArchive(File.Open(tampered, FileMode.Open, FileAccess.ReadWrite), ZipArchiveMode.Update))
                {
                    changed.GetEntry("snapshot.json")!.Delete();
                    using var writer = new StreamWriter(changed.CreateEntry("snapshot.json").Open());
                    await writer.WriteAsync("{}");
                }
                await File.WriteAllTextAsync(tampered + ".sha256", Hash(await File.ReadAllBytesAsync(tampered)) + "\n");
                Assert(!(await CustodyBundle.VerifyAsync(tampered)).IsValid, "Manifest verification rejects modified content even with a recomputed detached checksum");
            }
            using (var response = await client.GetAsync("/api/report"))
            {
                var report = await response.Content.ReadAsStringAsync();
                Assert(response.IsSuccessStatusCode && response.Content.Headers.ContentType?.MediaType == "text/html", "Redacted printable HTML report is available");
                Assert(!report.Contains("api-private-host", StringComparison.Ordinal) && !report.Contains(token, StringComparison.Ordinal), "Report carries no original identity or session token");
            }
            using (var response = await client.GetAsync("/api/report?format=pdf"))
            {
                var bytes = await response.Content.ReadAsByteArrayAsync();
                var pdf = Encoding.Latin1.GetString(bytes);
                Assert(response.IsSuccessStatusCode && response.Content.Headers.ContentType?.MediaType == "application/pdf", "Authenticated PDF download returns PDF content type");
                Assert(pdf.StartsWith("%PDF-1.4", StringComparison.Ordinal) && pdf.TrimEnd().EndsWith("%%EOF", StringComparison.Ordinal), "PDF has a valid header and end marker");
                var xref = pdf.LastIndexOf("startxref\n", StringComparison.Ordinal) + "startxref\n".Length;
                var offset = int.Parse(pdf[xref..].Split('\n')[0], System.Globalization.CultureInfo.InvariantCulture);
                Assert(pdf[offset..].StartsWith("xref\n", StringComparison.Ordinal), "PDF cross-reference offset points to its xref table");
                Assert(!pdf.Contains("api-private-host", StringComparison.Ordinal) && !pdf.Contains("private-argument", StringComparison.Ordinal) && !pdf.Contains(token, StringComparison.Ordinal), "PDF output remains redacted and token-free");
            }
            using (var response = await client.GetAsync("/api/report?format=sarif"))
            {
                var text = await response.Content.ReadAsStringAsync();
                using var sarif = JsonDocument.Parse(text);
                Assert(response.IsSuccessStatusCode && sarif.RootElement.GetProperty("version").GetString() == "2.1.0", "Authenticated SARIF export uses version 2.1.0");
                var result = sarif.RootElement.GetProperty("runs")[0].GetProperty("results")[0];
                Assert(result.GetProperty("ruleId").GetString() == "TEST_WARNING" && result.GetProperty("level").GetString() == "warning", "SARIF preserves finding code and severity");
                Assert(!text.Contains("api-private-host", StringComparison.Ordinal) && !text.Contains(token, StringComparison.Ordinal), "SARIF evidence remains redacted and token-free");
            }
            using (var response = await client.GetAsync("/api/report?format=unknown")) Assert(response.StatusCode == HttpStatusCode.BadRequest, "Report endpoint rejects unknown formats");
            using (var response = await client.PostAsync("/api/collect", new StringContent("unexpected"))) Assert(response.StatusCode == HttpStatusCode.BadRequest, "Collection endpoint accepts no commands or body");
            await TestFleetAsync(client);
            Assert(collections == 1, "Fleet comparison and other API reads do not start extra host collections");
            await Task.Delay(2100);
            using (var response = await client.PostAsync("/api/collect", null)) Assert(response.IsSuccessStatusCode, "Manual collection invokes centralized collector");
            using (var response = await client.PostAsync("/api/collect", null)) Assert((int)response.StatusCode == 429, "Repeated collection is rate limited");
            Assert(collections == 2, "Rate-limited request does not start a second collection");
            using (var response = await client.GetAsync("/api/snapshot?full=true"))
            {
                var text = await response.Content.ReadAsStringAsync();
                Assert(response.IsSuccessStatusCode && !text.Contains(token, StringComparison.Ordinal), "Even full snapshots remove a session token observed in browser process arguments");
                using var snapshot = JsonDocument.Parse(text);
                Assert(snapshot.RootElement.GetProperty("processes")[0].GetProperty("commandLine").GetString()!.Contains("[redacted-session-token]", StringComparison.Ordinal), "Full process command line preserves evidence with session-token replacement marker");
                Assert(snapshot.RootElement.GetProperty("findings")[0].GetProperty("detail").GetString()!.Contains("[redacted-session-token]", StringComparison.Ordinal), "Collected finding details remove reflected session tokens before publication");
            }
            foreach (var tool in new[] { "opscope_snapshot", "opscope_findings" })
            {
                var request = JsonSerializer.Serialize(new { jsonrpc = "2.0", id = 44, method = "tools/call", @params = new { name = tool } });
                using var response = await client.PostAsync("/mcp", new StringContent(request, Encoding.UTF8, "application/json"));
                var text = await response.Content.ReadAsStringAsync();
                Assert(response.IsSuccessStatusCode && !text.Contains(token, StringComparison.Ordinal) && text.Contains("[redacted-session-token]", StringComparison.Ordinal), "MCP tool receives sanitized evidence when process arguments contained session token: " + tool);
            }
            using (var response = await client.GetAsync("/api/timeline"))
            {
                Assert(response.IsSuccessStatusCode, "Timeline supports retained baselines with multiple redacted service names");
                using var timeline = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                var events = timeline.RootElement.GetProperty("data").GetProperty("events").EnumerateArray().ToArray();
                Assert(events.Any(item => item.GetProperty("kind").GetString() == "baseline"), "Timeline includes retained baseline observation");
                Assert(events.Any(item => item.GetProperty("kind").GetString() == "drift" && item.GetProperty("source").GetString() == "snapshot-diff"), "Timeline includes actual observed listener drift");
            }
            await Task.Delay(2100);
            using (var response = await client.PostAsync("/api/cloud/azure-scope-2/inventory", null))
            {
                Assert(response.IsSuccessStatusCode, "Successful cloud report with coverage warnings remains HTTP success");
                using var report = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                Assert(report.RootElement.GetProperty("operationSucceeded").GetBoolean(), "Cloud report keeps its explicit success field");
            }
            using (var response = await client.PostAsync("/api/cloud/azure-scope-2/inventory", null))
            {
                Assert(response.IsSuccessStatusCode && response.Headers.GetValues("X-Opscope-Cache").Single() == "hit" && successfulCloudCalls == 1, "Repeated cloud reads reuse their bounded redacted cache without another provider call or cooldown error");
            }
            await Task.Delay(2100);
            using (var response = await client.PostAsync("/api/cloud/azure-scope-2/health", null))
            {
                var text = await response.Content.ReadAsStringAsync();
                using var report = JsonDocument.Parse(text);
                Assert(response.StatusCode == HttpStatusCode.BadGateway && !report.RootElement.GetProperty("operationSucceeded").GetBoolean(), "Failed cloud coverage returns HTTP502 with its analysis report");
                Assert(!text.Contains(token, StringComparison.Ordinal), "Cloud report free text cannot reflect the active session token");
            }
            await Task.Delay(2100);
            DateTimeOffset previousObservation;
            using (var previous = JsonDocument.Parse(await client.GetStringAsync("/api/snapshot"))) previousObservation = previous.RootElement.GetProperty("collectedAtUtc").GetDateTimeOffset();
            using (var response = await client.PostAsync("/api/collect", null)) Assert(response.IsSuccessStatusCode, "A third observation is retained for nearest-baseline timeline comparison");
            using (var response = await client.GetAsync("/api/timeline"))
            {
                using var report = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                var baselineEvent = report.RootElement.GetProperty("data").GetProperty("events").EnumerateArray().Single(item => item.GetProperty("kind").GetString() == "baseline");
                Assert(response.IsSuccessStatusCode && baselineEvent.GetProperty("timestampUtc").GetDateTimeOffset() == previousObservation, "Live timeline chooses the nearest previous retained observation rather than the oldest history entry");
            }
            await Task.Delay(2100);
            failCollection = true;
            using (var response = await client.PostAsync("/api/collect", null)) Assert(response.StatusCode == HttpStatusCode.ServiceUnavailable, "Collection failure returns503 instead of being mislabeled as rate limiting");
            using (var response = await client.GetAsync("/api/snapshot")) Assert(response.IsSuccessStatusCode, "Failed collection preserves the previous successful evidence");
        }
        finally
        {
            await stop.CancelAsync();
            await serverTask.WaitAsync(TimeSpan.FromSeconds(10));
            Assert(serverTask.IsCompletedSuccessfully, "Cancellation cleanly stops server and background collection");
        }
        // SQLite holds the database open while the server runs on Windows.
        // Inspect persisted bytes only after shutdown has disposed its connection.
        Assert(!Encoding.UTF8.GetString(File.ReadAllBytes(historyPath)).Contains(reflectedToken!, StringComparison.Ordinal), "History never stores session token");
    }

    private static async Task TestCloudCatalogAsync(HttpClient client, string token)
    {
        using var response = await client.GetAsync("/api/cloud/catalog");
        var text = await response.Content.ReadAsStringAsync();
        using var catalog = JsonDocument.Parse(text);
        Assert(response.IsSuccessStatusCode && catalog.RootElement.GetProperty("version").GetInt32() == 2, "Authenticated cloud catalog declares its versioned contract");
        var providers = catalog.RootElement.GetProperty("providers").EnumerateArray().ToArray();
        var expected = new[] { "azure", "aws", "gcp", "oci", "digitalocean", "hetzner", "cloudflare", "openstack", "alibaba", "ibm", "scaleway" };
        Assert(providers.Select(provider => provider.GetProperty("id").GetString()).Order(StringComparer.Ordinal).SequenceEqual(expected.Order(StringComparer.Ordinal)), "Catalog exposes all eleven unique canonical providers without requiring configured credentials");
        var gcp = providers.Single(provider => provider.GetProperty("id").GetString() == "gcp");
        Assert(gcp.GetProperty("scopes").GetArrayLength() == 0 && gcp.GetProperty("operations").EnumerateArray().Any(operation => operation.GetProperty("name").GetString() == "inventory" && operation.GetProperty("availability").GetString() == "not-configured"), "Known unconfigured providers expose their missing scope instead of an empty successful inventory");
        var actions = catalog.RootElement.GetProperty("actions").EnumerateArray().ToArray();
        Assert(actions.Any(action => action.GetProperty("actionKey").GetString() == "azure-scope-2/inventory") && actions.All(action => action.GetProperty("readOnly").GetBoolean()), "Catalog preserves explicitly configured action aliases as read-only actions");
        Assert(!text.Contains(token, StringComparison.Ordinal) && !text.Contains("api-private-host", StringComparison.Ordinal), "Cloud discovery reveals no host evidence or session secret");
        foreach (var (path, status) in new[]
        {
            ("/api/cloud/gcp/inventory", HttpStatusCode.Conflict),
            ("/api/cloud/gcp/delete", HttpStatusCode.NotImplemented),
            ("/api/cloud/not-a-provider/inventory", HttpStatusCode.NotFound)
        })
        {
            using var result = await client.PostAsync(path, null);
            Assert(result.StatusCode == status, "Cloud dispatch distinguishes unknown, unsupported, and unconfigured operations: " + path);
        }
        using (var coverageResponse = await client.GetAsync("/api/cloud/coverage"))
        {
            var coverage = await coverageResponse.Content.ReadAsStringAsync();
            Assert(coverageResponse.IsSuccessStatusCode && coverage.Contains("not-requested", StringComparison.Ordinal) && !coverage.Contains(token, StringComparison.Ordinal), "Coverage starts as not-requested and carries no session token");
        }
    }

    private static async Task TestMetricsHistoryAsync(HttpClient client, Func<int> collectionCount, string token)
    {
        var initialCollections = collectionCount();
        using (var response = await client.GetAsync("/api/metrics/capabilities"))
        {
            using var capabilities = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert(response.IsSuccessStatusCode && capabilities.RootElement.GetProperty("capacity").GetInt32() <= 720 && capabilities.RootElement.GetProperty("sampleIntervalSeconds").GetDouble() >= 5, "Metrics capabilities describe the bounded lightweight sampler independently of full evidence refresh");
        }
        using (var response = await client.GetAsync("/api/metrics/history?window=5m&limit=1"))
        {
            var text = await response.Content.ReadAsStringAsync();
            using var history = JsonDocument.Parse(text);
            var root = history.RootElement;
            Assert(response.IsSuccessStatusCode && root.GetProperty("schemaVersion").GetInt32() == 1 && root.GetProperty("source").GetString() == "local-lightweight", "Metrics history names its version and aggregate source");
            var points = root.GetProperty("points").EnumerateArray().ToArray();
            Assert(points.Length <= 1 && root.GetProperty("capacity").GetInt32() <= 720, "Metrics history applies the requested response bound and retention capacity");
            foreach (var point in points)
            {
                Assert(point.GetProperty("sequence").GetInt64() > 0 && point.GetProperty("sampledAtUtc").GetDateTimeOffset() <= DateTimeOffset.UtcNow, "Each metric has an actual UTC observation and positive sequence");
                foreach (var name in new[] { "cpuPercent", "memoryPercent" })
                {
                    var value = point.GetProperty(name);
                    Assert(value.ValueKind == JsonValueKind.Null || value.GetDouble() is >= 0 and <= 100, "Metrics use null for unavailable counters and bounded percentages for observations: " + name);
                }
            }
            Assert(!text.Contains(token, StringComparison.Ordinal) && !text.Contains("api-private-host", StringComparison.Ordinal) && !text.Contains("private-user", StringComparison.Ordinal), "Session metrics expose no identity or session secret");
        }
        using (var response = await client.GetAsync("/api/metrics/history?window=1h&afterSequence=9223372036854775807"))
        {
            using var history = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert(response.IsSuccessStatusCode && history.RootElement.GetProperty("points").GetArrayLength() == 0, "Metrics cursor beyond the last observation returns an empty interval without fabricated samples");
        }
        foreach (var query in new[] { "window=2m", "window=5m&window=15m", "limit=0", "limit=721", "limit=invalid", "afterSequence=-1", "afterSequence=999999999999999999999", "path=/etc/passwd" })
        {
            using var response = await client.GetAsync("/api/metrics/history?" + query);
            Assert(response.StatusCode == HttpStatusCode.BadRequest, "Metrics history rejects malformed, duplicate, unknown, or out-of-range query values: " + query);
        }
        Assert(collectionCount() == initialCollections, "Metrics capabilities and history never invoke full evidence collection");
    }

    private static async Task TestOfflineAnalysisAsync(HttpClient client, Func<int> collectionCount, string token)
    {
        var beforeCollections = collectionCount();
        var beforeHistory = await client.GetStringAsync("/api/history");
        var beforeLive = await client.GetStringAsync("/api/snapshot");
        var snapshot = Fixture() with { CpuUsedPercent = 96, CollectionWarnings = ["Observed launch secret " + token] };
        var baseline = snapshot with { CollectedAtUtc = snapshot.CollectedAtUtc.AddMinutes(-5), CpuUsedPercent = 10, Listeners = [] };
        static StringContent Body(object value) => new(JsonSerializer.Serialize(value, new JsonSerializerOptions(JsonSerializerDefaults.Web)), Encoding.UTF8, "application/json");
        using (var response = await client.PostAsync("/api/analyze", Body(new { snapshot, operation = "inspect" })))
        {
            var text = await response.Content.ReadAsStringAsync();
            var inspected = Reporter.ParseSnapshot(text);
            Assert(response.IsSuccessStatusCode && inspected.CpuUsedPercent == 96, "Saved snapshot inspection returns a validated flat Snapshot with uploaded observations");
            Assert(inspected.Host.Hostname == "[redacted-host]" && !text.Contains("api-private-host", StringComparison.Ordinal) && !text.Contains("private-user", StringComparison.Ordinal) && !text.Contains("private-argument", StringComparison.Ordinal) && !text.Contains(token, StringComparison.Ordinal), "Saved inspection redacts identities, command arguments, and reflected session secrets");
        }
        foreach (var scenario in new[] { "high-cpu", "disk-full", "port-exposed" })
        {
            using var response = await client.PostAsync("/api/analyze", Body(new { snapshot, operation = "triage", scenario }));
            var text = await response.Content.ReadAsStringAsync();
            using var report = JsonDocument.Parse(text);
            var data = report.RootElement.GetProperty("data");
            Assert(response.IsSuccessStatusCode && report.RootElement.GetProperty("kind").GetString() == "triage" && data.GetProperty("scenario").GetString() == scenario && data.GetProperty("steps").GetArrayLength() == 3, "Saved triage uses shared guidance for " + scenario);
            Assert(data.GetProperty("steps")[0].TryGetProperty("number", out _) && data.GetProperty("steps")[0].TryGetProperty("guidance", out _), "Triage result exposes numbered evidence and guidance");
            Assert(!text.Contains("api-private-host", StringComparison.Ordinal) && !text.Contains("private-volume", StringComparison.Ordinal) && !text.Contains("192.0.2.35", StringComparison.Ordinal) && !text.Contains(token, StringComparison.Ordinal), "Saved triage redacts evidence for " + scenario);
        }
        var csv = "type,value,label\nprocess,worker,reflected " + token + "\nsha256," + new string('a', 64) + ",offline hash\n";
        using (var response = await client.PostAsync("/api/analyze", Body(new { snapshot, operation = "ioc", indicators = new { format = "csv", text = csv } })))
        {
            var text = await response.Content.ReadAsStringAsync();
            using var report = JsonDocument.Parse(text);
            var data = report.RootElement.GetProperty("data");
            Assert(response.IsSuccessStatusCode && data.GetProperty("indicatorCount").GetInt32() == 2 && data.GetProperty("matches").GetArrayLength() == 1, "Saved CSV IoCs compare exact recorded process evidence");
            Assert(report.RootElement.GetProperty("warnings").EnumerateArray().Any(warning => warning.GetString()!.Contains("offline snapshots do not contain executable hashes", StringComparison.Ordinal)), "Offline IoC hash limitations are explicit without reading live executables");
            Assert(!text.Contains(token, StringComparison.Ordinal) && !text.Contains("api-private-host", StringComparison.Ordinal), "Saved IoC labels and evidence cannot expose session token or host identity");
        }
        const string stix = """{"type":"bundle","objects":[{"type":"process","name":"worker"},{"type":"indicator","pattern":"[process:name = 'worker' OR process:name = 'other']"}]}""";
        using (var response = await client.PostAsync("/api/analyze", Body(new { snapshot, operation = "ioc", indicators = new { format = "stix", text = stix } })))
        {
            using var report = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert(response.IsSuccessStatusCode && report.RootElement.GetProperty("data").GetProperty("matches").GetArrayLength() == 1, "Saved STIX IoCs use the shared observable parser");
            Assert(report.RootElement.GetProperty("warnings").EnumerateArray().Any(warning => warning.GetString()!.Contains("Unsupported STIX compound", StringComparison.Ordinal)), "Saved IoC results preserve import coverage warnings");
        }
        using (var response = await client.PostAsync("/api/analyze", Body(new { snapshot, operation = "timeline", baseline })))
        {
            using var report = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var events = report.RootElement.GetProperty("data").GetProperty("events").EnumerateArray().ToArray();
            Assert(response.IsSuccessStatusCode && events.Any(item => item.GetProperty("kind").GetString() == "baseline") && events.Any(item => item.GetProperty("kind").GetString() == "drift"), "Saved timeline compares only the supplied baseline and observation");
        }
        foreach (var invalid in new object[]
        {
            new { snapshot, operation = "inspect", path = "/etc/passwd" },
            new { snapshot, operation = "Inspect" },
            new { snapshot, operation = "inspect", scenario = "high-cpu" },
            new { snapshot, operation = "triage", scenario = "shell" },
            new { snapshot, operation = "triage" },
            new { snapshot, operation = "ioc", indicators = new { format = "json", text = stix } },
            new { snapshot, operation = "ioc", indicators = new { format = "csv", text = csv, path = "/etc/passwd" } },
            new { snapshot, operation = "ioc", indicators = new { format = "stix", text = "{\"type\":99}" } },
            new { snapshot, operation = "ioc", indicators = new { format = "csv", text = "type,value\n" + new string('é', 65536) } },
            new { snapshot, operation = "timeline", baseline = snapshot with { CollectedAtUtc = snapshot.CollectedAtUtc.AddMinutes(1) } },
            new { snapshot = new { }, operation = "inspect" }
        })
        {
            using var response = await client.PostAsync("/api/analyze", Body(invalid));
            Assert(response.StatusCode == HttpStatusCode.BadRequest, "Saved analysis rejects malformed, extra, oversized, or operation-incompatible fields");
        }
        var validJson = JsonSerializer.Serialize(new { snapshot, operation = "inspect" }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        using (var response = await client.PostAsync("/api/analyze", new StringContent(validJson.Replace("\"operation\":\"inspect\"", "\"operation\":\"inspect\",\"operation\":\"inspect\"", StringComparison.Ordinal), Encoding.UTF8, "application/json")))
            Assert(response.StatusCode == HttpStatusCode.BadRequest, "Saved analysis rejects duplicate request properties");
        using (var response = await client.PostAsync("/api/analyze", new StringContent(validJson.Replace("\"operation\":\"inspect\"", "\"operation\":\"\\uD800\"", StringComparison.Ordinal), Encoding.UTF8, "application/json")))
            Assert(response.StatusCode == HttpStatusCode.BadRequest, "Saved analysis rejects invalid escaped Unicode operation text");
        using (var response = await client.PostAsync("/api/analyze", new StringContent(validJson[..^1] + ",\"\\uD800\":0}", Encoding.UTF8, "application/json")))
            Assert(response.StatusCode == HttpStatusCode.BadRequest, "Saved analysis rejects invalid escaped Unicode property names");
        await AssertOversizedJsonRejectedAsync(client, "/api/analyze", validJson, "Saved analysis total request is bounded to2MiB");
        using (var document = JsonDocument.Parse(await client.GetStringAsync("/api/openapi.json")))
        {
            var paths = document.RootElement.GetProperty("paths");
            var variants = paths.GetProperty("/api/analyze").GetProperty("post").GetProperty("requestBody").GetProperty("content").GetProperty("application/json").GetProperty("schema").GetProperty("oneOf");
            Assert(variants.GetArrayLength() == 4 && variants.EnumerateArray().All(variant => !variant.GetProperty("additionalProperties").GetBoolean()), "OpenAPI documents each exact saved-analysis request variant");
            Assert(paths.GetProperty("/api/report").TryGetProperty("post", out _), "OpenAPI exposes authenticated saved-snapshot export");
        }
        var contentTypes = new Dictionary<string, string> { ["json"] = "application/json", ["html"] = "text/html", ["pdf"] = "application/pdf", ["sarif"] = "application/sarif+json", ["junit"] = "application/xml", ["csv"] = "text/csv", ["jsonl"] = "application/x-ndjson", ["cef"] = "text/plain" };
        foreach (var (format, contentType) in contentTypes)
        {
            using var response = await client.PostAsync("/api/report", Body(new { snapshot, format }));
            var bytes = await response.Content.ReadAsByteArrayAsync();
            var text = (format == "pdf" ? Encoding.Latin1 : Encoding.UTF8).GetString(bytes);
            Assert(response.IsSuccessStatusCode && response.Content.Headers.ContentType?.MediaType == contentType && response.Content.Headers.ContentDisposition?.DispositionType == "attachment", "Saved snapshot exports as a typed attachment: " + format);
            Assert(!text.Contains("api-private-host", StringComparison.Ordinal) && !text.Contains("private-user", StringComparison.Ordinal) && !text.Contains("private-argument", StringComparison.Ordinal) && !text.Contains(token, StringComparison.Ordinal), "Saved report export remains redacted and token-free: " + format);
            if (format == "json") Assert(Reporter.ParseSnapshot(text).CpuUsedPercent == 96, "Saved JSON report exports the chosen uploaded snapshot instead of live evidence");
            if (format == "pdf") Assert(text.StartsWith("%PDF-1.4", StringComparison.Ordinal), "Saved PDF report is an actual PDF document");
        }
        foreach (var value in new object[] { new { snapshot, format = "shell" }, new { snapshot, format = "html", path = "/tmp/report" }, new { snapshot = new { }, format = "html" } })
        {
            using var response = await client.PostAsync("/api/report", Body(value));
            Assert(response.StatusCode == HttpStatusCode.BadRequest, "Saved report rejects unsupported formats, output paths, and invalid snapshots");
        }
        Assert(collectionCount() == beforeCollections && await client.GetStringAsync("/api/history") == beforeHistory, "Saved inspection, analysis, exports, and validation failures invoke no collectors and write no history");
        Assert(await client.GetStringAsync("/api/snapshot") == beforeLive, "Saved evidence never overwrites the cached live snapshot");
    }

    private static async Task TestUploadValidationAsync(HttpClient client, Uri bootstrap, string token)
    {
        var json = Reporter.ToJson(Fixture());
        var invalidUtf8 = Encoding.UTF8.GetBytes(json);
        invalidUtf8[json.IndexOf("private-volume", StringComparison.Ordinal)] = 0xff;
        using (var body = new ByteArrayContent(invalidUtf8))
        {
            body.Headers.ContentType = new("application/json");
            using var response = await client.PostAsync("/api/diff", body);
            Assert(response.StatusCode == HttpStatusCode.BadRequest, "Malformed UTF8 inside otherwise valid snapshot text is rejected rather than replaced");
        }
        using (var body = new StringContent(json, Encoding.UTF8, "application/json"))
        {
            body.Headers.ContentType!.CharSet = "utf-16";
            using var response = await client.PostAsync("/api/diff", body);
            Assert(response.StatusCode == HttpStatusCode.BadRequest, "JSON upload cannot claim a conflicting nonUTF8 charset");
        }
        using var connection = new TcpClient();
        await connection.ConnectAsync(IPAddress.Loopback, bootstrap.Port);
        using var stream = connection.GetStream();
        var headers = $"POST /api/analyze HTTP/1.1\r\nHost: 127.0.0.1:{bootstrap.Port}\r\nX-Opscope-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: 3\r\nConnection: close\r\n\r\n{{";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(headers));
        await stream.FlushAsync();
        using var reader = new StreamReader(stream, Encoding.ASCII);
        using var secondConnection = new TcpClient();
        await secondConnection.ConnectAsync(IPAddress.Loopback, bootstrap.Port);
        using var secondStream = secondConnection.GetStream();
        await secondStream.WriteAsync(Encoding.ASCII.GetBytes(headers.Replace("/api/analyze", "/api/report", StringComparison.Ordinal)));
        await secondStream.FlushAsync();
        await Task.Delay(100);
        using (var response = await client.PostAsync("/api/analyze", new StringContent("{}", Encoding.UTF8, "application/json")))
            Assert(response.StatusCode == HttpStatusCode.TooManyRequests, "Saved analysis and export share a two-operation concurrency limit");
        using (var response = await client.GetAsync("/api/snapshot")) Assert(response.IsSuccessStatusCode, "Busy saved-evidence operations leave live evidence readable");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var status = await reader.ReadLineAsync(deadline.Token);
        Assert(status?.StartsWith("HTTP/1.1 408", StringComparison.Ordinal) == true, "Authenticated stalled uploads receive408 within the bounded upload deadline");
        using var health = await client.GetAsync("/api/snapshot");
        Assert(health.IsSuccessStatusCode, "Stalled upload timeout leaves live evidence available");
    }

    private static async Task TestPolicyPreviewAsync(HttpClient client, Func<int> collectionCount)
    {
        var beforeCollections = collectionCount();
        var beforeHistory = await client.GetStringAsync("/api/history");
        const string policy = """
            version: 1
            thresholds:
              cpuWarningPercent: 10
              cpuCriticalPercent: 15
              memoryWarningPercent: 20
              memoryCriticalPercent: 90
              diskWarningPercent: 40
              diskCriticalPercent: 90
            allowedPorts: [443]
            rules:
              - id: listener-count
                metric: network.listenerCount
                operator: ">="
                value: 1
                severity: warning
                title: Listener count rule matched
            """;
        using (var response = await client.PostAsync("/api/policy/preview", PolicyBody(policy)))
        {
            Assert(response.IsSuccessStatusCode, "Valid YAML policy preview evaluates the cached snapshot");
            var text = await response.Content.ReadAsStringAsync();
            using var report = JsonDocument.Parse(text);
            var findings = report.RootElement.GetProperty("findings").EnumerateArray().ToArray();
            Assert(report.RootElement.GetProperty("kind").GetString() == "policy" && report.RootElement.GetProperty("data").GetProperty("rulesEvaluated").GetInt32() == 1, "Policy preview returns a policy report with evaluated rule count");
            var cpu = findings.Single(item => item.GetProperty("code").GetString() == "POLICY_CPU");
            Assert(cpu.GetProperty("severity").GetInt32() == (int)FindingSeverity.Critical, "Policy preview reports critical when observed CPU exceeds configured 15 percent threshold");
            Assert(findings.Any(item => item.GetProperty("code").GetString() == "POLICY_MEMORY") && findings.Any(item => item.GetProperty("code").GetString() == "POLICY_PORT") && findings.Any(item => item.GetProperty("code").GetString() == "RULE_listener-count"), "Policy preview evaluates memory thresholds, approved ports, and declarative rules");
            Assert(!text.Contains("api-private-host", StringComparison.Ordinal) && !text.Contains("private-user", StringComparison.Ordinal) && !text.Contains("192.0.2.35", StringComparison.Ordinal), "Policy preview report remains redacted");
        }
        using (var response = await client.PostAsync("/api/policy/preview", PolicyBody(policy.Replace("cpuCriticalPercent: 15", "cpuCriticalPercent: 20", StringComparison.Ordinal))))
        {
            Assert(response.IsSuccessStatusCode, "Policy thresholds can be previewed again without host changes");
            using var report = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var cpu = report.RootElement.GetProperty("findings").EnumerateArray().Single(item => item.GetProperty("code").GetString() == "POLICY_CPU");
            Assert(cpu.GetProperty("severity").GetInt32() == (int)FindingSeverity.Warning, "Same observed 17.5 percent CPU becomes warning when critical threshold rises to 20 percent");
        }
        foreach (var (yaml, description) in new[]
        {
            ("version: 99\n", "Unsupported policy version is rejected"),
            ("version: 1\ncommand: id\n", "Policy cannot introduce a command key"),
            ("version: 1\nrequiredServices: &services [worker]\nrules: *services\n", "Policy YAML aliases and anchors are rejected"),
            ("version: 1\n#" + new string('x', 128 * 1024), "Policy preview enforces 128 KiB YAML bound")
        })
        {
            using var response = await client.PostAsync("/api/policy/preview", PolicyBody(yaml));
            Assert(response.StatusCode == HttpStatusCode.BadRequest, description);
        }
        using (var response = await client.PostAsync("/api/policy/preview", new StringContent("{\"text\":\"version: 1\",\"command\":\"id\"}", Encoding.UTF8, "application/json"))) Assert(response.StatusCode == HttpStatusCode.BadRequest, "Policy preview rejects extra JSON fields");
        using (var response = await client.PostAsync("/api/policy/preview", new StringContent("version: 1", Encoding.UTF8, "text/plain"))) Assert(response.StatusCode == HttpStatusCode.BadRequest, "Policy preview requires bounded JSON request");
        using (var response = await client.PostAsync("/api/policy/preview", new StringContent(new string('x', 512 * 1024 + 1), Encoding.UTF8, "application/json"))) Assert(response.StatusCode == HttpStatusCode.BadRequest, "Policy preview bounds JSON body before parsing");
        Assert(collectionCount() == beforeCollections, "Policy validation and preview do not invoke host collectors");
        Assert(await client.GetStringAsync("/api/history") == beforeHistory, "Policy previews and validation failures write no history snapshots");
    }
    private static StringContent PolicyBody(string text) => new(JsonSerializer.Serialize(new { text }), Encoding.UTF8, "application/json");

    private static async Task TestFleetAsync(HttpClient client)
    {
        var first = Fixture() with { Host = Fixture().Host with { Hostname = "a-fleet-private" }, CpuUsedPercent = 10 };
        var second = Fixture() with { Host = Fixture().Host with { Hostname = "z-fleet-private" }, CpuUsedPercent = 95 };
        static StringContent Body(IReadOnlyList<Snapshot> snapshots) => new(JsonSerializer.Serialize(new { snapshots }, new JsonSerializerOptions(JsonSerializerDefaults.Web)), Encoding.UTF8, "application/json");
        var before = await client.GetStringAsync("/api/history");
        using (var response = await client.PostAsync("/api/fleet", Body([first, second])))
        {
            var text = await response.Content.ReadAsStringAsync();
            Assert(response.IsSuccessStatusCode, "Stateless fleet endpoint accepts two validated distinct-host snapshots");
            using var report = JsonDocument.Parse(text);
            var data = report.RootElement.GetProperty("data");
            Assert(report.RootElement.GetProperty("kind").GetString() == "fleet" && data.GetProperty("hosts").GetArrayLength() == 2, "Fleet result contains both actual host observations");
            Assert(data.GetProperty("medianCpuUsedPercent").GetDouble() == 52.5, "Fleet median uses actual uploaded CPU observations");
            Assert(report.RootElement.GetProperty("findings").EnumerateArray().Any(finding => finding.GetProperty("code").GetString() == "FLEET_CPU_OUTLIER" && finding.GetProperty("severity").GetInt32() == 2), "Fleet analyzer identifies the observed critical CPU outlier");
            Assert(data.GetProperty("hosts").EnumerateArray().Select(host => host.GetProperty("host").GetString()).SequenceEqual(["[redacted-host-1]", "[redacted-host-2]"]), "Fleet rows keep distinct indexed redacted host labels");
            Assert(!text.Contains("a-fleet-private", StringComparison.Ordinal) && !text.Contains("z-fleet-private", StringComparison.Ordinal) && !text.Contains("private-user", StringComparison.Ordinal), "Fleet response contains no uploaded host or user identity");
            Assert(data.GetProperty("hosts").EnumerateArray().All(host => host.GetProperty("snapshotCount").GetInt32() == 1), "Fleet result preserves per-host snapshot counts");
        }
        using (var response = await client.PostAsync("/api/fleet", Body([first]))) Assert(response.StatusCode == HttpStatusCode.BadRequest, "Fleet endpoint requires at least two snapshots");
        using (var response = await client.PostAsync("/api/fleet", Body([first, first]))) Assert(response.StatusCode == HttpStatusCode.BadRequest, "Fleet endpoint requires distinct host identities");
        using (var response = await client.PostAsync("/api/fleet", Body([Reporter.RedactForOutput(first), Reporter.RedactForOutput(second)]))) Assert(response.StatusCode == HttpStatusCode.BadRequest, "Fleet does not fabricate distinct hosts from generic redacted labels");
        using (var response = await client.PostAsync("/api/fleet", Body(Enumerable.Repeat(first, 101).ToArray()))) Assert(response.StatusCode == HttpStatusCode.BadRequest, "Fleet endpoint rejects more than 100 uploaded snapshots");
        using (var response = await client.PostAsync("/api/fleet", new StringContent("{\"snapshots\":[{},{}]}", Encoding.UTF8, "application/json"))) Assert(response.StatusCode == HttpStatusCode.BadRequest, "Fleet validates each snapshot through the shared parser");
        using (var response = await client.PostAsync("/api/fleet", new StringContent("{\"snapshots\":[],\"command\":\"ignored\"}", Encoding.UTF8, "application/json"))) Assert(response.StatusCode == HttpStatusCode.BadRequest, "Fleet endpoint accepts no command or extra request properties");
        using (var response = await client.PostAsync("/api/fleet", new StringContent("{}", Encoding.UTF8, "text/plain"))) Assert(response.StatusCode == HttpStatusCode.BadRequest, "Fleet request requires JSON content type");
        await AssertOversizedJsonRejectedAsync(client, "/api/fleet", JsonSerializer.Serialize(new { snapshots = new[] { first, second } }, new JsonSerializerOptions(JsonSerializerDefaults.Web)), "Fleet total request bytes are capped at 2 MiB");
        Assert(await client.GetStringAsync("/api/history") == before, "Fleet uploads and results never write to snapshot history");
    }

    private static async Task AssertOversizedJsonRejectedAsync(HttpClient client, string path, string validJson, string description)
    {
        // Trailing whitespace preserves valid JSON, so rejection demonstrates the byte
        // limit rather than a syntax error. The same unpadded evidence is valid above.
        var padding = HistoryStore.MaximumSnapshotBytes + 1 - Encoding.UTF8.GetByteCount(validJson);
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(validJson + new string(' ', padding), Encoding.UTF8, "application/json")
        };
        // Let Kestrel reject the known oversized Content-Length before HttpClient starts
        // writing the body; otherwise a legitimate early close can surface as a broken pipe.
        request.Headers.ExpectContinue = true;
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
        Assert(response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.RequestEntityTooLarge, description);
        using var health = await client.GetAsync("/api/snapshot");
        Assert(health.IsSuccessStatusCode, "Local evidence remains available after an oversized request: " + path);
    }

    private static async Task RejectHeader(HttpClient client, string name, string value, string description)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/snapshot");
        request.Headers.TryAddWithoutValidation(name, value);
        using var response = await client.SendAsync(request);
        Assert(response.StatusCode == HttpStatusCode.Forbidden, description);
    }
    private static string Hash(byte[] content) => Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
    private static int ErrorCode(string? json)
    {
        using var document = JsonDocument.Parse(json!);
        return document.RootElement.GetProperty("error").GetProperty("code").GetInt32();
    }
    private static void Throws<T>(Action action, string description) where T : Exception
    {
        try { action(); throw new InvalidOperationException("Expected " + typeof(T).Name + ": " + description); }
        catch (T) { Assert(true, description); }
    }
    private static void Assert(bool condition, string description)
    {
        if (!condition) throw new InvalidOperationException("FAIL: " + description);
        assertions++;
        Console.WriteLine("PASS " + description);
    }
}
