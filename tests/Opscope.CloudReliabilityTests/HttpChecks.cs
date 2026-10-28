using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Opscope;
using Opscope.Api;

internal static class HttpChecks
{
    private static int assertions;

    public static async Task<int> RunAsync()
    {
        assertions = 0;
        var root = Path.Combine(Path.GetTempPath(), "opscope-cloud-http-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await LocalAsync(root);
            await ProxyAsync(root);
            return assertions;
        }
        finally { try { Directory.Delete(root, true); } catch (IOException) { } }
    }

    private static async Task LocalAsync(string root)
    {
        var ready = Signal<Uri>();
        var entered = Signal<bool>();
        var release = Signal<bool>();
        var clock = new HttpClock();
        using var shutdown = new CancellationTokenSource();
        var collections = 0;
        var quotaCalls = 0;
        var deniedCalls = 0;
        string token = "";
        var server = LocalServer.RunAsync(new ServerOptions
        {
            HistoryPath = Path.Combine(root, "local.sqlite"), RefreshInterval = TimeSpan.FromSeconds(60), CloudTimeProvider = clock,
            CollectAsync = _ => Task.FromResult(Fixture(Interlocked.Increment(ref collections), token)),
            OnStarted = uri => { token = uri.Fragment[7..]; ready.TrySetResult(uri); },
            CloudActions = new Dictionary<string, Func<CancellationToken, Task<AnalysisReport>>>
            {
                ["azure-scope-1/inventory"] = async cancellation => { entered.TrySetResult(true); await release.Task.WaitAsync(cancellation); return Report("azure", "inventory", "Complete", token); },
                ["azure-scope-2/inventory"] = _ => { Interlocked.Increment(ref quotaCalls); return Task.FromResult(Report("azure", "inventory", "RateLimited", token)); },
                ["azure-scope-2/health"] = _ => { Interlocked.Increment(ref deniedCalls); return Task.FromResult(Report("azure", "health", "Complete", token)); },
                ["azure-scope-3/inventory"] = _ => Task.FromResult(Report("azure", "inventory", "Complete", token)),
                ["gcp-scope-1/health"] = _ => Task.FromResult(Report("gcp", "health", "Complete", token))
            }
        }, shutdown.Token);
        try
        {
            var bootstrap = await Started(ready.Task, server);
            Check(bootstrap.Host == "127.0.0.1" && bootstrap.Port > 0 && token.Length == 64, "local cloud fixture retains loopback bootstrap authentication");
            using var client = Client(new Uri(bootstrap.GetLeftPart(UriPartial.Authority)));
            using (var unauthenticated = await client.GetAsync("/api/cloud/coverage")) Check(unauthenticated.StatusCode == HttpStatusCode.Unauthorized, "cloud observations require session authentication");
            client.DefaultRequestHeaders.Add("X-Opscope-Token", token);
            using (var crossOrigin = new HttpRequestMessage(HttpMethod.Post, "/api/cloud/azure-scope-2/inventory"))
            {
                crossOrigin.Headers.Add("Origin", "https://other.example");
                using var denied = await client.SendAsync(crossOrigin);
                Check(denied.StatusCode == HttpStatusCode.Forbidden && quotaCalls == 0, "cloud admission preserves local origin boundary");
            }
            // The independent host collector has its existing two second minimum interval.
            await Task.Delay(TimeSpan.FromMilliseconds(2100));
            var slow = client.PostAsync("/api/cloud/azure-scope-1/inventory", null);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            using (var busy = await client.PostAsync("/api/cloud/azure-scope-3/inventory", null).WaitAsync(TimeSpan.FromSeconds(3)))
            {
                Check(busy.StatusCode == HttpStatusCode.TooManyRequests, "a second cloud request returns immediately while a read is active");
                Check(Header(busy, "X-Opscope-Retry-Scope") == "azure-scope-3" && Header(busy, "X-Opscope-Retry-Reason") == "workspace-busy" && Header(busy, "Retry-After") == "1", "busy response identifies the requested alias and workspace admission reason");
            }
            using (var collected = await client.PostAsync("/api/collect", null).WaitAsync(TimeSpan.FromSeconds(3)))
            {
                Check(collected.IsSuccessStatusCode && collections == 2 && !slow.IsCompleted, "manual host collection completes while a cloud callback remains blocked");
                CheckPrivate(await collected.Content.ReadAsStringAsync(), token, "manual collection");
            }
            using (var snapshot = await client.GetAsync("/api/snapshot").WaitAsync(TimeSpan.FromSeconds(3)))
            {
                Check(snapshot.IsSuccessStatusCode && !slow.IsCompleted, "latest snapshot remains available during cloud read");
                CheckPrivate(await snapshot.Content.ReadAsStringAsync(), token, "snapshot");
            }
            using (var streamStop = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
            using (var events = await client.GetAsync("/api/events", HttpCompletionOption.ResponseHeadersRead, streamStop.Token))
            {
                Check(events.IsSuccessStatusCode && events.Content.Headers.ContentType?.MediaType == "text/event-stream", "SSE opens while cloud callback remains blocked");
                using var reader = new StreamReader(await events.Content.ReadAsStreamAsync(streamStop.Token));
                Check(await reader.ReadLineAsync(streamStop.Token) == "event: snapshot", "SSE still publishes host snapshots during cloud work");
                CheckPrivate(await reader.ReadLineAsync(streamStop.Token) ?? "", token, "SSE snapshot");
                streamStop.Cancel();
            }
            clock.Advance(TimeSpan.FromSeconds(3));
            release.TrySetResult(true);
            using (var completed = await slow.WaitAsync(TimeSpan.FromSeconds(5)))
            {
                Check(completed.IsSuccessStatusCode && Header(completed, "X-Opscope-Cache") == "miss", "released cloud read finishes with cache metadata");
                Check(!completed.Headers.Contains("X-Opscope-Retry-Reason"), "completed long cloud read does not advertise its own released slot as workspace busy");
                CheckPrivate(await completed.Content.ReadAsStringAsync(), token, "cloud read");
            }

            string firstJson;
            string cachedAt;
            string expiresAt;
            using (var quota = await client.PostAsync("/api/cloud/azure-scope-2/inventory", null))
            {
                firstJson = await quota.Content.ReadAsStringAsync();
                cachedAt = Header(quota, "X-Opscope-Cache-Cached-At");
                expiresAt = Header(quota, "X-Opscope-Cache-Expires-At");
                Check(quota.StatusCode == HttpStatusCode.TooManyRequests && quotaCalls == 1, "provider quota report retains HTTP 429");
                Check(Header(quota, "X-Opscope-Cache") == "miss" && Header(quota, "X-Opscope-Cache-Remaining-Seconds") == "15", "provider quota report uses the error cache lifetime");
                Check(DateTimeOffset.Parse(expiresAt) - DateTimeOffset.Parse(cachedAt) == TimeSpan.FromSeconds(15), "cache timestamps describe the fifteen second quota report lifetime");
                Check(Header(quota, "Retry-After") == "15" && Header(quota, "X-Opscope-Retry-Scope") == "azure-scope-2" && Header(quota, "X-Opscope-Retry-Reason") == "provider-quota", "quota response marks the configured scope cooldown");
                using var json = JsonDocument.Parse(firstJson);
                Check(json.RootElement.GetProperty("data").GetProperty("coverage").GetProperty("state").GetString() == "RateLimited" && json.RootElement.GetProperty("cloudProblem").GetProperty("code").GetString() == "PROVIDER_RATE_LIMITED", "quota response preserves redacted evidence and fixed problem metadata");
                CheckPrivate(firstJson, token, "quota report");
            }
            clock.Advance(TimeSpan.FromSeconds(5));
            using (var hit = await client.PostAsync("/api/cloud/azure-scope-2/inventory", null))
            {
                Check(hit.StatusCode == HttpStatusCode.TooManyRequests && quotaCalls == 1 && await hit.Content.ReadAsStringAsync() == firstJson, "cached quota response preserves status, body, and callback count");
                Check(Header(hit, "X-Opscope-Cache") == "hit" && Header(hit, "X-Opscope-Cache-Age-Seconds") == "5" && Header(hit, "X-Opscope-Cache-Remaining-Seconds") == "10", "quota cache age advances without renewing the lifetime");
                Check(Header(hit, "Retry-After") == "10" && Header(hit, "X-Opscope-Cache-Cached-At") == cachedAt, "cached quota response does not renew cooldown or observation time");
                Check(Header(hit, "X-Opscope-Cache-Expires-At") == expiresAt, "cache hit preserves original expiry timestamp");
            }
            using (var sibling = await client.PostAsync("/api/cloud/azure-scope-2/health", null))
            {
                Check(sibling.StatusCode == HttpStatusCode.TooManyRequests && deniedCalls == 0, "provider quota suppresses other operations in the same configured alias");
                Check(Header(sibling, "X-Opscope-Retry-Reason") == "provider-quota" && Header(sibling, "Retry-After") == "10", "same alias operations share the remaining quota interval");
            }
            foreach (var path in new[] { "/api/cloud/azure-scope-3/inventory", "/api/cloud/gcp-scope-1/health" })
            {
                using var independent = await client.PostAsync(path, null);
                Check(independent.IsSuccessStatusCode, "another alias or provider remains readable during provider quota: " + path);
            }
            using (var coverage = await client.GetAsync("/api/cloud/coverage"))
            {
                using var json = JsonDocument.Parse(await coverage.Content.ReadAsStringAsync());
                var action = json.RootElement.GetProperty("actions").EnumerateArray().Single(item => item.GetProperty("actionKey").GetString() == "azure-scope-2/inventory");
                Check(action.GetProperty("status").GetString() == "rate-limited" && action.GetProperty("retryAfterSeconds").GetInt32() == 10 && !action.GetProperty("canRequestRead").GetBoolean(), "coverage exposes current bounded quota state");
            }
            clock.Advance(TimeSpan.FromSeconds(11));
            using (var retried = await client.PostAsync("/api/cloud/azure-scope-2/inventory", null)) Check(retried.StatusCode == HttpStatusCode.TooManyRequests && quotaCalls == 2 && Header(retried, "X-Opscope-Cache") == "miss", "expired quota response admits a new provider read");
        }
        finally
        {
            release.TrySetResult(true);
            shutdown.Cancel();
            try { await server.WaitAsync(TimeSpan.FromSeconds(8)); } catch (OperationCanceledException) { }
        }
    }

    private static async Task ProxyAsync(string root)
    {
        const string origin = "https://cloud.opscope.example";
        var secret = new string('B', 64);
        var ready = Signal<Uri>();
        var clock = new HttpClock();
        using var shutdown = new CancellationTokenSource();
        var port = FreePort();
        var calls = 0;
        var server = LocalServer.RunAsync(new ServerOptions
        {
            Port = port, PublicOrigin = origin, ProxyToken = secret, HistoryPath = Path.Combine(root, "proxy.sqlite"), RefreshInterval = TimeSpan.FromSeconds(60), CloudTimeProvider = clock,
            CollectAsync = _ => Task.FromResult(Fixture(1, secret)), OnStarted = uri => ready.TrySetResult(uri),
            CloudActions = new Dictionary<string, Func<CancellationToken, Task<AnalysisReport>>> { ["azure-scope-1/inventory"] = _ => { Interlocked.Increment(ref calls); return Task.FromResult(Report("azure", "inventory", "RateLimited", secret)); } }
        }, shutdown.Token);
        try
        {
            Check((await Started(ready.Task, server)).AbsoluteUri == origin + "/", "proxy bootstrap never exposes the upstream secret");
            using var client = Client(new Uri($"http://127.0.0.1:{port}"));
            client.DefaultRequestHeaders.Host = "cloud.opscope.example";
            client.DefaultRequestHeaders.Add("Origin", origin);
            using (var rejected = await client.PostAsync("/api/cloud/azure-scope-1/inventory", null)) Check(rejected.StatusCode == HttpStatusCode.Unauthorized && calls == 0, "proxy cloud reads still require upstream authentication");
            client.DefaultRequestHeaders.Add("X-Opscope-Token", secret);
            using (var first = await client.PostAsync("/api/cloud/azure-scope-1/inventory", null))
            {
                Check(first.StatusCode == HttpStatusCode.TooManyRequests && Header(first, "X-Opscope-Retry-Reason") == "provider-quota", "proxy mode preserves scoped quota response headers");
                CheckPrivate(await first.Content.ReadAsStringAsync(), secret, "proxy cloud report");
            }
            clock.Advance(TimeSpan.FromSeconds(4));
            using (var cached = await client.PostAsync("/api/cloud/azure-scope-1/inventory", null)) Check(calls == 1 && Header(cached, "X-Opscope-Cache") == "hit" && Header(cached, "Retry-After") == "11", "proxy mode shares bounded cache and decreasing retry contract");
            using (var snapshot = await client.GetAsync("/api/snapshot")) CheckPrivate(await snapshot.Content.ReadAsStringAsync(), secret, "proxy snapshot");
            client.DefaultRequestHeaders.Host = "wrong.example";
            using (var rejected = await client.PostAsync("/api/cloud/azure-scope-1/inventory", null)) Check(rejected.StatusCode == HttpStatusCode.Forbidden && calls == 1, "cached cloud reports retain proxy canonical host enforcement");
        }
        finally { shutdown.Cancel(); try { await server.WaitAsync(TimeSpan.FromSeconds(8)); } catch (OperationCanceledException) { } }
    }

    private static Snapshot Fixture(int sequence, string token) => new(
        DateTimeOffset.UtcNow.AddMilliseconds(sequence),
        new HostInfo("private-cloud-host", "Test OS", "Linux", "X64", ".NET 8", "kernel", DateTimeOffset.UtcNow.AddDays(-1), TimeSpan.FromDays(1), false, 2, "private-cloud-user"),
        12, new MemoryInfo(1000, 500, 500, 50, "test"), [], [],
        [new ProcessInfo(1, "worker", "private-cloud-user", 100, 1, TimeSpan.Zero, "browser #token=" + token, false)], [], [],
        new SecurityPosture([], false, false, 1), new ToolingPosture([]), [], [], TimeSpan.FromMilliseconds(1));

    private static AnalysisReport Report(string provider, string operation, string state, string token) => new($"cloud/{provider}/{operation}", DateTimeOffset.UtcNow, [], new { coverage = new { state }, resourceCount = 7, detail = "reflected " + token }) { OperationSucceeded = state != "RateLimited" };
    private static HttpClient Client(Uri address) => new(new SocketsHttpHandler { UseProxy = false }) { BaseAddress = address, Timeout = TimeSpan.FromSeconds(8) };
    private static TaskCompletionSource<T> Signal<T>() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static async Task<Uri> Started(Task<Uri> ready, Task server) { var completed = await Task.WhenAny(ready, server).WaitAsync(TimeSpan.FromSeconds(8)); if (completed == server) await server; return await ready.WaitAsync(TimeSpan.FromSeconds(1)); }
    private static int FreePort() { using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); return ((IPEndPoint)listener.LocalEndpoint).Port; }
    private static string Header(HttpResponseMessage response, string name) => response.Headers.TryGetValues(name, out var values) ? values.Single() : throw new InvalidOperationException("Missing response header: " + name);
    private static void CheckPrivate(string body, string token, string source) => Check(!body.Contains(token, StringComparison.Ordinal) && !body.Contains("private-cloud-host", StringComparison.Ordinal) && !body.Contains("private-cloud-user", StringComparison.Ordinal), source + " omits session secrets and private host identity");
    private static void Check(bool condition, string message) { assertions++; if (!condition) throw new InvalidOperationException("HTTP reliability assertion failed: " + message); }

    private sealed class HttpClock : TimeProvider
    {
        private long elapsedTicks;
        private readonly DateTimeOffset initialUtc = new(2026, 10, 28, 12, 0, 0, TimeSpan.Zero);
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Interlocked.Read(ref elapsedTicks);
        public override DateTimeOffset GetUtcNow() => initialUtc.AddTicks(Interlocked.Read(ref elapsedTicks));
        internal void Advance(TimeSpan duration) => Interlocked.Add(ref elapsedTicks, duration.Ticks);
    }
}
