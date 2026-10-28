using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Opscope;
using Opscope.Api;
using Opscope.Cloud;

internal static class Program
{
    private static int assertions;
    private static readonly string Root = Path.Combine(Path.GetTempPath(), "opscope-remote-tests-" + Guid.NewGuid().ToString("N"));
    private static readonly string ProxyToken = new('A', 64);
    private const string PublicOrigin = "https://opscope.example.test";

    private static async Task<int> Main()
    {
        Directory.CreateDirectory(Root);
        try
        {
            await TestConfigurationAsync();
            await TestProxyAsync();
            await TestLocalSessionAsync();
            Console.WriteLine($"PASS: {assertions} remote-hosting and provider-session boundary assertions.");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
        finally { try { Directory.Delete(Root, true); } catch (IOException) { } }
    }

    private static async Task TestConfigurationAsync()
    {
        Assert(LocalServer.ValidateProxyConfiguration(null, null) is null, "Local defaults require no proxy configuration");
        Assert(LocalServer.ValidateProxyConfiguration(PublicOrigin + "/", ProxyToken) == PublicOrigin, "Root slash normalizes to exact browser origin");
        Assert(LocalServer.ValidateProxyConfiguration("https://opscope.example.test:8443", ProxyToken) == "https://opscope.example.test:8443", "Explicit HTTPS port is retained");
        var cases = new (string? Origin, string? Token)[]
        {
            (PublicOrigin, null), (null, ProxyToken), (PublicOrigin, "short"), (PublicOrigin, new string('z', 64)),
            ("http://opscope.example.test", ProxyToken), ("https://user:password@opscope.example.test", ProxyToken),
            (PublicOrigin + "/ui", ProxyToken), (PublicOrigin + "/./", ProxyToken), (PublicOrigin + "?x=1", ProxyToken),
            (PublicOrigin + "#token=x", ProxyToken), (PublicOrigin + ":0", ProxyToken), (PublicOrigin + "%2f", ProxyToken),
            ("https://opscope.example.test\\bad", ProxyToken), (PublicOrigin + " ", ProxyToken), ("//opscope.example.test", ProxyToken),
            ("https://", ProxyToken), ("https:///opscope.example.test", ProxyToken)
        };
        var collected = 0;
        foreach (var item in cases)
        {
            var history = Path.Combine(Root, "invalid-" + assertions + ".sqlite");
            try
            {
                await LocalServer.RunAsync(new ServerOptions { PublicOrigin = item.Origin, ProxyToken = item.Token, HistoryPath = history, CollectAsync = _ => { collected++; return Task.FromResult(Fixture()); } });
                throw new InvalidOperationException("Invalid proxy configuration unexpectedly started a server.");
            }
            catch (ArgumentException error)
            {
                Assert(!error.Message.Contains(ProxyToken, StringComparison.Ordinal), "Configuration rejection does not expose secret");
                Assert(!File.Exists(history), "Invalid proxy config is rejected before history initialization");
            }
        }
        Assert(collected == 0, "Invalid proxy config never starts host collection");
        var options = new ServerOptions { PublicOrigin = PublicOrigin, ProxyToken = ProxyToken };
        Assert(!JsonSerializer.Serialize(options).Contains(ProxyToken, StringComparison.Ordinal), "Options JSON excludes proxy token");
        Assert(!options.ToString().Contains(ProxyToken, StringComparison.Ordinal), "Options diagnostic string excludes proxy token");
    }

    private static async Task TestProxyAsync()
    {
        var port = FreePort();
        using var shutdown = new CancellationTokenSource();
        var ready = new TaskCompletionSource<Uri>(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        var definitions = new[]
        {
            (State: "NotConfigured", Status: 409, Success: false, Code: "PROVIDER_NOT_CONFIGURED"),
            (State: "PermissionDenied", Status: 424, Success: false, Code: "PROVIDER_PERMISSION_DENIED"),
            (State: "RateLimited", Status: 429, Success: false, Code: "PROVIDER_RATE_LIMITED"),
            (State: "TimedOut", Status: 504, Success: false, Code: "PROVIDER_TIMED_OUT"),
            (State: "Unsupported", Status: 501, Success: false, Code: "OPERATION_UNSUPPORTED"),
            (State: "Failed", Status: 502, Success: false, Code: "PROVIDER_UNAVAILABLE"),
            (State: "Partial", Status: 200, Success: false, Code: "PROVIDER_PARTIAL"),
            (State: "Complete", Status: 200, Success: true, Code: "PROVIDER_READ_COMPLETED")
        };
        var actions = definitions.Select((item, i) => new KeyValuePair<string, Func<CancellationToken, Task<AnalysisReport>>>($"azure-scope-{i + 1}/inventory", _ =>
        {
            Interlocked.Increment(ref calls);
            return Task.FromResult(new AnalysisReport("cloud/azure/inventory", DateTimeOffset.UtcNow, [], new
            {
                resourceCount = item.State == "Partial" ? 1 : 0,
                detail = "reflected " + ProxyToken,
                coverage = new { state = item.State, observedAtUtc = DateTimeOffset.UtcNow, enumeratedResources = 1, expectedScopes = 1, completedScopes = 1 }
            }) { OperationSucceeded = item.Success });
        })).ToDictionary(pair => pair.Key, pair => pair.Value);
        var server = LocalServer.RunAsync(new ServerOptions
        {
            Port = port, PublicOrigin = PublicOrigin, ProxyToken = ProxyToken, HistoryPath = Path.Combine(Root, "proxy.sqlite"),
            CollectAsync = _ => Task.FromResult(Fixture()), OnStarted = uri => ready.SetResult(uri), CloudActions = actions,
            RefreshInterval = TimeSpan.FromSeconds(60)
        }, shutdown.Token);
        try
        {
            var bootstrap = await ready.Task.WaitAsync(TimeSpan.FromSeconds(15));
            Assert(bootstrap.AbsoluteUri == PublicOrigin + "/" && bootstrap.Fragment.Length == 0, "Proxy bootstrap returns public HTTPS URL without secret fragment");
            using var client = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}"), Timeout = TimeSpan.FromSeconds(10) };
            async Task<HttpResponseMessage> Send(string path, bool authenticated = true, string? host = "opscope.example.test", string? origin = PublicOrigin, string? referer = null, string? fetch = "same-origin", string? forwarded = null, bool post = false)
            {
                using var request = new HttpRequestMessage(post ? HttpMethod.Post : HttpMethod.Get, path);
                request.Headers.Host = host;
                if (authenticated) request.Headers.Add("X-Opscope-Token", ProxyToken);
                if (origin is not null) request.Headers.Add("Origin", origin);
                if (referer is not null) request.Headers.Add("Referer", referer);
                if (fetch is not null) request.Headers.Add("Sec-Fetch-Site", fetch);
                if (forwarded is not null) { request.Headers.Add("X-Forwarded-Host", forwarded); request.Headers.Add("X-Forwarded-For", "198.51.100.5"); request.Headers.Add("X-Forwarded-Proto", "https"); }
                return await client.SendAsync(request);
            }
            using (var response = await Send("/api/session", false)) Assert(response.StatusCode == HttpStatusCode.Unauthorized, "Public origin alone does not authenticate upstream");
            using (var response = await Send("/api/session", host: "attacker.example.test", forwarded: "opscope.example.test")) Assert(response.StatusCode == HttpStatusCode.Forbidden, "Forwarded host cannot override exact Host check");
            using (var response = await Send("/api/session", origin: "https://attacker.example.test")) Assert(response.StatusCode == HttpStatusCode.Forbidden, "Foreign Origin is rejected despite upstream secret");
            using (var response = await Send("/api/session", referer: "https://attacker.example.test/page")) Assert(response.StatusCode == HttpStatusCode.Forbidden, "Foreign Referer is rejected");
            using (var response = await Send("/api/session", referer: "https://user@opscope.example.test/page")) Assert(response.StatusCode == HttpStatusCode.Forbidden, "Credential-bearing Referer is rejected");
            using (var response = await Send("/api/session", fetch: "cross-site")) Assert(response.StatusCode == HttpStatusCode.Forbidden, "Cross-site Fetch Metadata is rejected");
            using (var response = await Send("/api/session", host: "opscope.example.test:443")) Assert(response.StatusCode == HttpStatusCode.Forbidden, "Noncanonical Host is rejected");
            using (var response = await Send("/api/session", origin: null, fetch: null, forwarded: "attacker.example.test"))
            {
                Assert(response.IsSuccessStatusCode, "Authenticated nonbrowser proxy health request works; untrusted forwarded headers ignored");
                var text = await response.Content.ReadAsStringAsync();
                using var data = JsonDocument.Parse(text);
                Assert(data.RootElement.GetProperty("authenticationMode").GetString() == "proxy" && data.RootElement.GetProperty("authenticated").GetBoolean(), "Proxy session explicitly reports authentication mode");
                Assert(data.RootElement.EnumerateObject().Count() == 3 && !text.Contains(ProxyToken, StringComparison.Ordinal), "Session describes no credentials or identities");
                Assert(!response.Headers.Contains("Access-Control-Allow-Origin") && !response.Headers.Contains("Set-Cookie"), "Backend creates no CORS grant or browser auth cookie");
            }
            using (var response = await Send("/api/cloud/connections", false)) Assert(response.StatusCode == HttpStatusCode.Unauthorized, "Connections diagnostics remain protected");
            using (var response = await Send("/api/cloud/connections"))
            {
                var text = await response.Content.ReadAsStringAsync();
                using var data = JsonDocument.Parse(text);
                Assert(response.IsSuccessStatusCode && !data.RootElement.GetProperty("remoteRequestsMade").GetBoolean(), "Connections GET performs no provider calls");
                Assert(calls == 0 && !text.Contains(ProxyToken, StringComparison.Ordinal), "Diagnostics neither test access nor expose upstream secret");
                Assert(data.RootElement.GetProperty("providers").GetArrayLength() == 12, "Guided setup covers all supported clouds and Kubernetes");
            }
            using (var response = await Send("/api/openapi.json"))
            {
                using var data = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                Assert(data.RootElement.GetProperty("paths").TryGetProperty("/api/session", out _) && data.RootElement.GetProperty("paths").TryGetProperty("/api/cloud/connections", out _), "OpenAPI advertises protected session and connection endpoints");
                Assert(data.RootElement.GetProperty("paths").GetProperty("/api/cloud/{provider}/{operation}").GetProperty("post").GetProperty("responses").TryGetProperty("424", out _), "OpenAPI separates provider denial from Opscope auth failure");
            }
            for (var i = 0; i < definitions.Length; i++)
            {
                await Task.Delay(2050);
                using var response = await Send($"/api/cloud/azure-scope-{i + 1}/inventory", post: true);
                var text = await response.Content.ReadAsStringAsync();
                Assert(text.Length > 0, $"{definitions[i].State} produced a structured provider outcome, HTTP {(int)response.StatusCode}");
                using var data = JsonDocument.Parse(text);
                Assert((int)response.StatusCode == definitions[i].Status, $"{definitions[i].State} uses provider-specific HTTP status");
                Assert(data.RootElement.GetProperty("kind").GetString() == "cloud/azure/inventory" && data.RootElement.TryGetProperty("data", out _), "Provider outcome keeps existing report shape");
                Assert(data.RootElement.GetProperty("cloudProblem").GetProperty("code").GetString() == definitions[i].Code, "Fixed remediation metadata explains provider outcome");
                Assert(!text.Contains(ProxyToken, StringComparison.Ordinal), "Cloud report scrubs upstream token even if a callback reflects it");
                if (definitions[i].State == "Partial") Assert(data.RootElement.GetProperty("data").GetProperty("resourceCount").GetInt32() == 1, "Useful partial evidence is preserved even when overall operation did not succeed");
                using var session = await Send("/api/session");
                Assert(session.IsSuccessStatusCode, "Provider outcome does not end Opscope proxy session");
            }
            using (var response = await Send("/api/cloud/azure-scope-2/inventory", post: true))
            {
                Assert((int)response.StatusCode == 424 && response.Headers.GetValues("X-Opscope-Cache").Single() == "hit", "Cached denial retains provider status and metadata");
                Assert(calls == definitions.Length, "Cached provider results do not repeat remote reads");
            }
            using (var response = await Send("/api/settings")) Assert(!(await response.Content.ReadAsStringAsync()).Contains(ProxyToken, StringComparison.Ordinal), "Settings omit upstream token");
            using (var response = await Send("/api/snapshot")) Assert(!(await response.Content.ReadAsStringAsync()).Contains(ProxyToken, StringComparison.Ordinal), "Snapshot output omits upstream token");
            using (var response = await Send("/")) Assert(!response.Headers.Contains("Server") && !(await response.Content.ReadAsStringAsync()).Contains(ProxyToken, StringComparison.Ordinal), "HTML shell contains no upstream secret or server header");
        }
        finally { shutdown.Cancel(); try { await server; } catch (OperationCanceledException) { } }
    }

    private static async Task TestLocalSessionAsync()
    {
        using var shutdown = new CancellationTokenSource();
        var ready = new TaskCompletionSource<Uri>(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = LocalServer.RunAsync(new ServerOptions
        {
            HistoryPath = Path.Combine(Root, "local.sqlite"), CollectAsync = _ => Task.FromResult(Fixture()), OnStarted = uri => ready.SetResult(uri)
        }, shutdown.Token);
        try
        {
            var bootstrap = await ready.Task.WaitAsync(TimeSpan.FromSeconds(15));
            Assert(bootstrap.Host == "127.0.0.1" && bootstrap.Fragment.StartsWith("#token=", StringComparison.Ordinal), "Default local bootstrap retains loopback token fragment");
            using var client = new HttpClient { BaseAddress = new Uri(bootstrap.GetLeftPart(UriPartial.Authority)) };
            using (var denied = await client.GetAsync("/api/session")) Assert(denied.StatusCode == HttpStatusCode.Unauthorized, "Local session bootstrap cannot authenticate without token");
            client.DefaultRequestHeaders.Add("X-Opscope-Token", bootstrap.Fragment[7..]);
            using var response = await client.GetAsync("/api/session");
            using var data = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert(response.IsSuccessStatusCode && data.RootElement.GetProperty("authenticationMode").GetString() == "local", "Local mode is explicit and separate from proxy mode");
        }
        finally { shutdown.Cancel(); try { await server; } catch (OperationCanceledException) { } }
    }

    private static int FreePort() { using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); return ((IPEndPoint)listener.LocalEndpoint).Port; }
    private static Snapshot Fixture() => new(DateTimeOffset.UtcNow,
        new HostInfo("private-proxy-host", "Test OS", "Linux", "X64", ".NET 8", "kernel", DateTimeOffset.UtcNow.AddDays(-1), TimeSpan.FromDays(1), false, 2, "private-user"),
        5, new MemoryInfo(100, 50, 50, 50, "fixture"), [], [], [], [], [], new SecurityPosture([], false, false, 0), new ToolingPosture([]), [], [], TimeSpan.Zero);
    private static void Assert(bool condition, string message) { assertions++; if (!condition) throw new InvalidOperationException(message); }
}
