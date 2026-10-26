using System.Reflection;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Opscope;
using Opscope.Cloud;

var assertions = 0;
void Assert(bool value, string message) { if (!value) throw new InvalidOperationException(message); assertions++; }
static string Serialize(AnalysisReport report) => JsonSerializer.Serialize(report, ReportSecurity.JsonOptions);
var scopes = new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal)
{
    ["oci"] = new() { ["compartment"] = "ocid1.compartment.oc1..test", ["region"] = "eu-frankfurt-1" },
    ["digitalocean"] = new() { ["project"] = "11111111-1111-1111-1111-111111111111" },
    ["hetzner"] = new() { ["project"] = "authorized-project" },
    ["cloudflare"] = new() { ["account"] = new string('a', 32) },
    ["openstack"] = new() { ["cloud-name"] = "private-readonly", ["project"] = "authorized-project", ["region"] = "RegionOne" },
    ["alibaba"] = new() { ["account"] = "123456", ["region"] = "eu-central-1" },
    ["ibm"] = new() { ["account"] = "ibmaccount", ["resource-group"] = "authorizedgroup", ["region"] = "eu-de" },
    ["scaleway"] = new() { ["project"] = "11111111-1111-1111-1111-111111111111", ["zone"] = "fr-par-1" }
};
foreach (var (id, options) in scopes)
{
    var runner = new FixtureRunner();
    var provider = AdditionalCloudProviders.Create(id, runner);
    var inventory = await provider.CollectAsync("inventory", options);
    Assert(inventory.OperationSucceeded, id + " bounded inventory succeeds");
    Assert(Serialize(inventory).Contains("partial", StringComparison.Ordinal), id + " reports narrow coverage explicitly");
    Assert(!Serialize(inventory).Contains("SECRET_FIELD", StringComparison.Ordinal), id + " arbitrary provider fields are excluded");
    Assert(!ReportSecurity.Serialize(inventory).Contains("resource-private", StringComparison.Ordinal), id + " HTTP/export redacts resource names and IDs");
    Assert(runner.Calls.Count > 0, id + " inventory makes real configured reads");
    var health = await provider.CollectAsync("health", options);
    Assert(health.OperationSucceeded, id + " health observes control-plane states");
    runner.Calls.Clear();
    var unsupported = await provider.CollectAsync("delete", options);
    Assert(!unsupported.OperationSucceeded && Serialize(unsupported).Contains("unsupported", StringComparison.Ordinal) && runner.Calls.Count == 0, id + " unsupported operation makes no call");
    var unconfigured = await provider.CollectAsync("inventory", new Dictionary<string, string>());
    Assert(!unconfigured.OperationSucceeded && Serialize(unconfigured).Contains("not_configured", StringComparison.Ordinal) && runner.Calls.Count == 0, id + " missing scope makes no call");
    runner.Failure = new AdditionalCloudQueryException("permission_denied", "SECRET_FIELD");
    var denied = await provider.CollectAsync("inventory", options);
    Assert(!denied.OperationSucceeded && Serialize(denied).Contains("permission_denied", StringComparison.Ordinal) && !Serialize(denied).Contains("SECRET_FIELD", StringComparison.Ordinal), id + " denied is not empty success and raw errors are omitted");
    runner.Failure = new AdditionalCloudQueryException("rate_limited", "SECRET_FIELD");
    runner.Calls.Clear();
    var limited = await provider.CollectAsync("inventory", options);
    Assert(!limited.OperationSucceeded && runner.Calls.Count == 1 && Serialize(limited).Contains("rate_limited", StringComparison.Ordinal), id + " throttling stops without retries");
    runner.Failure = null;
    runner.Malformed = true;
    var malformed = await provider.CollectAsync("inventory", options);
    Assert(!malformed.OperationSucceeded, id + " malformed response never establishes empty inventory");
    using var cancellation = new CancellationTokenSource();
    cancellation.Cancel();
    runner.Calls.Clear();
    try { await provider.CollectAsync("inventory", options, cancellation.Token); throw new Exception("Expected cancellation."); }
    catch (OperationCanceledException) { Assert(runner.Calls.Count == 0, id + " caller cancellation propagates before query"); }
}
foreach (var id in new[] { "oci", "digitalocean", "hetzner", "openstack" })
{
    var report = await AdditionalCloudProviders.Create(id, new FixtureRunner()).CollectAsync("posture", scopes[id]);
    Assert(report.OperationSucceeded && report.Findings.Any(f => f.Code.EndsWith("WORLD_INGRESS", StringComparison.Ordinal)), id + " posture is based on observed global ingress configuration");
}
foreach (var (provider, code) in new[] { ("cloudflare", "CLOUDFLARE_ZONE_PAUSED"), ("alibaba", "ALIBABA_DISK_UNENCRYPTED") })
{
    var report = await AdditionalCloudProviders.Create(provider, new FixtureRunner()).CollectAsync("posture", scopes[provider]);
    Assert(report.OperationSucceeded && report.Findings.Any(f => f.Code == code), provider + " posture interprets explicit configuration evidence only");
}
var paged = new FixtureRunner { Paged = true };
var pagedReport = await AdditionalCloudProviders.Create("hetzner", paged).CollectAsync("inventory", scopes["hetzner"]);
Assert(pagedReport.OperationSucceeded && paged.Calls.Any(c => c.Tool == "hetzner-api" && c.Args[2] == "2"), "Hetzner follows bounded provider pagination");
var metrics = await AdditionalCloudProviders.Create("hetzner", new FixtureRunner()).CollectAsync("metrics", scopes["hetzner"]);
Assert(metrics.OperationSucceeded && Serialize(metrics).Contains("periodSeconds", StringComparison.Ordinal) && Serialize(metrics).Contains("12.5", StringComparison.Ordinal), "Hetzner CPU preserves real timestamp, unit and granularity");
Assert(!Serialize(metrics).Contains("NaN", StringComparison.Ordinal), "Invalid numeric metrics are omitted");
var doMetrics = await AdditionalCloudProviders.Create("digitalocean", new FixtureRunner()).CollectAsync("metrics", scopes["digitalocean"]);
Assert(doMetrics.OperationSucceeded && Serialize(doMetrics).Contains("cumulative_counter", StringComparison.Ordinal) && Serialize(doMetrics).Contains("123.5", StringComparison.Ordinal), "DigitalOcean CPU preserves native counter units and labels rather than inventing percent");
foreach (var id in new[] { "digitalocean", "hetzner" })
{
    var boundedTime = await AdditionalCloudProviders.Create(id, new FixtureRunner { OutOfWindowMetrics = true }).CollectAsync("metrics", scopes[id]);
    using var result = JsonDocument.Parse(Serialize(boundedTime));
    var samples = result.RootElement.GetProperty("data").GetProperty("metrics")[0].GetProperty("samples");
    Assert(!boundedTime.OperationSucceeded && Serialize(boundedTime).Contains("timestamp", StringComparison.Ordinal) && Serialize(boundedTime).Contains("partial", StringComparison.Ordinal), id + " rejects stale and future provider timestamps with explicit incomplete coverage");
    Assert(samples.GetArrayLength() == 1 && samples[0].GetProperty("timestampUtc").GetDateTimeOffset().Ticks % TimeSpan.TicksPerSecond == TimeSpan.TicksPerSecond / 2, id + " retains the genuine in-window fractional sample without fabricating time");
}
var oversizedMetrics = await AdditionalCloudProviders.Create("digitalocean", new FixtureRunner { LargeMetrics = true }).CollectAsync("metrics", scopes["digitalocean"]);
using (var result = JsonDocument.Parse(Serialize(oversizedMetrics)))
{
    var totalPoints = result.RootElement.GetProperty("data").GetProperty("metrics").EnumerateArray().Sum(series => series.GetProperty("samples").GetArrayLength());
    Assert(totalPoints <= 10000 && !oversizedMetrics.OperationSucceeded && Serialize(oversizedMetrics).Contains("budget", StringComparison.Ordinal), "DigitalOcean enforces a whole-collection 10000-point budget across modes/cores");
}
var noData = await AdditionalCloudProviders.Create("hetzner", new FixtureRunner { NoMetrics = true }).CollectAsync("metrics", scopes["hetzner"]);
Assert(noData.OperationSucceeded && Serialize(noData).Contains("no_data", StringComparison.Ordinal), "Empty metric series are unavailable rather than zero");
var mismatch = await AdditionalCloudProviders.Create("openstack", new FixtureRunner { WrongIdentity = true }).CollectAsync("inventory", scopes["openstack"]);
Assert(!mismatch.OperationSucceeded && Serialize(mismatch).Contains("permission_denied", StringComparison.Ordinal), "OpenStack verifies authenticated project before inventory");
var invalid = new FixtureRunner();
await AdditionalCloudProviders.Create("cloudflare", invalid).CollectAsync("inventory", new Dictionary<string,string> { ["account"] = new string('a',32), ["zones"] = "https://127.0.0.1" });
Assert(invalid.Calls.Count == 0, "Invalid zone scope makes no remote query");
var validation = typeof(AdditionalCloudCommandRunner).GetMethod("ValidateArguments", BindingFlags.NonPublic | BindingFlags.Static)!;
foreach (var (tool, commandArgs) in new[]
{
    ("oci", new[] { "compute", "instance", "terminate", "--instance-id", "private" }),
    ("openstack", new[] { "server", "list", "--os-auth-url", "https://127.0.0.1" }),
    ("gcloud", new[] { "compute", "instances", "list", "--configuration", "evil" }),
    ("aliyun", new[] { "ecs", "DescribeInstances", "--endpoint", "http://169.254.169.254" }),
    ("ibmcloud", new[] { "target", "--account", "other" }),
    ("ibmcloud", new[] { "target", "--resource-group-name", "other" }),
    ("scw", new[] { "instance", "server", "list", "api-url=http://localhost" })
})
{
    try { validation.Invoke(null, [tool, commandArgs]); throw new Exception("Expected command rejection."); }
    catch (TargetInvocationException ex) when (ex.InnerException is InvalidOperationException or ArgumentException) { Assert(true, tool + " mutation/endpoint override rejected"); }
}
var transportConstructor = typeof(AdditionalCloudCommandRunner).GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null, [typeof(HttpMessageHandler), typeof(Func<string, string?>)], null)!;
var httpHandler = new FixedHandler();
var transport = (AdditionalCloudCommandRunner)transportConstructor.Invoke([httpHandler, (Func<string, string?>)(_ => "fixture-credential")]);
await transport.RunAsync("hetzner-api", ["servers", "configured", "1"], CancellationToken.None);
Assert(httpHandler.Requests.Count == 1 && httpHandler.Requests[0].Host == "api.hetzner.cloud" && httpHandler.Methods.All(m => m == HttpMethod.Get), "REST transport only constructs fixed-host GET queries");
foreach (var (status, expected) in new[] { (HttpStatusCode.Forbidden, "permission_denied"), (HttpStatusCode.TooManyRequests, "rate_limited"), (HttpStatusCode.Redirect, "failed") })
{
    httpHandler.Status = status;
    var previous = httpHandler.Requests.Count;
    try { await transport.RunAsync("digitalocean-api", ["droplets", "configured", "1"], CancellationToken.None); throw new Exception("Expected classified status failure."); }
    catch (AdditionalCloudQueryException ex) { Assert(ex.State == expected && httpHandler.Requests.Count == previous + 1 && !ex.Message.Contains("fixture-credential", StringComparison.Ordinal), "HTTP status is classified without following redirects or retrying"); }
}
httpHandler.Status = HttpStatusCode.OK;
await transport.RunAsync("scaleway-api", ["servers", "11111111-1111-1111-1111-111111111111@fr-par-1", "1"], CancellationToken.None);
Assert(httpHandler.Requests[^1].Host == "api.scaleway.com" && httpHandler.Requests[^1].AbsolutePath == "/instance/v1/zones/fr-par-1/servers" && httpHandler.Requests[^1].Query.Contains("project=11111111-1111-1111-1111-111111111111", StringComparison.Ordinal), "Scaleway REST query uses actual project selector and bounded pagination");
await transport.RunAsync("ibm-api", ["resources-active", "ibmaccount@authorizedgroup", "1"], CancellationToken.None);
Assert(httpHandler.Requests[^1].Host == "resource-controller.cloud.ibm.com" && httpHandler.Requests[^1].AbsolutePath == "/v2/resource_instances" && httpHandler.Requests[^1].Query.Contains("resource_group_id=authorizedgroup", StringComparison.Ordinal), "IBM uses verified Resource Controller query with explicit authorized group");
var badCredentialTransport = (AdditionalCloudCommandRunner)transportConstructor.Invoke([httpHandler, (Func<string, string?>)(_ => "invalid\r\ncredential")]);
var requestsBeforeBadCredential = httpHandler.Requests.Count;
try { await badCredentialTransport.RunAsync("hetzner-api", ["servers", "configured", "1"], CancellationToken.None); throw new Exception("Expected credential validation."); }
catch (AdditionalCloudQueryException ex) { Assert(ex.State == "not_configured" && httpHandler.Requests.Count == requestsBeforeBadCredential, "Invalid credential header is rejected safely before network access"); }
httpHandler.Oversized = true;
try { await transport.RunAsync("hetzner-api", ["servers", "configured", "1"], CancellationToken.None); throw new Exception("Expected byte limit."); }
catch (AdditionalCloudQueryException ex) { Assert(ex.State == "partial", "Declared oversized content fails its byte budget"); }
httpHandler.Oversized = false;
try { await transport.RunAsync("cloudflare-api", ["zones", "http://127.0.0.1", "1"], CancellationToken.None); throw new Exception("Expected endpoint rejection."); }
catch (InvalidOperationException) { Assert(true, "Untrusted scope cannot become a URL or endpoint override"); }
Console.WriteLine($"Multicloud regression checks passed ({assertions}).");

sealed class FixtureRunner : ICloudCommandRunner
{
    public List<(string Tool, string[] Args)> Calls { get; } = [];
    public Exception? Failure { get; set; }
    public bool Malformed { get; set; }
    public bool Paged { get; set; }
    public bool NoMetrics { get; set; }
    public bool WrongIdentity { get; set; }
    public bool LargeMetrics { get; set; }
    public bool OutOfWindowMetrics { get; set; }
    public Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> args, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!tool.EndsWith("-api", StringComparison.Ordinal))
            typeof(AdditionalCloudCommandRunner).GetMethod("ValidateArguments", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, [tool, args]);
        Calls.Add((tool, args.ToArray()));
        if (Failure is not null) throw Failure;
        if (Malformed) return Parse("{}");
        var command = string.Join(' ', args.Take(3));
        if (tool == "oci") return Parse("""{"data":[{"id":"resource-private","display-name":"resource-private-name","lifecycle-state":"RUNNING","ingress-security-rules":[{"source":"0.0.0.0/0"}],"secret":"SECRET_FIELD"}]}""");
        if (tool == "digitalocean-api" && args[0] == "cpu-metrics" && LargeMetrics)
            return Parse(JsonSerializer.Serialize(new { status = "success", data = new { resultType = "matrix", result = Enumerable.Range(0, 32).Select(core => new { metric = new { cpu = core.ToString(), mode = "idle" }, values = Enumerable.Range(0, 720).Select(point => new object[] { DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 3599 + point * 5, "123.5" }) }) } }));
        if (tool == "digitalocean-api") return args[0] switch
        {
            "cpu-metrics" => Parse(JsonSerializer.Serialize(new { status = "success", data = new { resultType = "matrix", result = new[] { new { metric = new { cpu = "0", mode = "idle" }, values = CpuValues("123.5") } } } })),
            "project-resources" => Parse("""{"resources":[{"urn":"do:droplet:7"},{"urn":"do:volume:resource-private"}],"links":{}}"""),
            "droplets" => Parse("""{"droplets":[{"id":7,"name":"resource-private-name","status":"active","region":{"slug":"fra1"},"secret":"SECRET_FIELD"}],"links":{}}"""),
            "volumes" => Parse("""{"volumes":[{"id":"resource-private","name":"resource-private-name","size_gigabytes":10}],"links":{}}"""),
            _ => Parse("""{"firewalls":[{"id":"resource-private","name":"resource-private-name","droplet_ids":[7],"inbound_rules":[{"sources":{"addresses":["0.0.0.0/0"]}}]}],"links":{}}""")
        };
        if (tool == "hetzner-api")
        {
            if (args[0] == "cpu-metrics") return Parse(JsonSerializer.Serialize(new { metrics = new { step = 60.0, time_series = new { cpu = new { values = NoMetrics ? System.Array.Empty<object[]>() : CpuValues("12.5") } } } }));
            var next = Paged && args[0] == "servers" && args[2] == "1" ? "2" : "null";
            return Parse("{\"" + args[0] + "\":[{\"id\":7,\"name\":\"resource-private-name\",\"status\":\"running\",\"rules\":[{\"direction\":\"in\",\"source_ips\":[\"::/0\"]}],\"secret\":\"SECRET_FIELD\"}],\"meta\":{\"pagination\":{\"next_page\":" + next + "}}}");
        }
        if (tool == "cloudflare-api") return Parse("""{"success":true,"result":[{"id":"resource-private","name":"resource-private-name","account":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"status":"active","paused":true,"secret":"SECRET_FIELD"}],"result_info":{"total_pages":1}}""");
        if (tool == "openstack") return args[0] == "token" ? Parse(WrongIdentity ? """{"project_id":"other"}""" : """{"project_id":"authorized-project"}""") : Parse("""[{"ID":"resource-private","Name":"resource-private-name","Status":"ACTIVE","Direction":"ingress","IP Range":"::/0","secret":"SECRET_FIELD"}]""");
        if (tool == "aliyun")
        {
            if (args[0] == "sts") return Parse("""{"AccountId":"123456"}""");
            return args[1] switch
            {
                "DescribeInstances" => Parse("""{"TotalCount":1,"Instances":{"Instance":[{"InstanceId":"resource-private","InstanceName":"resource-private-name","Status":"Running","secret":"SECRET_FIELD"}]}}"""),
                "DescribeDisks" => Parse("""{"TotalCount":1,"Disks":{"Disk":[{"DiskId":"resource-private","DiskName":"resource-private-name","Status":"In_use","Encrypted":false}]}}"""),
                _ => Parse("""{"TotalCount":1,"Vpcs":{"Vpc":[{"VpcId":"resource-private","VpcName":"resource-private-name"}]}}""")
            };
        }
        if (tool == "ibm-api") return Parse("""{"resources":[{"id":"resource-private","name":"resource-private-name","account_id":"ibmaccount","resource_group_id":"authorizedgroup","region_id":"eu-de","state":"active","secret":"SECRET_FIELD"}]}""");
        if (tool == "scaleway-api") return Parse("{\"" + args[0] + "\":[{\"id\":\"resource-private\",\"name\":\"resource-private-name\",\"state\":\"running\",\"secret\":\"SECRET_FIELD\"}]}");
        throw new InvalidOperationException("Unexpected fixture command: " + command);
    }
    private object[][] CpuValues(string value)
    {
        var end = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var values = new List<object[]> { new object[] { end - 120 + .5, value }, new object[] { end - 60, "NaN" } };
        if (OutOfWindowMetrics)
        {
            values.Add([end - 7200, value]);
            values.Add([end + 3600, value]);
        }
        return values.ToArray();
    }
    static Task<JsonElement> Parse(string json) { using var document = JsonDocument.Parse(json); return Task.FromResult(document.RootElement.Clone()); }
}

sealed class FixedHandler : HttpMessageHandler
{
    public List<Uri> Requests { get; } = [];
    public List<HttpMethod> Methods { get; } = [];
    public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;
    public bool Oversized { get; set; }
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request.RequestUri!);
        Methods.Add(request.Method);
        var response = new HttpResponseMessage(Status) { Content = new StringContent("{\"servers\":[],\"meta\":{\"pagination\":{\"next_page\":null}}}") };
        if (Oversized) response.Content.Headers.ContentLength = 9 * 1024 * 1024;
        response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromMinutes(1));
        response.Headers.Location = new Uri("http://127.0.0.1/private");
        return Task.FromResult(response);
    }
}
