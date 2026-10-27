using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using Opscope;
using Opscope.Cloud;

var assertions = 0;
var now = DateTimeOffset.UtcNow.AddMinutes(-3);
const string Compartment = "ocid1.compartment.oc1..authorizedcompartment";
const string Instance = "ocid1.instance.oc1..privateinstance";
const string Project = "11111111-1111-1111-1111-111111111111";
const string Resource = "22222222-2222-2222-2222-222222222222";
const string CpuMetric = "33333333-3333-3333-3333-333333333333";
const string MemoryMetric = "44444444-4444-4444-4444-444444444444";
const string Account = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const string Zone = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const string OtherZone = "cccccccccccccccccccccccccccccccc";
var ociOptions = new Dictionary<string, string> { ["compartment"] = Compartment, ["region"] = "eu-frankfurt-1", ["profile"] = "reader" };
var stackOptions = new Dictionary<string, string> { ["cloud-name"] = "reader-cloud", ["project"] = Project, ["region"] = "RegionOne" };
var edgeOptions = new Dictionary<string, string> { ["account"] = Account, ["zones"] = Zone };
var never = new FakeRunner((_, _) => throw new Exception("Unexpected provider request"));

var oci = new FakeRunner((tool, args) =>
{
    Check(tool == "oci" && args.Contains(Compartment) && args.Contains("CpuUtilization[1m].mean()"), "OCI query uses fixed CPU read in selected compartment");
    SupplementalCloudMetricsCommandRunnerA.Validate(tool, args);
    return OciRows(Compartment, new object[] { new { timestamp = now, value = 0 }, new { timestamp = now.AddMinutes(1), value = 25 } });
});
var ociReport = await SupplementalCloudMetricsA.CollectAsync("oci", ociOptions, oci);
Check(ociReport.OperationSucceeded && State(ociReport) == "Complete", "Scoped OCI metric read completes");
var ociSeries = Data(ociReport).GetProperty("metrics")[0];
Check(ociSeries.GetProperty("unit").GetString() == "percent" && ociSeries.GetProperty("samplingPeriodSeconds").GetInt32() == 60, "OCI preserves percent units and one-minute means");
Check(ociSeries.GetProperty("points")[0].GetProperty("value").GetDouble() == 0, "Genuine OCI zero is retained");
var safeOci = ReportSecurity.Serialize(ociReport);
Check(!safeOci.Contains(Compartment, StringComparison.Ordinal) && !safeOci.Contains(Instance, StringComparison.Ordinal), "OCI report redacts scope and resource IDs");

foreach (var mismatch in new[] { "", "ocid1.compartment.oc1..anothercompartment" })
{
    var result = await SupplementalCloudMetricsA.CollectAsync("oci", ociOptions, new FakeRunner((_, _) => OciRows(mismatch, new[] { new { timestamp = now, value = 5 } })));
    Check(State(result) == "Partial" && Points(result) == 0, "OCI rows must establish selected compartment ownership");
}
var invalidTimes = await SupplementalCloudMetricsA.CollectAsync("oci", ociOptions,
    new FakeRunner((_, _) => OciRows(Compartment, new object[] { new { timestamp = now.AddHours(-4), value = 50 }, new { timestamp = now.AddHours(3), value = 50 }, new { timestamp = now, value = 101 }, new { timestamp = now.AddSeconds(1), value = 12.5 } })));
Check(State(invalidTimes) == "Partial" && Points(invalidTimes) == 1, "OCI excludes stale, future and out-of-range samples without inventing values");
var bounded = await SupplementalCloudMetricsA.CollectAsync("oci", ociOptions,
    new FakeRunner((_, _) => OciRows(Compartment, Enumerable.Range(0, 10020).Select(i => new { timestamp = now.AddMinutes(-30).AddMilliseconds(i * 100), value = 30 }).ToArray())));
Check(State(bounded) == "Partial" && Points(bounded) == 10000, "OCI aggregate metric retention is capped at ten thousand observations");
var emptyOci = await SupplementalCloudMetricsA.CollectAsync("oci", ociOptions, new FakeRunner((_, _) => Json(new { data = Array.Empty<object>() })));
Check(emptyOci.OperationSucceeded && Data(emptyOci).GetProperty("dataStatus").GetString() == "no_data" && Points(emptyOci) == 0, "Empty telemetry remains no_data rather than a zero series");
var noConfig = await SupplementalCloudMetricsA.CollectAsync("oci", new Dictionary<string, string>(), never);
Check(State(noConfig) == "NotConfigured" && never.Calls.Count == 0, "Missing OCI configuration performs no query");
var failed = await SupplementalCloudMetricsA.CollectAsync("oci", ociOptions, new FakeRunner((_, _) => throw new IOException("SECRET_PROVIDER_BODY")));
Check(!failed.OperationSucceeded && !ReportSecurity.Serialize(failed).Contains("SECRET_PROVIDER_BODY", StringComparison.Ordinal), "CLI failure omits raw remote exception text");

var stack = StackRunner();
var stackReport = await SupplementalCloudMetricsA.CollectAsync("openstack", stackOptions, stack);
Check(stackReport.OperationSucceeded && Points(stackReport) == 4, "Owned Gnocchi resources yield CPU and memory observations");
Check(Data(stackReport).GetProperty("metrics")[0].GetProperty("unit").GetString() == "ns" && Data(stackReport).GetProperty("metrics")[1].GetProperty("unit").GetString() == "MiB", "Gnocchi cumulative CPU and memory preserve native units");
Check(stack.Calls.Any(call => call.Arguments.Contains("project_id=\"" + Project + "\"")) && stack.Calls.All(call => !call.Arguments.Contains("--refresh")), "Gnocchi resource search is project-scoped and never refreshes aggregation");
var deniedIdentity = await SupplementalCloudMetricsA.CollectAsync("openstack", stackOptions, StackRunner(wrongIdentity: true));
Check(State(deniedIdentity) == "PermissionDenied" && Points(deniedIdentity) == 0, "OpenStack token project must match authorized scope");
var wrongResource = StackRunner(wrongMetricOwner: true);
var deniedMetric = await SupplementalCloudMetricsA.CollectAsync("openstack", stackOptions, wrongResource);
Check(State(deniedMetric) == "Partial" && Points(deniedMetric) == 0 && !wrongResource.Calls.Any(call => call.Arguments.Take(3).SequenceEqual(new[] { "metric", "measures", "show" })), "Gnocchi metric ownership is checked before reading measures");
var badGrain = await SupplementalCloudMetricsA.CollectAsync("openstack", stackOptions, StackRunner(granularity: 300));
Check(State(badGrain) == "Partial" && Points(badGrain) == 0, "Different provider granularity is not relabelled as a minute");
var repeatedResources = StackRunner(repeatedPages: true);
var repeated = await SupplementalCloudMetricsA.CollectAsync("openstack", stackOptions, repeatedResources);
Check(State(repeated) == "Partial" && repeatedResources.Calls.Count <= 60, "Repeated Gnocchi resource pages stop within the read budget");
var safeStack = ReportSecurity.Serialize(stackReport);
Check(!safeStack.Contains(Project, StringComparison.Ordinal) && !safeStack.Contains(Resource, StringComparison.Ordinal), "Gnocchi report redacts project and VM identity");

using var edgeHandler = new FakeHandler(request => request.Method == HttpMethod.Get ? OwnedZone(Zone, Account) : EdgeResponse(Zone, now));
using var edgeHttp = new HttpClient(edgeHandler);
var edge = await SupplementalCloudMetricsA.CollectForTestAsync("cloudflare", edgeOptions, never, edgeHttp, _ => "fixture-access-token");
Check(edge.OperationSucceeded && Points(edge) == 3 && Data(edge).GetProperty("metrics").GetArrayLength() == 3, "Cloudflare returns separate request, byte and cached-request observations");
Check(Data(edge).GetProperty("metrics")[0].GetProperty("samplingPeriodSeconds").GetInt32() == 300 && Data(edge).GetProperty("metrics")[1].GetProperty("unit").GetString() == "bytes", "Cloudflare keeps five-minute sums and bandwidth units");
Check(edgeHandler.Requests.Count == 2 && edgeHandler.Requests[0].Method == HttpMethod.Get && edgeHandler.Requests[1].Method == HttpMethod.Post && edgeHandler.Requests.All(r => r.Uri.Host == "api.cloudflare.com"), "Cloudflare verifies ownership before a fixed-host analytics read");
using (var query = JsonDocument.Parse(edgeHandler.Requests[1].Body!))
{
    Check(query.RootElement.GetProperty("query").GetString() == SupplementalCloudMetricsA.EdgeQuery && !SupplementalCloudMetricsA.EdgeQuery.Contains("mutation", StringComparison.Ordinal), "Only the fixed read-only GraphQL document can be sent");
    Check(query.RootElement.GetProperty("variables").GetProperty("zoneTag").GetString() == Zone, "Analytics variables retain the authorized zone");
}
Check(!ReportSecurity.Serialize(edge).Contains(Zone, StringComparison.Ordinal), "Cloudflare zone IDs do not enter redacted reports");
using var wrongZoneHandler = new FakeHandler(_ => OwnedZone(Zone, "dddddddddddddddddddddddddddddddd"));
using var wrongZoneHttp = new HttpClient(wrongZoneHandler);
var wrongZone = await SupplementalCloudMetricsA.CollectForTestAsync("cloudflare", edgeOptions, never, wrongZoneHttp, _ => "fixture-token");
Check(State(wrongZone) == "PermissionDenied" && wrongZoneHandler.Requests.Count == 1, "Cloudflare account mismatch prevents analytics query");
foreach (var status in new[] { HttpStatusCode.Forbidden, HttpStatusCode.TooManyRequests, HttpStatusCode.Redirect })
{
    using var handler = new FakeHandler(_ => new(status) { Headers = { Location = new("https://untrusted.invalid/") }, Content = new StringContent("SECRET_REMOTE_TEXT") });
    using var http = new HttpClient(handler);
    var result = await SupplementalCloudMetricsA.CollectForTestAsync("cloudflare", new Dictionary<string, string>(edgeOptions) { ["zones"] = Zone + "," + OtherZone }, never, http, _ => "fixture-token");
    Check(State(result) == (status == HttpStatusCode.Forbidden ? "PermissionDenied" : status == HttpStatusCode.TooManyRequests ? "RateLimited" : "Failed") && !ReportSecurity.Serialize(result).Contains("SECRET_REMOTE_TEXT", StringComparison.Ordinal), "Cloudflare HTTP failure preserves safe explicit status " + status);
    Check(handler.Requests.All(request => request.Uri.Host == "api.cloudflare.com") && (status != HttpStatusCode.TooManyRequests || handler.Requests.Count == 1), "Cloudflare never follows redirects or retries rate-limited scopes");
}
using var bigHandler = new FakeHandler(_ => new(HttpStatusCode.OK) { Content = new StringContent(new string('x', 2 * 1024 * 1024 + 1)) });
using var bigHttp = new HttpClient(bigHandler);
Check(State(await SupplementalCloudMetricsA.CollectForTestAsync("cloudflare", edgeOptions, never, bigHttp, _ => "fixture-token")) == "Partial", "Cloudflare response byte bound is explicit incomplete coverage");
using var noTokenHandler = new FakeHandler(_ => throw new Exception("Credential validation must precede network"));
using var noTokenHttp = new HttpClient(noTokenHandler);
var badToken = await SupplementalCloudMetricsA.CollectForTestAsync("cloudflare", edgeOptions, never, noTokenHttp, _ => "bad\r\ntoken");
Check(State(badToken) == "NotConfigured" && noTokenHandler.Requests.Count == 0, "Invalid credential headers never reach HTTP");
using var futureHandler = new FakeHandler(request => request.Method == HttpMethod.Get ? OwnedZone(Zone, Account) : EdgeResponse(Zone, now.AddHours(3)));
using var futureHttp = new HttpClient(futureHandler);
Check(State(await SupplementalCloudMetricsA.CollectForTestAsync("cloudflare", edgeOptions, never, futureHttp, _ => "fixture-token")) == "Partial", "Cloudflare future timestamps cannot appear fresh");

using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
try { await SupplementalCloudMetricsA.CollectAsync("oci", ociOptions, new FakeRunner((_, _) => Json(new { data = Array.Empty<object>() })), cancelled.Token); throw new Exception("Cancellation was swallowed"); }
catch (OperationCanceledException) { Check(true, "Upstream cancellation remains cancellation"); }
foreach (var request in new[]
{
    new[] { "token", "issue" },
    new[] { "metric", "measures", "show", CpuMetric, "--refresh" },
    new[] { "metric", "resource", "delete", Resource },
    new[] { "metric", "resource", "search", "project_id=\"" + Project + "\"", "--os-auth-url", "https://untrusted.invalid/" }
}) Reject(() => SupplementalCloudMetricsCommandRunnerA.Validate("openstack", request), "Unsafe or unscoped Gnocchi grammar is rejected");
Reject(() => SupplementalCloudMetricsCommandRunnerA.Validate("oci", ["monitoring", "metric-data", "summarize-metrics-data"]), "Unscoped OCI telemetry is rejected");
Reject(() => SupplementalCloudMetricsCommandRunnerA.Validate("openstack", new[] { "metric", "resource", "search", "project_id=\"" + Resource + "\"", "--type", "instance", "--limit", "20", "--os-cloud", "reader", "--os-project-id", Project, "--os-region-name", "RegionOne", "-f", "json" }), "Gnocchi search cannot select a different project than its CLI identity");
Console.WriteLine($"PASS: {assertions} supplemental OCI, Gnocchi and Cloudflare telemetry checks.");

void Check(bool condition, string message) { assertions++; if (!condition) throw new InvalidOperationException(message); }
void Reject(Action action, string message) { try { action(); throw new Exception("Unsafe grammar accepted"); } catch (Exception error) when (error is InvalidOperationException or ArgumentException) { Check(true, message); } }
static JsonElement Json(object data) => JsonSerializer.SerializeToElement(data);
static JsonElement Data(AnalysisReport report) => JsonSerializer.SerializeToElement(report.Data, ReportSecurity.JsonOptions);
static string State(AnalysisReport report) => Data(report).GetProperty("coverage").GetProperty("state").GetString()!;
static int Points(AnalysisReport report) => Data(report).GetProperty("metrics").EnumerateArray().Sum(s => s.GetProperty("points").GetArrayLength());
static JsonElement OciRows(string compartment, object points) => Json(new { data = new[] { new Dictionary<string, object> { ["compartment-id"] = compartment, ["name"] = "CpuUtilization", ["namespace"] = "oci_computeagent", ["dimensions"] = new { resourceId = Instance }, ["aggregated-datapoints"] = points } } });
FakeRunner StackRunner(bool wrongIdentity = false, bool wrongMetricOwner = false, double granularity = 60, bool repeatedPages = false) => new((tool, args) =>
{
    SupplementalCloudMetricsCommandRunnerA.Validate(tool, args);
    if (args.Take(2).SequenceEqual(new[] { "token", "issue" })) return Json(new { project_id = wrongIdentity ? Resource : Project });
    if (args.Take(3).SequenceEqual(new[] { "metric", "resource", "search" })) return Json(Enumerable.Repeat(new { id = Resource, project_id = Project }, repeatedPages ? 20 : 1).ToArray());
    if (args.Take(3).SequenceEqual(new[] { "metric", "resource", "show" })) return Json(new { id = Resource, project_id = Project, metrics = new Dictionary<string, string> { ["cpu"] = CpuMetric, ["memory.usage"] = MemoryMetric } });
    if (args.Take(2).SequenceEqual(new[] { "metric", "show" })) return Json(new Dictionary<string, object> { ["id"] = args[2], ["name"] = args[2] == CpuMetric ? "cpu" : "memory.usage", ["unit"] = args[2] == CpuMetric ? "ns" : "MiB", ["resource/id"] = wrongMetricOwner ? Project : Resource, ["resource/project_id"] = Project });
    if (args.Take(3).SequenceEqual(new[] { "metric", "measures", "show" })) return Json(new[] { new { timestamp = now, granularity, value = 0 }, new { timestamp = now.AddSeconds(60), granularity, value = 1048576 } });
    throw new InvalidOperationException("Unexpected Gnocchi command");
});
static HttpResponseMessage OwnedZone(string zone, string account) => new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(new { success = true, result = new { id = zone, account = new { id = account } } }), Encoding.UTF8, "application/json") };
static HttpResponseMessage EdgeResponse(string zone, DateTimeOffset time) => new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(new { data = new { viewer = new { zones = new[] { new { zoneTag = zone, httpRequests1mGroups = new[] { new { dimensions = new { datetimeFiveMinutes = time }, sum = new { requests = 0, bytes = 1048576, cachedRequests = 4 } } } } } } } }), Encoding.UTF8, "application/json") };

sealed class FakeRunner(Func<string, IReadOnlyList<string>, JsonElement> response) : ICloudCommandRunner
{
    public List<(string Tool, IReadOnlyList<string> Arguments)> Calls { get; } = [];
    public Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> args, CancellationToken ct) { ct.ThrowIfCancellationRequested(); Calls.Add((tool, args.ToArray())); return Task.FromResult(response(tool, args)); }
}
sealed class FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
{
    public List<(HttpMethod Method, Uri Uri, string? Body)> Requests { get; } = [];
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    { ct.ThrowIfCancellationRequested(); Requests.Add((request.Method, request.RequestUri!, request.Content is null ? null : await request.Content.ReadAsStringAsync(ct))); return response(request); }
}
