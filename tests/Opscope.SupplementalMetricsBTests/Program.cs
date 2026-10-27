using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using Opscope;
using Opscope.Cloud;

var checks = 0;
const string Monitoring = "11111111-1111-1111-1111-111111111111";
const string Project = "22222222-2222-2222-2222-222222222222";
const string Source = "33333333-3333-3333-3333-333333333333";
var now = DateTimeOffset.UtcNow;
var aliOptions = new Dictionary<string, string> { ["account"] = "123456789012", ["region"] = "cn-hangzhou", ["profile"] = "reader" };
var ibmOptions = new Dictionary<string, string> { ["account"] = "privateaccount", ["resource-group"] = "privategroup", ["region"] = "eu-de", ["monitoring-instance"] = Monitoring };
var scwOptions = new Dictionary<string, string> { ["project"] = Project, ["zone"] = "fr-par-1", ["cockpit-source"] = Source };
JsonElement Json(object value) => JsonSerializer.SerializeToElement(value);
JsonElement Prometheus(params object[] samples) => Json(new { status = "success", data = new { resultType = "matrix", result = new[] { new { metric = new { __name__ = "up", instance = "private-target", authorization = "PRIVATE_REMOTE_LABEL" }, values = samples } } } });
JsonElement AliPoints(IEnumerable<object> points, string next = "") => Json(new { Success = true, Datapoints = JsonSerializer.Serialize(points), NextToken = next });
JsonElement InstanceMetadata() => Json(new { account_id = "privateaccount", resource_group_id = "privategroup", region_id = "eu-de", guid = Monitoring, resource_id = "sysdig-monitor" });
JsonElement SourceMetadata(string? project = null, string? url = null) => Json(new { id = Source, project_id = project ?? Project, region = "fr-par", type = "metrics", url = url ?? $"https://{Source}.metrics.cockpit.fr-par.scw.cloud" });
FakeRunner AliRunner(Func<IReadOnlyList<string>, JsonElement> metrics, params (string Id, string Region)[] resources) => new((tool, args) => args[0] switch
{
    "identity" => Json(new { AccountId = "123456789012" }),
    "instances" => Json(new { TotalCount = resources.Length, Instances = new { Instance = resources.Select(row => new { InstanceId = row.Id, RegionId = row.Region }) } }),
    "cpu" => metrics(args),
    _ => throw new Exception("Unexpected semantic command")
});
JsonElement Data(AnalysisReport report) => JsonSerializer.SerializeToElement(report.Data, ReportSecurity.JsonOptions);
string State(AnalysisReport report) => Data(report).GetProperty("coverage").GetProperty("state").GetString()!;
void Check(bool value, string message) { checks++; if (!value) throw new InvalidOperationException(message); }

var ali = AliRunner(_ => AliPoints(new object[] { new { instanceId = "i-one", timestamp = now.AddMinutes(-2).ToUnixTimeMilliseconds(), Average = 0d } }), ("i-one", "cn-hangzhou"));
var aliReport = await SupplementalCloudMetricsB.CollectAsync("alibaba", aliOptions, ali);
Check(aliReport.OperationSucceeded && State(aliReport) == "complete", "Valid scoped Alibaba CPU reads complete");
var aliSeries = Data(aliReport).GetProperty("metrics")[0];
Check(aliSeries.GetProperty("unit").GetString() == "percent" && aliSeries.GetProperty("samplingPeriodSeconds").GetInt32() == 60, "CPU retains percentage unit and sixty-second period");
Check(aliSeries.GetProperty("points")[0].GetProperty("value").GetDouble() == 0, "A genuine observed zero is retained");
Check(ali.Calls.Select(call => call.Arguments[0]).SequenceEqual(new[] { "identity", "instances", "cpu" }), "Account and ECS ownership are checked before any CPU read");
var providerPeriod = AliRunner(_ => Json(new { Success = true, Period = "300", Datapoints = JsonSerializer.Serialize(new[] { new { instanceId = "i-one", timestamp = now.AddMinutes(-2).ToUnixTimeMilliseconds(), Average = 31d } }) }), ("i-one", "cn-hangzhou"));
var periodReport = await SupplementalCloudMetricsB.CollectAsync("alibaba", aliOptions, providerPeriod);
Check(State(periodReport) == "partial" && Data(periodReport).GetProperty("metrics")[0].GetProperty("samplingPeriodSeconds").GetInt32() == 300, "Actual CloudMonitor response cadence overrides the requested period and is disclosed: " + ReportSecurity.Serialize(periodReport));

var narrowed = new Dictionary<string, string>(aliOptions) { ["metric-resources"] = "i-one" };
var broadResponse = AliRunner(_ => AliPoints(new object[] { new { instanceId = "i-one", timestamp = now.AddMinutes(-2).ToUnixTimeMilliseconds(), Average = 25d } }), ("i-one", "cn-hangzhou"), ("i-other", "cn-hangzhou"));
var narrowedReport = await SupplementalCloudMetricsB.CollectAsync("alibaba", narrowed, broadResponse);
Check(!narrowedReport.OperationSucceeded && State(narrowedReport) == "partial", "Unrequested enumeration is reported as partial");
Check(broadResponse.Calls.Where(call => call.Arguments[0] == "cpu").All(call => call.Arguments[4] == "i-one"), "An explicit instance allowlist cannot be broadened by an API response");
var foreignRegion = AliRunner(_ => throw new Exception("Metrics must not run"), ("i-one", "cn-beijing"));
Check(State(await SupplementalCloudMetricsB.CollectAsync("alibaba", aliOptions, foreignRegion)) == "permission_denied" && foreignRegion.Calls.Count == 2, "Foreign-region resources fail before metric queries");
var wrongAccount = new FakeRunner((_, _) => Json(new { AccountId = "otheraccount" }));
Check(State(await SupplementalCloudMetricsB.CollectAsync("alibaba", aliOptions, wrongAccount)) == "permission_denied" && wrongAccount.Calls.Count == 1, "A mismatched Alibaba identity never enumerates resources");

var empty = AliRunner(_ => throw new Exception("No instance metric should run"));
var emptyReport = await SupplementalCloudMetricsB.CollectAsync("alibaba", aliOptions, empty);
Check(emptyReport.OperationSucceeded && State(emptyReport) == "no_data" && Data(emptyReport).GetProperty("metrics").GetArrayLength() == 0, "No resources is no_data, without a fabricated zero series");
var malformedTime = AliRunner(_ => AliPoints(new object[]
{
    new { instanceId = "i-one", timestamp = now.AddHours(-2).ToUnixTimeMilliseconds(), Average = 9d },
    new { instanceId = "i-one", timestamp = now.AddMinutes(10).ToUnixTimeMilliseconds(), Average = 8d },
    new { instanceId = "i-other", timestamp = now.AddMinutes(-2).ToUnixTimeMilliseconds(), Average = 7d },
    new { instanceId = "i-one", timestamp = now.AddMinutes(-2).ToUnixTimeMilliseconds(), Average = 120d }
}), ("i-one", "cn-hangzhou"));
var invalidTimeReport = await SupplementalCloudMetricsB.CollectAsync("alibaba", aliOptions, malformedTime);
Check(!invalidTimeReport.OperationSucceeded && State(invalidTimeReport) == "partial" && Data(invalidTimeReport).GetProperty("metrics")[0].GetProperty("points").GetArrayLength() == 0, "Stale/future/foreign/out-of-range CPU samples are omitted with partial coverage");
var repeatingPage = AliRunner(_ => AliPoints(new object[] { new { instanceId = "i-one", timestamp = now.AddMinutes(-2).ToUnixTimeMilliseconds(), Average = 40d } }, "again"), ("i-one", "cn-hangzhou"));
Check(State(await SupplementalCloudMetricsB.CollectAsync("alibaba", aliOptions, repeatingPage)) == "partial" && repeatingPage.Calls.Count == 4, "Repeated CloudMonitor continuation stops at two metric reads");
var denied = AliRunner(_ => Json(new { Success = false, Code = "Forbidden.AccessDenied", Message = "PRIVATE_PROVIDER_ERROR" }), ("i-one", "cn-hangzhou"));
var deniedReport = await SupplementalCloudMetricsB.CollectAsync("alibaba", aliOptions, denied);
Check(State(deniedReport) == "permission_denied" && !ReportSecurity.Serialize(deniedReport).Contains("PRIVATE_PROVIDER_ERROR", StringComparison.Ordinal), "CloudMonitor denial is classified without provider error text");
var pointBudget = AliRunner(_ => AliPoints(Enumerable.Range(0, 10001).Select(_ => (object)new { instanceId = "i-one", timestamp = now.AddMinutes(-2).ToUnixTimeMilliseconds(), Average = 42d })), ("i-one", "cn-hangzhou"));
var boundedReport = await SupplementalCloudMetricsB.CollectAsync("alibaba", aliOptions, pointBudget);
Check(State(boundedReport) == "partial" && Data(boundedReport).GetProperty("metrics").EnumerateArray().Sum(series => series.GetProperty("points").GetArrayLength()) <= 10000, "The global point budget is enforced with explicit partiality");
var padding = new string('x', 6 * 1024 * 1024);
var aggregateBytes = new FakeRunner((_, args) => args[0] switch
{
    "identity" => Json(new { AccountId = "123456789012" }),
    "instances" => Json(new { TotalCount = 1, Instances = new { Instance = new[] { new { InstanceId = "i-one", RegionId = "cn-hangzhou" } } }, extra = padding }),
    _ => Json(new { Success = true, Datapoints = "[]", NextToken = args[7] == "" ? "next" : "", extra = padding })
});
Check(State(await SupplementalCloudMetricsB.CollectAsync("alibaba", aliOptions, aggregateBytes)) == "partial" && aggregateBytes.Calls.Count == 4, "A whole-operation sixteen-MiB budget stops individually bounded pages");

var prom = Prometheus(new object[] { now.AddMinutes(-3).ToUnixTimeSeconds() + .5, "0" }, new object[] { now.AddMinutes(-2).ToUnixTimeSeconds(), "1" });
var ibm = new FakeRunner((_, args) => args[0] == "instance" ? InstanceMetadata() : prom);
var ibmReport = await SupplementalCloudMetricsB.CollectAsync("ibm", ibmOptions, ibm);
Check(ibmReport.OperationSucceeded && ibm.Calls.Count == 2, "IBM service ownership is verified before reading its Monitoring instance");
var ibmSeries = Data(ibmReport).GetProperty("metrics")[0];
Check(ibmSeries.GetProperty("metric").GetString() == "up" && ibmSeries.GetProperty("unit").GetString() == "ratio", "IBM scrape availability is represented as a ratio gauge, not CPU");
Check(ibmSeries.GetProperty("points")[0].GetProperty("timeUtc").GetDateTimeOffset().Millisecond == 500, "Fractional native Prometheus timestamps are preserved");
var safeIbm = ReportSecurity.Serialize(ibmReport);
Check(!safeIbm.Contains("privateaccount", StringComparison.Ordinal) && !safeIbm.Contains(Monitoring, StringComparison.Ordinal) && !safeIbm.Contains("private-target", StringComparison.Ordinal) && !safeIbm.Contains("PRIVATE_REMOTE_LABEL", StringComparison.Ordinal), "Metric labels, account and service identifiers remain private");
var wrongIbm = new FakeRunner((_, _) => Json(new { account_id = "other", resource_group_id = "privategroup", region_id = "eu-de", guid = Monitoring, resource_id = "sysdig-monitor" }));
Check(State(await SupplementalCloudMetricsB.CollectAsync("ibm", ibmOptions, wrongIbm)) == "permission_denied" && wrongIbm.Calls.Count == 1, "A foreign IBM Monitoring instance is never queried");

var scw = new FakeRunner((_, args) => args[0] == "source" ? SourceMetadata() : prom);
var scwReport = await SupplementalCloudMetricsB.CollectAsync("scaleway", scwOptions, scw);
Check(scwReport.OperationSucceeded && scw.Calls.Count == 2 && State(scwReport) == "complete", "Scaleway binds source UUID/project/region/type before querying");
foreach (var badUrl in new[] { "https://127.0.0.1/", $"https://{Source}.metrics.cockpit.fr-par.scw.cloud.evil.invalid/", $"http://{Source}.metrics.cockpit.fr-par.scw.cloud/", $"https://user@{Source}.metrics.cockpit.fr-par.scw.cloud/", $"https://{Source}.metrics.cockpit.fr-par.scw.cloud/?token=secret" })
{
    var bad = new FakeRunner((_, _) => SourceMetadata(url: badUrl));
    Check(State(await SupplementalCloudMetricsB.CollectAsync("scaleway", scwOptions, bad)) == "permission_denied" && bad.Calls.Count == 1, "Untrusted Cockpit endpoint is rejected before metrics: " + badUrl);
}
var crossProject = new FakeRunner((_, _) => SourceMetadata(project: Monitoring));
Check(State(await SupplementalCloudMetricsB.CollectAsync("scaleway", scwOptions, crossProject)) == "permission_denied" && crossProject.Calls.Count == 1, "A Cockpit data source from another project is rejected");
var emptyProm = new FakeRunner((_, args) => args[0] == "source" ? SourceMetadata() : Json(new { status = "success", data = new { resultType = "matrix", result = Array.Empty<object>() } }));
Check(State(await SupplementalCloudMetricsB.CollectAsync("scaleway", scwOptions, emptyProm)) == "no_data", "Missing scrape series never become a healthy zero");
var invalidProm = new FakeRunner((_, args) => args[0] == "instance" ? InstanceMetadata() : Prometheus(new object[] { now.AddMinutes(10).ToUnixTimeSeconds(), "1" }, new object[] { now.AddMinutes(-2).ToUnixTimeSeconds(), ".7" }));
Check(State(await SupplementalCloudMetricsB.CollectAsync("ibm", ibmOptions, invalidProm)) == "partial", "Future timestamps and nonbinary up values are omitted");

foreach (var provider in new[] { "alibaba", "ibm", "scaleway" })
{
    var untouched = new FakeRunner((_, _) => throw new Exception("No configured read should execute"));
    Check(State(await SupplementalCloudMetricsB.CollectAsync(provider, new Dictionary<string, string>(), untouched)) == "not_configured" && untouched.Calls.Count == 0, provider + " missing scope never makes a request");
    using var canceled = new CancellationTokenSource(); canceled.Cancel();
    try { await SupplementalCloudMetricsB.CollectAsync(provider, new Dictionary<string, string>(), untouched, canceled.Token); throw new Exception("Cancellation ignored"); }
    catch (OperationCanceledException) { Check(untouched.Calls.Count == 0, provider + " preserves upstream cancellation before requests"); }
}

var dates = new[] { now.AddHours(-1).ToString("O"), now.ToString("O") };
var grammar = SupplementalCloudMetricsBRunner.AlibabaArguments(new[] { "cpu", "123456789012", "cn-hangzhou", "reader", "i-one", dates[0], dates[1], "" });
Check(grammar.Take(2).SequenceEqual(new[] { "cms", "DescribeMetricList" }) && grammar.Contains("--region") && grammar.Contains("--Namespace") && grammar.Contains("CPUUtilization"), "CloudMonitor maps to its real read API with the CLI's regional selector");
Check(!grammar.Contains("--endpoint") && !grammar.Contains("--RegionId"), "CloudMonitor's API grammar does not introduce endpoint overrides or a nonexistent API RegionId parameter");
foreach (var bad in new[]
{
    new[] { "delete", "123456789012", "cn-hangzhou", "reader" },
    new[] { "identity", "123456789012", "https://evil.invalid", "reader" },
    new[] { "identity", "123456789012", "cn-hangzhou", "@private-file" },
    new[] { "instances", "123456789012", "cn-hangzhou", "reader", "[\"--endpoint\"]" },
    new[] { "cpu", "123456789012", "cn-hangzhou", "reader", "i-one", now.AddDays(-1).ToString("O"), dates[1], "" }
})
{
    try { SupplementalCloudMetricsBRunner.AlibabaArguments(bad); throw new Exception("Unsafe command accepted"); }
    catch (InvalidOperationException) { Check(true, "Unsafe Alibaba semantic query rejected"); }
}

var http = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}", Encoding.UTF8, "application/json") });
var transport = new SupplementalCloudMetricsBRunner(http, _ => "FIXTURE_TOKEN");
var window = new[] { now.AddHours(-1).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture) };
await transport.RunAsync("ibm-monitor", new[] { "instance", "privateaccount", "privategroup", "eu-de", Monitoring }, CancellationToken.None);
Check(http.Requests[^1].Uri.Host == "resource-controller.cloud.ibm.com" && http.Requests[^1].Uri.AbsolutePath == "/v2/resource_instances/" + Monitoring, "IBM instance metadata uses its fixed Resource Controller route");
await transport.RunAsync("ibm-monitor", new[] { "up", "privateaccount", "privategroup", "eu-de", Monitoring, window[0], window[1] }, CancellationToken.None);
Check(http.Requests[^1].Uri.Host == "eu-de.monitoring.cloud.ibm.com" && http.Requests[^1].Uri.AbsolutePath == "/prometheus/api/v1/query_range", "IBM metrics use the fixed regional Prometheus read endpoint");
Check(http.Requests[^1].Headers.GetValueOrDefault("IBMInstanceID") == Monitoring && http.Requests[^1].Headers.GetValueOrDefault("Authorization") == "Bearer FIXTURE_TOKEN", "IBM IAM authentication scopes the metric request to the selected instance");
Check(http.Requests[^1].Uri.Query.Contains("query=up", StringComparison.Ordinal) && http.Requests.All(request => request.Method == HttpMethod.Get), "Every HTTP operation is GET with the fixed up query");
await transport.RunAsync("scaleway-cockpit", new[] { "source", Project, "fr-par", Source }, CancellationToken.None);
Check(http.Requests[^1].Uri.Host == "api.scaleway.com" && http.Requests[^1].Uri.AbsolutePath == "/cockpit/v1/regions/fr-par/data-sources/" + Source && http.Requests[^1].Headers.GetValueOrDefault("X-Auth-Token") == "FIXTURE_TOKEN", "Cockpit source metadata uses the documented route and backend API token");
await transport.RunAsync("scaleway-cockpit", new[] { "up", Project, "fr-par", Source, window[0], window[1] }, CancellationToken.None);
Check(http.Requests[^1].Uri.Host == $"{Source}.metrics.cockpit.fr-par.scw.cloud" && http.Requests[^1].Headers.GetValueOrDefault("X-Token") == "FIXTURE_TOKEN", "Cockpit metrics use the verified data-source hostname and query token");

foreach (var status in new[] { HttpStatusCode.Forbidden, HttpStatusCode.TooManyRequests, HttpStatusCode.Redirect })
{
    var rejected = new RecordingHandler(_ => new HttpResponseMessage(status) { Content = new StringContent("PRIVATE_PROVIDER_BODY"), Headers = { Location = new Uri("https://untrusted.invalid/") } });
    var reader = new SupplementalCloudMetricsBRunner(rejected, _ => "FIXTURE_TOKEN");
    try { await reader.RunAsync("ibm-monitor", new[] { "instance", "privateaccount", "privategroup", "eu-de", Monitoring }, CancellationToken.None); throw new Exception("Rejected status accepted"); }
    catch (SupplementalMetricException error) { Check(error.State == (status == HttpStatusCode.Forbidden ? "permission_denied" : status == HttpStatusCode.TooManyRequests ? "rate_limited" : "failed") && !error.Message.Contains("PRIVATE_PROVIDER_BODY", StringComparison.Ordinal) && rejected.Requests.Count == 1, "HTTP denial/rate/redirect is safe and not retried"); }
}
foreach (var token in new string?[] { null, "", "private\r\nheader", new('a', 16385) })
{
    var uncalled = new RecordingHandler(_ => throw new Exception("Bad credential must not make a request"));
    var reader = new SupplementalCloudMetricsBRunner(uncalled, _ => token);
    try { await reader.RunAsync("ibm-monitor", new[] { "instance", "privateaccount", "privategroup", "eu-de", Monitoring }, CancellationToken.None); throw new Exception("Bad token accepted"); }
    catch (SupplementalMetricException error) { Check(error.State == "not_configured" && uncalled.Requests.Count == 0, "Missing, oversized and control-containing credentials remain outside HTTP"); }
}
var huge = new RecordingHandler(_ => { var content = new StringContent("{}"); content.Headers.ContentLength = 8 * 1024 * 1024 + 1; return new HttpResponseMessage(HttpStatusCode.OK) { Content = content }; });
try { await new SupplementalCloudMetricsBRunner(huge, _ => "FIXTURE_TOKEN").RunAsync("ibm-monitor", new[] { "instance", "privateaccount", "privategroup", "eu-de", Monitoring }, CancellationToken.None); throw new Exception("Oversized response accepted"); }
catch (SupplementalMetricException error) { Check(error.State == "partial", "Declared byte limit rejects oversized bodies before parsing"); }
var streamedHuge = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new UnknownLengthContent(8 * 1024 * 1024 + 1) });
try { await new SupplementalCloudMetricsBRunner(streamedHuge, _ => "FIXTURE_TOKEN").RunAsync("ibm-monitor", new[] { "instance", "privateaccount", "privategroup", "eu-de", Monitoring }, CancellationToken.None); throw new Exception("Oversized unknown-length response accepted"); }
catch (SupplementalMetricException error) { Check(error.State == "partial", "Effective streamed bytes remain bounded when Content-Length is absent"); }
using (var cancelRead = new CancellationTokenSource(TimeSpan.FromMilliseconds(50)))
{
    var slow = new RecordingHandler(async (_, token) => { await Task.Delay(Timeout.Infinite, token); return new HttpResponseMessage(HttpStatusCode.OK); });
    try { await new SupplementalCloudMetricsBRunner(slow, _ => "FIXTURE_TOKEN").RunAsync("ibm-monitor", new[] { "instance", "privateaccount", "privategroup", "eu-de", Monitoring }, cancelRead.Token); throw new Exception("HTTP cancellation ignored"); }
    catch (OperationCanceledException) { Check(slow.Requests.Count == 1, "Caller cancellation interrupts an in-flight HTTP request"); }
}
var blocked = new RecordingHandler(_ => throw new Exception("Unsafe route must not be called"));
try { await new SupplementalCloudMetricsBRunner(blocked, _ => "FIXTURE_TOKEN").RunAsync("ibm-monitor", new[] { "up", "privateaccount", "privategroup", "127.0.0.1", Monitoring, window[0], window[1] }, CancellationToken.None); throw new Exception("Untrusted host accepted"); }
catch (InvalidOperationException) { Check(blocked.Requests.Count == 0, "Regional host allowlist prevents endpoint injection"); }

Console.WriteLine($"PASS: {checks} Alibaba, IBM and Scaleway metric scope, unit, privacy, transport and budget checks.");

sealed class FakeRunner(Func<string, IReadOnlyList<string>, JsonElement> response) : ICloudCommandRunner
{
    public List<(string Tool, IReadOnlyList<string> Arguments)> Calls { get; } = [];
    public Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    { cancellationToken.ThrowIfCancellationRequested(); Calls.Add((tool, arguments.ToArray())); return Task.FromResult(response(tool, arguments)); }
}
sealed class RecordingHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> response;
    public List<(Uri Uri, HttpMethod Method, Dictionary<string, string> Headers)> Requests { get; } = [];
    public RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> response) => this.response = (request, _) => Task.FromResult(response(request));
    public RecordingHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> response) => this.response = response;
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    { Requests.Add((request.RequestUri!, request.Method, request.Headers.ToDictionary(header => header.Key, header => string.Join(",", header.Value), StringComparer.OrdinalIgnoreCase))); return response(request, cancellationToken); }
}
sealed class UnknownLengthContent(int length) : HttpContent
{
    protected override bool TryComputeLength(out long result) { result = 0; return false; }
    protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
    {
        var chunk = new byte[16384];
        for (var remaining = length; remaining > 0; remaining -= chunk.Length) await stream.WriteAsync(chunk.AsMemory(0, Math.Min(remaining, chunk.Length)));
    }
}
