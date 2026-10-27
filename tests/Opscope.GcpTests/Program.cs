using System.Net;
using System.Text;
using System.Text.Json;
using Opscope;
using Opscope.Cloud;

const string Project = "private-project-123";
var options = new Dictionary<string, string> { ["project"] = Project };
var noMetrics = new FakeMetrics(new(CoverageState.Complete, DateTimeOffset.UtcNow, [], ["No metric evidence."]));
var asset = "[{\"name\":\"//compute.googleapis.com/projects/private-project-123/zones/europe-west1-b/instances/private-host\",\"assetType\":\"compute.googleapis.com/Instance\",\"displayName\":\"private-host\",\"location\":\"europe-west1-b\",\"labels\":{\"private\":\"secret-value\"}}]";
var commands = new FakeRunner((_, _) => Json(asset));
var provider = new GcpProvider(commands, noMetrics);
var inventory = await provider.CollectAsync("inventory", options);
Check(inventory.OperationSucceeded && Coverage(inventory) == "Complete", "Bounded scoped inventory should complete");
Check(commands.Calls.Count == 1 && commands.Calls[0].Tool == "gcloud", "Inventory uses only controlled gcloud reads");
Check(commands.Calls[0].Arguments.Contains("projects/" + Project), "Asset query must use the explicit project scope");
var output = ReportSecurity.Serialize(inventory);
Check(!output.Contains(Project, StringComparison.Ordinal) && !output.Contains("private-host", StringComparison.Ordinal) && !output.Contains("secret-value", StringComparison.Ordinal), "Cloud exports must redact identifiers and omit remote metadata");

var empty = await new GcpProvider(new FakeRunner((_, _) => Json("[]")), noMetrics).CollectAsync("inventory", options);
Check(empty.OperationSucceeded && empty.Warnings!.Any(text => text.Contains("does not establish", StringComparison.Ordinal)), "Empty inventory must explain coverage limits");
var failed = await new GcpProvider(new FakeRunner((_, _) => throw new IOException("secret-token-and-private-project")), noMetrics).CollectAsync("health", options);
Check(!failed.OperationSucceeded && Coverage(failed) == "Partial", "Successful metrics with failed VM evidence must be partial");
Check(!ReportSecurity.Serialize(failed).Contains("secret-token-and-private-project", StringComparison.Ordinal), "Transport exception text must stay private");

var projects = new Dictionary<string, string> { ["projects"] = Project + ",another-project-123" };
var partial = await new GcpProvider(new FakeRunner((_, args) => args.Contains("another-project-123") ? throw new IOException("denied") : Json(asset)), noMetrics).CollectAsync("inventory", projects);
Check(!partial.OperationSucceeded && Coverage(partial) == "Partial", "One denied project must not produce complete inventory");
var count = JsonSerializer.SerializeToElement(partial.Data, ReportSecurity.JsonOptions).GetProperty("coverage");
Check(count.GetProperty("expectedScopes").GetInt32() == 2 && count.GetProperty("completedScopes").GetInt32() == 1, "Coverage counts completed project scopes");

var largeRows = "[" + string.Join(',', Enumerable.Repeat(asset[1..^1], 501)) + "]";
var bounded = await new GcpProvider(new FakeRunner((_, _) => Json(largeRows)), noMetrics).CollectAsync("inventory", options);
Check(!bounded.OperationSucceeded && Coverage(bounded) == "Partial", "Row truncation must be partial");
Check(JsonSerializer.SerializeToElement(bounded.Data, ReportSecurity.JsonOptions).GetProperty("resources").GetArrayLength() == 500, "Inventory row bound enforced");

foreach (var invalid in new[] { "../escape", "https://evil.invalid", "bad", "project;--endpoint", "projects/private-project-123" })
{
    var invalidRunner = new FakeRunner((_, _) => Json("[]"));
    try { await new GcpProvider(invalidRunner, noMetrics).CollectAsync("inventory", new Dictionary<string, string> { ["project"] = invalid }); throw new Exception("Invalid project accepted"); }
    catch (ArgumentException) { Check(invalidRunner.Calls.Count == 0, "Invalid scope must not make a provider call"); }
}
var unsupportedRunner = new FakeRunner((_, _) => throw new Exception("Unexpected read"));
var unsupported = await new GcpProvider(unsupportedRunner, noMetrics).CollectAsync("cost", options);
Check(!unsupported.OperationSucceeded && Coverage(unsupported) == "NotConfigured" && unsupportedRunner.Calls.Count == 0, "Unconfigured Billing must never fabricate zero cost or invoke a provider");

var instanceJson = "[{\"name\":\"private-host\",\"zone\":\"https://www.googleapis.com/compute/v1/projects/private-project-123/zones/europe-west1-b\",\"status\":\"RUNNING\",\"machineType\":\"zones/europe-west1-b/machineTypes/e2-medium\"}]";
var firewallJson = "[{\"name\":\"private-admin-rule\",\"direction\":\"INGRESS\",\"sourceRanges\":[\"::/0\"],\"allowed\":[{\"IPProtocol\":\"tcp\",\"ports\":[\"20-25\"]}]}]";
var posture = await new GcpProvider(new FakeRunner((_, args) => Json(args.Contains("firewall-rules") ? firewallJson : instanceJson)), noMetrics).CollectAsync("posture", options);
Check(posture.Findings.Any(finding => finding.Code == "GCP_FIREWALL_ADMIN_INTERNET"), "IPv6 unrestricted administrative ports must be visible");
Check(!ReportSecurity.Serialize(posture).Contains("private-admin-rule", StringComparison.Ordinal), "Firewall finding resource names must be redacted");

var points = new[] { new GcpMetricPoint(DateTimeOffset.UtcNow.AddMinutes(-2), 24.5) };
var metricReader = new FakeMetrics(new(CoverageState.Complete, DateTimeOffset.UtcNow,
    [new(Project, "//compute.googleapis.com/projects/" + Project + "/zones/europe-west1-b/instances/12345", "europe-west1-b", "compute.googleapis.com/instance/cpu/utilization", "percent", "ALIGN_MEAN", 60, "cloud-monitoring", points)], []));
var metrics = await new GcpProvider(new FakeRunner((_, _) => throw new Exception("Metrics must not invoke gcloud")), metricReader).CollectAsync("metrics", options);
Check(metrics.OperationSucceeded && JsonSerializer.SerializeToElement(metrics.Data, ReportSecurity.JsonOptions).GetProperty("metrics")[0].GetProperty("samplingPeriodSeconds").GetInt32() == 60, "Genuine metrics retain provider cadence");
Check(!ReportSecurity.Serialize(metrics).Contains(Project, StringComparison.Ordinal), "Metrics project IDs must be redacted");
var namedOptions = new Dictionary<string, string>(options) { ["resource"] = "projects/" + Project + "/zones/europe-west1-b/instances/private-host" };
var namedInstance = instanceJson.Replace("\"name\":", "\"id\":\"12345\",\"name\":", StringComparison.Ordinal);
var namedHealth = await new GcpProvider(new FakeRunner((_, _) => Json(namedInstance)), metricReader).CollectAsync("health", namedOptions);
Check(namedHealth.OperationSucceeded && JsonSerializer.SerializeToElement(namedHealth.Data, ReportSecurity.JsonOptions).GetProperty("metrics").GetArrayLength() == 1, "Named VM scope must link to Monitoring numeric instance IDs through observed Compute id");
var narrowed = await new GcpProvider(new FakeRunner((_, _) => Json(asset)), noMetrics).CollectAsync("inventory", namedOptions);
Check(narrowed.OperationSucceeded && JsonSerializer.SerializeToElement(narrowed.Data, ReportSecurity.JsonOptions).GetProperty("resources").GetArrayLength() == 1, "Inventory honors explicit resource narrowing");
var scopeGuardRunner = new FakeRunner((_, _) => Json("[]"));
try { await new GcpProvider(scopeGuardRunner, noMetrics).CollectAsync("posture", namedOptions); throw new Exception("Unsupported resource-specific posture accepted"); }
catch (ArgumentException) { Check(scopeGuardRunner.Calls.Count == 0, "Unsupported resource-specific posture cannot silently widen its scope"); }
var denied = await new GcpProvider(new FakeRunner((_, _) => Json("[]")), new FakeMetrics(new(CoverageState.PermissionDenied, DateTimeOffset.UtcNow, [], ["Denied"])) ).CollectAsync("metrics", options);
Check(Coverage(denied) == "PermissionDenied" && !denied.OperationSucceeded, "Metrics denied must remain distinct from empty or healthy");
var tenThousandPoints = Enumerable.Range(0, 10000).Select(index => new GcpMetricPoint(DateTimeOffset.UtcNow.AddSeconds(-index), 25)).ToArray();
var aggregateReader = new FakeMetrics(new(CoverageState.Complete, DateTimeOffset.UtcNow,
    [new(Project, "//compute.googleapis.com/projects/" + Project + "/zones/europe-west1-b/instances/12345", "europe-west1-b", "compute.googleapis.com/instance/cpu/utilization", "percent", "ALIGN_MEAN", 60, "cloud-monitoring", tenThousandPoints)], []));
var aggregate = await new GcpProvider(new FakeRunner((_, _) => Json("[]")), aggregateReader).CollectAsync("metrics", projects);
var aggregateJson = JsonSerializer.SerializeToElement(aggregate.Data, ReportSecurity.JsonOptions);
Check(!aggregate.OperationSucceeded && Coverage(aggregate) == "Partial" && aggregateJson.GetProperty("metrics").EnumerateArray().Sum(series => series.GetProperty("points").GetArrayLength()) == 10000, "Metric point bounds apply across all projects in one operation");

var now = DateTimeOffset.UtcNow.AddMinutes(-2).ToString("O");
var monitoringJson = "{\"timeSeries\":[{\"metric\":{\"type\":\"compute.googleapis.com/instance/cpu/utilization\"},\"resource\":{\"type\":\"gce_instance\",\"labels\":{\"project_id\":\"" + Project + "\",\"zone\":\"europe-west1-b\",\"instance_id\":\"12345\"}},\"points\":[{\"interval\":{\"endTime\":\"" + now + "\"},\"value\":{\"doubleValue\":0.25}}]}]}";
var handler = new FakeHandler(_ => new(HttpStatusCode.OK) { Content = new StringContent(monitoringJson, Encoding.UTF8, "application/json") });
using var http = new HttpClient(handler);
var reader = new GcpMonitoringReader(http, _ => Task.FromResult("fixture-access-token"));
var read = await reader.ReadCpuAsync(Project, CancellationToken.None);
Check(read.State == CoverageState.Complete && read.Series.Single().Points.Single().Value == 25, "Monitoring utilization ratios convert to percentage");
Check(handler.Requests == 1 && handler.LastUri!.Host == "monitoring.googleapis.com" && handler.LastMethod == HttpMethod.Get, "Monitoring transport must issue GET to its fixed allowlisted host");
var repeatedPage = new FakeHandler(_ => new(HttpStatusCode.OK) { Content = new StringContent("{\"nextPageToken\":\"repeated\"}") });
using var pagingHttp = new HttpClient(repeatedPage);
var pageRead = await new GcpMonitoringReader(pagingHttp, _ => Task.FromResult("fixture-token")).ReadCpuAsync(Project, CancellationToken.None);
Check(pageRead.State == CoverageState.Partial && repeatedPage.Requests == 2, "Repeated page tokens must stop pagination and mark partial");
var redirect = new FakeHandler(_ => new(HttpStatusCode.Redirect) { Headers = { Location = new("https://untrusted.invalid/") } });
using var redirectHttp = new HttpClient(redirect);
var redirectRead = await new GcpMonitoringReader(redirectHttp, _ => Task.FromResult("fixture-token")).ReadCpuAsync(Project, CancellationToken.None);
Check(redirectRead.State == CoverageState.Failed && redirect.Requests == 1, "Redirects must never be followed");
var oversized = new FakeHandler(_ => new(HttpStatusCode.OK) { Content = new StringContent(new string('x', 4 * 1024 * 1024 + 1)) });
using var oversizedHttp = new HttpClient(oversized);
var hugeRead = await new GcpMonitoringReader(oversizedHttp, _ => Task.FromResult("fixture-token")).ReadCpuAsync(Project, CancellationToken.None);
Check(hugeRead.State == CoverageState.Failed, "Oversized Monitoring bodies must be rejected");
foreach (var status in new[] { HttpStatusCode.Forbidden, HttpStatusCode.TooManyRequests })
{
    using var statusHttp = new HttpClient(new FakeHandler(_ => new(status) { Content = new StringContent("SECRET-PROVIDER-BODY") }));
    var statusRead = await new GcpMonitoringReader(statusHttp, _ => Task.FromResult("fixture-token")).ReadCpuAsync(Project, CancellationToken.None);
    Check(statusRead.State == (status == HttpStatusCode.Forbidden ? CoverageState.PermissionDenied : CoverageState.RateLimited), "HTTP denial and rate limits need explicit coverage");
    Check(!JsonSerializer.Serialize(statusRead).Contains("SECRET-PROVIDER-BODY", StringComparison.Ordinal), "Provider HTTP bodies must stay private");
}

Check(CloudProviderRegistry.Descriptors.Count == 12 && CloudProviderRegistry.Descriptors.Select(item => item.ProviderId).Distinct().Count() == 12 && CloudProviderRegistry.Descriptors.Count(item => item.Category == "cluster") == 1, "Registry distinguishes eleven cloud providers and a unique Kubernetes cluster adapter");
Check(CloudProviderRegistry.SupportsOperation("gcp", "metrics") && CloudProviderRegistry.SupportsOperation("gcp", "cost") && CloudProviderRegistry.SupportsOperation("gcp", "scc") && !CloudProviderRegistry.SupportsOperation("gcp", "0"), "Capabilities match implemented advanced reads and reject enum numeric strings");
Check(CloudProviderRegistry.Create("gcp", commands).Name == "gcp", "Registry composes Google Cloud without network activity");
foreach (var request in new[] { new[] { "auth", "login" }, new[] { "compute", "instances", "delete" }, new[] { "compute", "instances", "list", "--project", Project, "--impersonate-service-account", "private@example.invalid" }, new[] { "compute", "instances", "list", "--endpoint", "https://evil.invalid" } })
{
    try { TrustedCloudCommandRunner.PrepareArguments("gcloud", request); throw new Exception("Unsafe gcloud grammar accepted"); }
    catch (InvalidOperationException) { }
}
var noBaselineRunner = new FakeRunner((_, _) => throw new Exception("Drift without a baseline must stay offline"));
var noBaseline = await new GcpProvider(noBaselineRunner, noMetrics).CollectAsync("drift", options);
Check(Coverage(noBaseline) == "NotConfigured" && noBaselineRunner.Calls.Count == 0, "Drift without an explicit baseline cannot query a provider");
var patchReader = new FakePatches();
await new GcpProvider(commands, noMetrics, patches: patchReader).CollectAsync("patches", options);
Check(patchReader.Projects.SequenceEqual(new[] { Project }), "GCP patch dispatch preserves the explicit project scope");
var correlationOptions = new Dictionary<string, string> { ["infrastructure-provider"] = "gcp", ["kubernetes-nodes"] = "true", ["gcp-projects"] = Project, ["endpoint"] = "https://never-forward.invalid", ["baseline"] = "private-file", ["resource"] = "never-forward-filter" };
var prepared = KubernetesInfrastructureCollection.Prepare(correlationOptions)!;
Check(prepared["projects"] == Project && prepared["provider"] == "gcp" && !prepared.ContainsKey("endpoint") && !prepared.ContainsKey("resource") && !prepared.ContainsKey("baseline"), "Node matching forwards only the fixed explicit infrastructure scope");
foreach (var mutate in new Action<Dictionary<string, string>>[] { o => o["infrastructure-provider"] = "unknown", o => o.Remove("kubernetes-nodes"), o => o["gcp-projects"] = "", o => o["gcp-projects"] = Project + "," + Project, o => o["gcp-projects"] = "https://untrusted.invalid" })
{
    var invalid = new Dictionary<string, string>(correlationOptions); mutate(invalid);
    try { KubernetesInfrastructureCollection.Prepare(invalid); throw new Exception("Unsafe correlation configuration accepted"); } catch (ArgumentException) { }
}
var infrastructureCalls = 0;
ICloudProvider CreateInfrastructure(string id, ICloudCommandRunner? unused)
{
    infrastructureCalls++;
    Check(id == "gcp", "Only the configured infrastructure adapter is constructed");
    return new FakeCloud("gcp", (_, selected) => { Check(selected["projects"] == Project && !selected.ContainsKey("endpoint"), "Only the prepared scope reaches the infrastructure inventory"); return new("cloud/gcp/inventory", DateTimeOffset.UtcNow, [], new { provider = "gcp" }); });
}
var clusterFixture = new FakeCloud("kubernetes", (_, _) => new("cloud/kubernetes/inventory", DateTimeOffset.UtcNow, [], new { provider = "kubernetes" }));
await KubernetesInfrastructureCollection.CollectAsync(clusterFixture, "inventory", new Dictionary<string, string>(), CreateInfrastructure);
await KubernetesInfrastructureCollection.CollectAsync(clusterFixture, "metrics", correlationOptions, CreateInfrastructure);
Check(infrastructureCalls == 0, "Default and metrics-only cluster collection never query infrastructure");
await KubernetesInfrastructureCollection.CollectAsync(clusterFixture, "inventory", correlationOptions, CreateInfrastructure);
Check(infrastructureCalls == 1, "Explicit node correlation performs one scoped inventory");
var failedCluster = new FakeCloud("kubernetes", (_, _) => new AnalysisReport("cloud/kubernetes/inventory", DateTimeOffset.UtcNow, [], new { provider = "kubernetes" }) { OperationSucceeded = false });
await KubernetesInfrastructureCollection.CollectAsync(failedCluster, "inventory", correlationOptions, CreateInfrastructure);
Check(infrastructureCalls == 1, "Failed cluster observations never trigger infrastructure follow-up");
var unavailableCorrelation = await KubernetesInfrastructureCollection.CollectAsync(clusterFixture, "inventory", correlationOptions, (_, _) => new FakeCloud("gcp", (_, _) => throw new IOException("PRIVATE-CLOUD-ERROR")));
Check(!ReportSecurity.Serialize(unavailableCorrelation).Contains("PRIVATE-CLOUD-ERROR", StringComparison.Ordinal) && unavailableCorrelation.Warnings!.Any(w => w.Contains("unverified", StringComparison.Ordinal)), "Infrastructure errors preserve unverified correlation without raw error text");
Check(ReportSecurity.Serialize(new AnalysisReport("catalog", DateTimeOffset.UtcNow, [], new { providerId = "gcp" })).Contains("gcp", StringComparison.Ordinal), "Node identity redaction preserves public catalog provider IDs");
Console.WriteLine("Google Cloud, ADC Monitoring, coverage, scope, redaction and registry checks passed");

static JsonElement Json(string text) => JsonDocument.Parse(text).RootElement.Clone();
static string Coverage(AnalysisReport report) => JsonSerializer.SerializeToElement(report.Data, ReportSecurity.JsonOptions).GetProperty("coverage").GetProperty("state").GetString()!;
static void Check(bool value, string message) { if (!value) throw new Exception(message); }

sealed class FakeRunner(Func<string, IReadOnlyList<string>, JsonElement> response) : ICloudCommandRunner
{
    public List<(string Tool, IReadOnlyList<string> Arguments)> Calls { get; } = [];
    public Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    { cancellationToken.ThrowIfCancellationRequested(); Calls.Add((tool, arguments.ToArray())); return Task.FromResult(response(tool, arguments)); }
}
sealed class FakeMetrics(GcpMetricResult result) : IGcpMonitoringReader
{
    public Task<GcpMetricResult> ReadCpuAsync(string project, CancellationToken cancellationToken) => Task.FromResult(result);
}
sealed class FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
{
    public int Requests { get; private set; }
    public Uri? LastUri { get; private set; }
    public HttpMethod? LastMethod { get; private set; }
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    { Requests++; LastUri = request.RequestUri; LastMethod = request.Method; return Task.FromResult(response(request)); }
}

sealed class FakePatches : IGcpPatchReader
{
    public IReadOnlyList<string> Projects { get; private set; } = [];
    public Task<AnalysisReport> ReadAsync(IReadOnlyList<string> projects, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default)
    { Projects = projects; return Task.FromResult(new AnalysisReport("cloud/gcp/patches", DateTimeOffset.UtcNow, [], new { provider = "gcp" })); }
}
sealed class FakeCloud(string name, Func<string, IReadOnlyDictionary<string, string>, AnalysisReport> response) : ICloudProvider
{
    public string Name => name;
    public Task<AnalysisReport> CollectAsync(string operation, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default)
    { cancellationToken.ThrowIfCancellationRequested(); return Task.FromResult(response(operation, options)); }
}
