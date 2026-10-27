using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using Opscope;
using Opscope.Cloud;

const string Project = "example-project";
const string Number = "123456789012";
var checks = 0;
var options = new Dictionary<string, string>();
var now = DateTimeOffset.UtcNow;
using (var http = new HttpClient(new Fixture(_ => throw new Exception("No network expected"))))
{
    var tokenCalls = 0;
    var reader = new GcpPatchReader(http, _ => { tokenCalls++; return Task.FromResult("fixture-token"); });
    var missing = await reader.ReadAsync([], options);
    Check(State(missing) == "NotConfigured" && tokenCalls == 0 && !missing.OperationSucceeded, "Missing projects do not authenticate or invent compliant evidence");
    foreach (var invalid in new[] { "projects/example-project", "https://untrusted.invalid/", "example-project,another-project", "bad\nproject" })
        await Throws(() => reader.ReadAsync([invalid], options), "Literal project validation precedes authentication");
    await Throws(() => reader.ReadAsync([Project, Project], options), "Duplicate projects are rejected before authentication");
    foreach (var option in new[] { "region", "resource" })
        await Throws(() => reader.ReadAsync([Project], new Dictionary<string, string> { [option] = "selected" }), "Unsupported narrowing is rejected before authentication");
    Check(tokenCalls == 0, "No rejected configuration acquires ADC");
}

foreach (var state in new[] { "STATE_UNSPECIFIED", "STARTED", "INSTANCE_LOOKUP", "PATCHING", "SUCCEEDED", "COMPLETED_WITH_INACTIVE_VMS", "COMPLETED_WITH_ERRORS", "CANCELED", "TIMED_OUT" })
{
    var handler = Standard(Job("first-job", state));
    using var client = new HttpClient(handler);
    var report = await Reader(client).ReadAsync([Project], options);
    var data = Data(report); var patch = data.GetProperty("patches"); var job = patch.GetProperty("jobs")[0];
    Check(report.OperationSucceeded && State(report) == "Complete" && job.GetProperty("state").GetString() == state, "Documented OS Config states preserve existing execution metadata");
    Check(patch.GetProperty("complianceState").GetString() == "unknown" && report.Findings.Count == 0, "Every execution state, including SUCCEEDED, leaves current compliance unknown");
    Check(job.GetProperty("succeededInstanceCount").GetInt64() == 7 && job.GetProperty("failedInstanceCount").GetInt64() == 2 && job.GetProperty("isStale").GetBoolean() == false, "Actual selected counters and recent update timestamps are retained");
    Check(handler.Requests.Count == 2 && handler.Requests.All(request => request.Method == HttpMethod.Get && request.Uri.Scheme == "https" && request.Bearer == "fixture-token"), "Only authenticated HTTPS GETs occur");
    Check(handler.Requests[0].Uri.Host == "cloudresourcemanager.googleapis.com" && handler.Requests[1].Uri.AbsolutePath == "/v1/projects/" + Number + "/patchJobs", "Patch queries use the verified numeric project identity");
    var query = Uri.UnescapeDataString(handler.Requests[1].Uri.Query);
    Check(query.Contains("fields=nextPageToken,patchJobs(name,createTime,updateTime,state,dryRun,instanceDetailsSummary(", StringComparison.Ordinal) && !query.Contains("patchConfig", StringComparison.Ordinal) && !query.Contains("filter", StringComparison.Ordinal), "Source projection excludes scripts, descriptions, instance filters and provider messages");
    var full = ReportSecurity.Serialize(report, false); var shared = ReportSecurity.Serialize(report);
    Check(!full.Contains("RAW-SECRET", StringComparison.Ordinal) && !shared.Contains(Project, StringComparison.Ordinal) && !shared.Contains("first-job", StringComparison.Ordinal), "Even private evidence omits unselected raw fields; shared evidence redacts identities");
}

var stale = Job("stale-dry-run", "SUCCEEDED"); stale["dryRun"] = true; stale["updateTime"] = now.AddDays(-5).ToString("O"); stale["createTime"] = now.AddDays(-6).ToString("O");
using (var client = new HttpClient(Standard(stale)))
{
    var report = await Reader(client).ReadAsync([Project], options);
    var job = Data(report).GetProperty("patches").GetProperty("jobs")[0];
    Check(job.GetProperty("dryRun").GetBoolean() && job.GetProperty("isStale").GetBoolean(), "Dry runs and updates older than 24 hours are explicitly preserved");
    Check(Data(report).GetProperty("patches").GetProperty("complianceState").GetString() == "unknown", "Stale successful simulation does not establish patch compliance");
}
using (var client = new HttpClient(Standard(new { name = "projects/" + Project + "/patchJobs/unknown-metadata", state = "STARTED" })))
{
    var report = await Reader(client).ReadAsync([Project], options); var job = Data(report).GetProperty("patches").GetProperty("jobs")[0];
    Check(!job.TryGetProperty("isStale", out _) && !job.TryGetProperty("succeededInstanceCount", out _) && !job.TryGetProperty("updatedAtUtc", out _), "Missing timestamps and counters remain absent rather than invented zeros or freshness");
}
using (var client = new HttpClient(Standard()))
{
    var report = await Reader(client).ReadAsync([Project], options);
    Check(report.OperationSucceeded && Data(report).GetProperty("patches").GetProperty("jobsRead").GetInt32() == 0 && report.Warnings!.Any(warning => warning.Contains("never means zero", StringComparison.Ordinal)), "Empty existing-job lists may complete a read but never assert zero missing patches");
}

foreach (var mutate in new Action<Dictionary<string, object?>>[]
{
    job => job["name"] = "projects/999999999999/patchJobs/foreign-job",
    job => job["name"] = "projects/" + Project + "/patchJobs/one/more",
    job => job["name"] = "https://untrusted.invalid/projects/" + Project + "/patchJobs/job",
    job => job["state"] = "UNTRUSTED-STATE",
    job => job["dryRun"] = "false",
    job => job["createTime"] = now.AddMinutes(5).ToString("O"),
    job => job["updateTime"] = "2026",
    job => job["instanceDetailsSummary"] = new { failedInstanceCount = "-1" },
    job => job["instanceDetailsSummary"] = new { failedInstanceCount = "1.5" },
    job => job["instanceDetailsSummary"] = new { failedInstanceCount = "9223372036854775808" },
    job => job["instanceDetailsSummary"] = "RAW-SECRET"
})
{
    var job = Job("invalid-job", "SUCCEEDED"); mutate(job);
    using var client = new HttpClient(Standard(job)); var report = await Reader(client).ReadAsync([Project], options);
    Check(!report.OperationSucceeded && State(report) == "Partial" && Data(report).GetProperty("patches").GetProperty("jobsRead").GetInt32() == 0, "Foreign, malformed, future or invalid numeric rows cannot become valid patch evidence");
}

foreach (var status in new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.TooManyRequests, HttpStatusCode.Redirect, HttpStatusCode.InternalServerError })
{
    var handler = new Fixture(request => request.RequestUri!.Host == "cloudresourcemanager.googleapis.com" ? Ok(Identity(Project, Number)) : new(status) { Content = new StringContent("RAW-SECRET-ERROR"), Headers = { Location = new("https://untrusted.invalid/") } });
    using var client = new HttpClient(handler); var report = await Reader(client).ReadAsync([Project], options);
    Check(State(report) == (status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden ? "PermissionDenied" : status == HttpStatusCode.TooManyRequests ? "RateLimited" : "Failed") && !report.OperationSucceeded && handler.Requests.Count == 2, "Denied, throttled and failed reads stay distinct without retries or redirect following");
    Check(!ReportSecurity.Serialize(report, false).Contains("RAW-SECRET", StringComparison.Ordinal), "Provider error bodies are never read into exported evidence");
}
var mismatch = new Fixture(_ => Ok(Identity("foreign-project", Number)));
using (var client = new HttpClient(mismatch))
    Check(State(await Reader(client).ReadAsync([Project], options)) == "Failed" && mismatch.Requests.Count == 1, "Unverified Resource Manager identities block OS Config queries");

var alias = Job("alias-job", "SUCCEEDED"); var alias2 = Job("alias-job", "SUCCEEDED"); alias2["name"] = "projects/" + Number + "/patchJobs/alias-job";
using (var client = new HttpClient(Standard(alias, alias2)))
{
    var report = await Reader(client).ReadAsync([Project], options);
    Check(State(report) == "Partial" && Data(report).GetProperty("patches").GetProperty("jobsRead").GetInt32() == 1, "ID and numeric-project aliases deduplicate to one canonical patch job");
}
var repeated = new Fixture(request => request.RequestUri!.Host == "cloudresourcemanager.googleapis.com" ? Ok(Identity(Project, Number)) : Ok(new { patchJobs = new[] { Job("repeat", "SUCCEEDED") }, nextPageToken = "same" }));
using (var client = new HttpClient(repeated))
    Check(State(await Reader(client).ReadAsync([Project], options)) == "Partial" && repeated.Requests.Count == 3, "Repeated cursors terminate before unbounded page traversal");
var pageCount = 0;
var paged = new Fixture(request => request.RequestUri!.Host == "cloudresourcemanager.googleapis.com" ? Ok(Identity(Project, Number)) : Ok(new { patchJobs = new[] { Job("page-" + ++pageCount, "SUCCEEDED") }, nextPageToken = "page-" + pageCount }));
using (var client = new HttpClient(paged))
    Check(State(await Reader(client).ReadAsync([Project], options)) == "Partial" && pageCount == 10, "Pagination is bounded to ten pages per project");
using (var client = new HttpClient(Standard(Enumerable.Range(0, 1001).Select(index => (object)Job("row-" + index, "SUCCEEDED")).ToArray())))
{
    var report = await Reader(client).ReadAsync([Project], options);
    Check(State(report) == "Partial" && Data(report).GetProperty("patches").GetProperty("jobsRead").GetInt32() == 1000, "A response exceeding the global row budget stays bounded and incomplete");
}
var projectIds = new[] { Project, "second-project" };
var identityCounter = 0;
var mixedDenial = new Fixture(request => request.RequestUri!.Host == "cloudresourcemanager.googleapis.com" ? ++identityCounter == 1 ? new(HttpStatusCode.Forbidden) : Ok(Identity("second-project", "222222222222")) : Ok(new { patchJobs = Array.Empty<object>() }));
using (var client = new HttpClient(mixedDenial))
{
    var report = await Reader(client).ReadAsync(projectIds, options);
    Check(State(report) == "Partial" && !report.OperationSucceeded && Data(report).GetProperty("coverage").GetProperty("completedScopes").GetInt32() == 1, "A useful scope plus a denied scope is incomplete rather than a blanket permission denial");
}
using (var client = new HttpClient(new Fixture(_ => new(HttpStatusCode.Forbidden))))
    Check(State(await Reader(client).ReadAsync(projectIds, options)) == "PermissionDenied", "All denied scopes preserve permission-denied status without invented partial evidence");
using (var client = new HttpClient(new Fixture(_ => new(HttpStatusCode.OK) { Content = new StringContent(new string('x', 4 * 1024 * 1024 + 1)) })))
    Check(State(await Reader(client).ReadAsync([Project], options)) == "Failed", "Oversized responses are rejected before parsing");
var boundedProjects = Enumerable.Range(0, 20).Select(index => "project-" + index.ToString("00", CultureInfo.InvariantCulture)).ToArray();
var boundedPages = 0;
var boundedRequests = new Fixture(request => request.RequestUri!.Host == "cloudresourcemanager.googleapis.com" ? Ok(Identity(request.RequestUri.AbsolutePath.Split('/')[^1], "123456789012")) : Ok(new { patchJobs = new[] { Job("request-" + ++boundedPages, "SUCCEEDED") }, nextPageToken = "cursor-" + boundedPages }));
using (var client = new HttpClient(boundedRequests))
{
    var report = await Reader(client).ReadAsync(boundedProjects, options);
    Check(State(report) == "Partial" && boundedRequests.Requests.Count == 60, "Cross-project pagination respects the global sixty-request budget");
}
var aggregateScopes = new[] { Project, "second-project", "third-project" }; var aggregateIdentity = 0;
var aggregate = new Fixture(request =>
{
    if (request.RequestUri!.Host == "cloudresourcemanager.googleapis.com")
        return Ok(Identity(request.RequestUri.AbsolutePath.Split('/')[^1], (++aggregateIdentity).ToString(CultureInfo.InvariantCulture)));
    var job = Job("aggregate", "SUCCEEDED"); job["name"] = request.RequestUri.AbsolutePath[4..] + "/aggregate";
    var body = JsonSerializer.Serialize(new { patchJobs = new[] { job } }) + new string(' ', 3 * 1024 * 1024);
    return new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
});
using (var client = new HttpClient(aggregate))
{
    var report = await Reader(client).ReadAsync(aggregateScopes, options); var coverage = Data(report).GetProperty("coverage");
    Check(State(report) == "Partial" && coverage.GetProperty("completedScopes").GetInt32() == 2 && Data(report).GetProperty("patches").GetProperty("jobsRead").GetInt32() == 2, "Aggregate response bytes remain bounded even when individual pages fit their limits");
}
using (var client = new HttpClient(new Fixture(_ => throw new OperationCanceledException())))
    Check(State(await Reader(client).ReadAsync([Project], options)) == "Failed", "Read cancellation without caller cancellation reports unavailable evidence");
using (var client = new HttpClient(new Fixture(_ => throw new Exception("No network expected"))))
{
    var reader = new GcpPatchReader(client, _ => Task.FromResult("bad\ntoken"));
    Check(State(await reader.ReadAsync([Project], options)) == "NotConfigured", "Malformed ADC tokens cannot reach a provider");
    var canceled = new CancellationToken(true); var propagated = false;
    try { await reader.ReadAsync([Project], options, canceled); } catch (OperationCanceledException) { propagated = true; }
    Check(propagated, "Caller cancellation propagates without provider requests");
}
Console.WriteLine($"PASS: {checks} OS Config patch evidence checks.");

GcpPatchReader Reader(HttpClient client) => new(client, _ => Task.FromResult("fixture-token"));
Fixture Standard(params object[] jobs) => new(request => request.RequestUri!.Host == "cloudresourcemanager.googleapis.com" ? Ok(Identity(Project, Number)) : Ok(new { patchJobs = jobs }));
object Identity(string project, string number) => new { projectId = project, name = "projects/" + number };
Dictionary<string, object?> Job(string id, string state) => new()
{
    ["name"] = "projects/" + Project + "/patchJobs/" + id, ["state"] = state,
    ["createTime"] = now.AddHours(-2).ToString("O", CultureInfo.InvariantCulture), ["updateTime"] = now.AddHours(-1).ToString("O", CultureInfo.InvariantCulture),
    ["instanceDetailsSummary"] = new { succeededInstanceCount = "7", failedInstanceCount = "2", timedOutInstanceCount = "0", description = "RAW-SECRET" },
    ["description"] = "RAW-SECRET", ["errorMessage"] = "RAW-SECRET", ["patchConfig"] = new { preStep = "RAW-SECRET" }, ["instanceFilter"] = "RAW-SECRET"
};
JsonElement Data(AnalysisReport report) => JsonSerializer.SerializeToElement(report.Data, ReportSecurity.JsonOptions);
string State(AnalysisReport report) => Data(report).GetProperty("coverage").GetProperty("state").GetString()!;
HttpResponseMessage Ok(object value) => new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json") };
void Check(bool value, string message) { if (!value) throw new Exception("FAIL: " + message); checks++; }
async Task Throws(Func<Task<AnalysisReport>> action, string message) { var rejected = false; try { await action(); } catch (ArgumentException) { rejected = true; } Check(rejected, message); }

sealed class Fixture(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
{
    public List<(HttpMethod Method, Uri Uri, string? Bearer)> Requests { get; } = [];
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    { cancellationToken.ThrowIfCancellationRequested(); Requests.Add((request.Method, request.RequestUri!, request.Headers.Authorization?.Parameter)); return Task.FromResult(respond(request)); }
}
