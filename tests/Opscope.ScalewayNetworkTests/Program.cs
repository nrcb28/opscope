using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Opscope;
using Opscope.Cloud;

const string Project = "11111111-2222-3333-4444-555555555555";
const string OtherProject = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const string Secret = "fixture-private-scaleway-secret";
var assertions = 0;
void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); assertions++; }
Dictionary<string, string> Options() => new(StringComparer.Ordinal) { ["project"] = Project, ["region"] = "fr-par" };
JsonElement Data(AnalysisReport report) => JsonSerializer.SerializeToElement(report.Data, ReportSecurity.JsonOptions);
string State(AnalysisReport report) => Data(report).GetProperty("coverage").GetProperty("state").GetString()!;
JsonObject Vpc(int id = 1, string? region = null) => new()
{
    ["id"] = Id(id), ["project_id"] = Project, ["region"] = region ?? "fr-par", ["is_default"] = false,
    ["routing_enabled"] = true, ["custom_routes_propagation_enabled"] = false,
    ["name"] = "private-vpc-name", ["tags"] = new JsonArray("PRIVATE-TAG"), ["unexpected"] = Secret
};
JsonObject Network(int id = 2, string? region = null) => new()
{
    ["id"] = Id(id), ["project_id"] = Project, ["region"] = region ?? "fr-par", ["vpc_id"] = Id(1),
    ["dhcp_enabled"] = true, ["default_route_propagation_enabled"] = false,
    ["name"] = "private-network-name", ["tags"] = new JsonArray("PRIVATE-TAG"),
    ["subnets"] = new JsonArray(new JsonObject { ["subnet"] = "192.0.2.0/24", ["project_id"] = OtherProject })
};
HttpResponseMessage JsonResponse(string kind, IEnumerable<JsonNode?> rows, int total, int padding = 0)
{
    var root = new JsonObject { [kind] = new JsonArray(rows.ToArray()), ["total_count"] = total };
    if (padding != 0) root["unselected_metadata"] = new string('x', padding);
    return Response(root.ToJsonString());
}
HttpResponseMessage Normal(HttpRequestMessage request, int _) => request.RequestUri!.AbsolutePath.EndsWith("/vpcs", StringComparison.Ordinal)
    ? JsonResponse("vpcs", [Vpc()], 1) : JsonResponse("private_networks", [Network()], 1);
async Task<(AnalysisReport Report, FixtureHandler Handler)> Read(Func<HttpRequestMessage, int, HttpResponseMessage>? response = null,
    IReadOnlyDictionary<string, string>? options = null, string? credential = Secret, string operation = "networks")
{
    var handler = new FixtureHandler(response ?? Normal);
    using var client = new HttpClient(handler);
    var provider = new ScalewayNetworkProvider(client, _ => credential);
    return (await provider.CollectAsync(operation, options ?? Options()), handler);
}

var valid = await Read();
Check(valid.Report.OperationSucceeded && State(valid.Report) == "complete", "Both scoped VPC products can complete independently of infrastructure health");
var resources = Data(valid.Report).GetProperty("resources");
Check(resources.GetArrayLength() == 2 && resources[0].GetProperty("type").GetString() == "network.vpc" && resources[1].GetProperty("type").GetString() == "network.privateNetwork", "VPC and Private Network retain distinct resource types");
Check(resources[0].GetProperty("properties").GetProperty("isDefault").ValueKind == JsonValueKind.False && resources[1].GetProperty("properties").GetProperty("dhcpEnabled").GetBoolean(), "Observed false and true booleans remain genuine observations");
Check(Data(valid.Report).GetProperty("scope").GetProperty("region").GetString() == "fr-par" && resources.EnumerateArray().All(resource => resource.GetProperty("account").GetString() == Project && resource.GetProperty("region").GetString() == "fr-par"), "Every resource agrees with the explicit project/region scope");
Check(valid.Handler.Requests.Count == 2 && valid.Handler.Requests.All(request => request.Method == "GET" && request.Host == "api.scaleway.com" && request.Scheme == "https" && request.Token == Secret && request.Query == $"?project_id={Project}&page=1&page_size=100"), "Only fixed HTTPS GETs with exact scope, pagination and backend token are sent");
var raw = JsonSerializer.Serialize(valid.Report, ReportSecurity.JsonOptions);
Check(new[] { Secret, "private-vpc-name", "private-network-name", "PRIVATE-TAG", "192.0.2.0", OtherProject, "subnets" }.All(value => !raw.Contains(value, StringComparison.Ordinal)), "Unselected names, tags, secrets, subnets and unrelated project identities never enter reports");
var redacted = ReportSecurity.Serialize(valid.Report);
Check(!redacted.Contains(Project, StringComparison.Ordinal) && !redacted.Contains(Id(1), StringComparison.Ordinal) && !redacted.Contains(Id(2), StringComparison.Ordinal), "Exports redact project, network and parent VPC identities");
Check(!valid.Report.Findings.Any() && valid.Report.Warnings!.Any(warning => warning.Contains("do not establish", StringComparison.Ordinal)), "Metadata does not create an inferred isolation or health verdict");
var normalChecks = Data(valid.Report).GetProperty("configurationEvidence").GetProperty("checks");
Check(normalChecks.GetArrayLength() == 2 && normalChecks.EnumerateArray().All(check => check.GetProperty("state").GetString() == "complete" && check.GetProperty("observations").GetProperty("expectedResources").GetInt32() == 1), "Per-product evidence distinguishes observed and expected enumeration counts");

foreach (var mutation in new Action<Dictionary<string, string>>[]
{
    options => options.Remove("project"), options => options.Remove("region"), options => { options.Remove("region"); options["zone"] = "fr-par-1"; },
    options => options["region"] = "fr-par-1", options => options["region"] = "https://127.0.0.1", options => options["region"] = "other-region",
    options => options["project"] = "../project", options => options["project"] = Project + "," + OtherProject,
    options => options["endpoint"] = "https://untrusted.invalid", options => options["api-url"] = "https://untrusted.invalid",
    options => options["resource"] = Id(1), options => options["regions"] = "fr-par,nl-ams"
})
{
    var options = Options(); mutation(options);
    var invalid = await Read(options: options);
    Check(!invalid.Report.OperationSucceeded && State(invalid.Report) == "not_configured" && invalid.Handler.Requests.Count == 0, "Invalid or ambiguous scope and unsupported overrides remain offline");
}
foreach (var token in new[] { "", "\r\nprivate", "secret with space", "secret-é", new string('x', 16385) })
{
    var noToken = await Read(credential: token);
    Check(State(noToken.Report) == "not_configured" && noToken.Handler.Requests.Count == 0, "Missing or malformed credentials never trigger HTTP reads");
}
var unsupported = await Read(operation: "delete");
Check(State(unsupported.Report) == "unsupported" && unsupported.Handler.Requests.Count == 0, "The regional reader cannot be used for a mutation operation");
var zoneOptions = Options(); zoneOptions["zone"] = "nl-ams-1";
var zoneIgnored = await Read(options: zoneOptions);
Check(zoneIgnored.Report.OperationSucceeded && zoneIgnored.Handler.Requests.All(request => request.Path.StartsWith("/vpc/v2/regions/fr-par/", StringComparison.Ordinal)) && zoneIgnored.Report.Warnings!.Any(warning => warning.Contains("zone option does not", StringComparison.Ordinal)), "An unrelated zone never changes or silently narrows the explicit region");

foreach (var region in new[] { "fr-par", "nl-ams", "pl-waw" })
{
    var options = Options(); options["region"] = region;
    var selected = await Read((request, _) => request.RequestUri!.AbsolutePath.EndsWith("/vpcs", StringComparison.Ordinal)
        ? JsonResponse("vpcs", [Vpc(region: region)], 1) : JsonResponse("private_networks", [Network(region: region)], 1), options);
    Check(selected.Report.OperationSucceeded && selected.Handler.Requests.All(request => request.Path.StartsWith($"/vpc/v2/regions/{region}/", StringComparison.Ordinal)), "Supported regions retain the selected API path and returned identity");
}

var empty = await Read((request, _) => JsonResponse(request.RequestUri!.AbsolutePath.EndsWith("/vpcs", StringComparison.Ordinal) ? "vpcs" : "private_networks", [], 0));
Check(empty.Report.OperationSucceeded && Data(empty.Report).GetProperty("resources").GetArrayLength() == 0 && State(empty.Report) == "complete", "Explicit zero totals with completed empty pages mean only an empty supported inventory");
Check(Data(empty.Report).GetProperty("configurationEvidence").GetProperty("checks").EnumerateArray().All(check => check.GetProperty("observations").GetProperty("expectedResources").GetInt32() == 0) && empty.Report.Warnings!.Any(warning => warning.Contains("not a security", StringComparison.Ordinal)), "An observed empty list does not become a healthy/security verdict");
foreach (var body in new[] { "{}", "[]", "null", "{\"vpcs\":[]}", "{\"vpcs\":[],\"total_count\":null}", "{\"vpcs\":[],\"total_count\":\"0\"}", "{\"vpcs\":[],\"total_count\":-1}", "{\"vpcs\":{},\"total_count\":0}", "{\"vpcs\":[],\"total_count\":0,\"total_count\":1}", "PRIVATE-RAW-ERROR" })
{
    var malformed = await Read((_, _) => Response(body));
    Check(!malformed.Report.OperationSucceeded && State(malformed.Report) == "failed" && Data(malformed.Report).GetProperty("resources").GetArrayLength() == 0 && !JsonSerializer.Serialize(malformed.Report).Contains("PRIVATE-RAW-ERROR", StringComparison.Ordinal), "Missing, duplicate or malformed envelopes never establish zero resources or echo raw provider text");
}
foreach (var mutate in new Action<JsonObject>[]
{
    row => row["project_id"] = OtherProject, row => row.Remove("project_id"), row => row["id"] = "bad-id",
    row => row["region"] = "nl-ams", row => row.Remove("region"), row => row["region"] = "fr-par-1"
})
{
    var mismatch = await Read((request, _) =>
    {
        if (request.RequestUri!.AbsolutePath.EndsWith("/vpcs", StringComparison.Ordinal)) { var row = Vpc(); mutate(row); return JsonResponse("vpcs", [row], 1); }
        return JsonResponse("private_networks", [Network()], 1);
    });
    Check(!mismatch.Report.OperationSucceeded && State(mismatch.Report) == "partial" && Data(mismatch.Report).GetProperty("resources").GetArrayLength() == 1, "Unverified VPC identities are omitted while independent valid network observations remain partial");
}
var nullRow = await Read((request, _) => request.RequestUri!.AbsolutePath.EndsWith("/vpcs", StringComparison.Ordinal) ? JsonResponse("vpcs", [null], 1) : JsonResponse("private_networks", [], 0));
Check(State(nullRow.Report) == "partial" && Data(nullRow.Report).GetProperty("resources").GetArrayLength() == 0, "Malformed resource rows cannot become complete inventory");
var unknownBoolean = await Read((request, _) =>
{
    if (!request.RequestUri!.AbsolutePath.EndsWith("/vpcs", StringComparison.Ordinal)) return JsonResponse("private_networks", [Network()], 1);
    var row = Vpc(); row.Remove("routing_enabled"); row["is_default"] = "false"; return JsonResponse("vpcs", [row], 1);
});
var unknownProperties = Data(unknownBoolean.Report).GetProperty("resources")[0].GetProperty("properties");
Check(State(unknownBoolean.Report) == "partial" && !unknownProperties.TryGetProperty("routingEnabled", out _) && !unknownProperties.TryGetProperty("isDefault", out _), "Unknown boolean configuration remains omitted rather than false");
var unknownVpc = await Read((request, _) =>
{
    if (request.RequestUri!.AbsolutePath.EndsWith("/vpcs", StringComparison.Ordinal)) return JsonResponse("vpcs", [], 0);
    var row = Network(); row["vpc_id"] = "PRIVATE-NON-UUID"; return JsonResponse("private_networks", [row], 1);
});
Check(State(unknownVpc.Report) == "partial" && !JsonSerializer.Serialize(unknownVpc.Report).Contains("PRIVATE-NON-UUID", StringComparison.Ordinal), "Invalid parent references remain unknown without copying arbitrary provider text");

foreach (var (status, expected) in new[] { (HttpStatusCode.Unauthorized, "permission_denied"), (HttpStatusCode.Forbidden, "permission_denied"), (HttpStatusCode.TooManyRequests, "rate_limited"), (HttpStatusCode.BadGateway, "failed") })
{
    var denied = await Read((_, _) => new(status) { Content = new StringContent("PRIVATE-PROVIDER-BODY " + Secret) });
    Check(!denied.Report.OperationSucceeded && State(denied.Report) == expected && !JsonSerializer.Serialize(denied.Report).Contains("PRIVATE-PROVIDER-BODY", StringComparison.Ordinal), "HTTP errors preserve explicit coverage and omit provider bodies");
    Check(Data(denied.Report).GetProperty("configurationEvidence").GetProperty("checks").EnumerateArray().All(check => !check.TryGetProperty("observations", out _)), "Failed, denied and unrequested checks do not publish a zero observation");
    if (status == HttpStatusCode.TooManyRequests) Check(denied.Handler.Requests.Count == 1 && Data(denied.Report).GetProperty("configurationEvidence").GetProperty("checks")[1].GetProperty("state").GetString() == "not_requested", "Quota rejection stops without retries or additional product reads");
}
var redirect = await Read((_, _) => new(HttpStatusCode.Redirect) { Headers = { Location = new Uri("https://untrusted.invalid/credential-sink") } });
Check(!redirect.Report.OperationSucceeded && redirect.Handler.Requests.All(request => request.Host == "api.scaleway.com") && redirect.Handler.Requests.Count == 2, "Redirect destinations never become follow-up requests");
var partlyDenied = await Read((request, _) => request.RequestUri!.AbsolutePath.EndsWith("/vpcs", StringComparison.Ordinal) ? JsonResponse("vpcs", [Vpc()], 1) : new(HttpStatusCode.Forbidden));
Check(State(partlyDenied.Report) == "partial" && Data(partlyDenied.Report).GetProperty("resources").GetArrayLength() == 1, "Successful VPC evidence survives an independent denied network read without claiming completeness");
var timeout = await Read((_, _) => throw new OperationCanceledException());
Check(State(timeout.Report) == "timed_out" && timeout.Handler.Requests.Count == 1, "Internal deadline failures remain unavailable and stop further products");
foreach (var rateLimit in new[] { true, false })
{
    var interruptedPage = await Read((request, number) =>
    {
        if (!request.RequestUri!.AbsolutePath.EndsWith("/vpcs", StringComparison.Ordinal))
            throw new InvalidOperationException("Quota or timeout must stop the next product even after useful evidence.");
        if (number == 1) return JsonResponse("vpcs", Enumerable.Range(1, 100).Select(value => Vpc(value)), 101);
        if (rateLimit) return new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        throw new OperationCanceledException();
    });
    var interruptedChecks = Data(interruptedPage.Report).GetProperty("configurationEvidence").GetProperty("checks");
    Check(State(interruptedPage.Report) == "partial" && interruptedPage.Handler.Requests.Count == 2 && Data(interruptedPage.Report).GetProperty("resources").GetArrayLength() == 100,
        "Quota or timeout after a successful page retains useful evidence and sends no additional product read");
    Check(interruptedChecks[0].GetProperty("state").GetString() == "partial" && interruptedChecks[0].GetProperty("observations").GetProperty("observedResources").GetInt32() == 100 &&
        interruptedChecks[1].GetProperty("state").GetString() == "not_requested" && !interruptedChecks[1].TryGetProperty("observations", out _),
        "Interrupted pagination keeps observed counts partial while the unread product remains unknown");
}
using (var cancel = new CancellationTokenSource())
{
    cancel.Cancel(); var handler = new FixtureHandler(Normal); using var client = new HttpClient(handler);
    try { await new ScalewayNetworkProvider(client, _ => Secret).CollectAsync("networks", Options(), cancel.Token); throw new Exception("Caller cancellation ignored"); }
    catch (OperationCanceledException) { Check(handler.Requests.Count == 0, "Caller cancellation propagates before any provider request"); }
}

var paged = await Read((request, _) =>
{
    if (!request.RequestUri!.AbsolutePath.EndsWith("/vpcs", StringComparison.Ordinal)) return JsonResponse("private_networks", [], 0);
    return request.RequestUri.Query.Contains("page=1&", StringComparison.Ordinal) ? JsonResponse("vpcs", Enumerable.Range(1, 100).Select(number => Vpc(number)), 101) : JsonResponse("vpcs", [Vpc(101)], 101);
});
Check(paged.Report.OperationSucceeded && Data(paged.Report).GetProperty("resources").GetArrayLength() == 101 && paged.Handler.Requests.Count == 3 && paged.Handler.Requests[1].Query.Contains("page=2&", StringComparison.Ordinal), "Pagination follows explicit totals within the same project/region");
var changedTotal = await Read((request, _) => request.RequestUri!.AbsolutePath.EndsWith("/vpcs", StringComparison.Ordinal)
    ? request.RequestUri.Query.Contains("page=1&", StringComparison.Ordinal) ? JsonResponse("vpcs", Enumerable.Range(1, 100).Select(number => Vpc(number)), 101) : JsonResponse("vpcs", [Vpc(101)], 102)
    : JsonResponse("private_networks", [], 0));
Check(State(changedTotal.Report) == "partial" && Data(changedTotal.Report).GetProperty("resources").GetArrayLength() == 100, "Changing total_count makes pagination incomplete without claiming absence");
var shortPage = await Read((request, _) => request.RequestUri!.AbsolutePath.EndsWith("/vpcs", StringComparison.Ordinal) ? JsonResponse("vpcs", [Vpc()], 101) : JsonResponse("private_networks", [], 0));
Check(State(shortPage.Report) == "partial" && shortPage.Handler.Requests.Count == 2, "A short page with unobserved declared resources is partial rather than an invented zero/complete remainder");
var duplicate = await Read((request, _) => request.RequestUri!.AbsolutePath.EndsWith("/vpcs", StringComparison.Ordinal) ? JsonResponse("vpcs", [Vpc(), Vpc()], 2) : JsonResponse("private_networks", [], 0));
Check(State(duplicate.Report) == "partial" && Data(duplicate.Report).GetProperty("resources").GetArrayLength() == 1, "Duplicate identities are not counted twice");
var budget = await Read((request, _) =>
{
    if (!request.RequestUri!.AbsolutePath.EndsWith("/vpcs", StringComparison.Ordinal)) throw new Exception("An exhausted global resource budget cannot query another product");
    var page = int.Parse(request.RequestUri.Query.Split("page=", StringSplitOptions.None)[1].Split('&')[0], System.Globalization.CultureInfo.InvariantCulture);
    return JsonResponse("vpcs", Enumerable.Range((page - 1) * 100 + 1, 100).Select(number => Vpc(number)), 1001);
});
Check(State(budget.Report) == "partial" && Data(budget.Report).GetProperty("resources").GetArrayLength() == 1000 && budget.Handler.Requests.Count == 10, "The global resource and per-product page bounds prevent unlimited enumeration");
Check(Data(budget.Report).GetProperty("configurationEvidence").GetProperty("checks")[1].GetProperty("state").GetString() == "partial", "A product omitted by the global bound is explicitly incomplete");

var oversized = await Read((_, _) => Response(new string('x', 4 * 1024 * 1024 + 1)));
Check(State(oversized.Report) == "partial" && Data(oversized.Report).GetProperty("resources").GetArrayLength() == 0, "Content-Length limits reject oversized provider data before parsing");
var streamed = await Read((_, _) => new(HttpStatusCode.OK) { Content = new StreamContent(new NonSeekableStream(new byte[4 * 1024 * 1024 + 1])) });
Check(State(streamed.Report) == "partial", "Unknown-length response streams are bounded while reading");
var aggregated = await Read((request, _) =>
{
    if (!request.RequestUri!.AbsolutePath.EndsWith("/vpcs", StringComparison.Ordinal)) return JsonResponse("private_networks", [], 0, 3 * 1024 * 1024);
    var page = request.RequestUri.Query.Contains("page=1&", StringComparison.Ordinal) ? 1 : 2;
    return JsonResponse("vpcs", Enumerable.Range((page - 1) * 100 + 1, 100).Select(number => Vpc(number)), 200, 3 * 1024 * 1024);
});
Check(State(aggregated.Report) == "partial" && Data(aggregated.Report).GetProperty("resources").GetArrayLength() == 200, "Aggregate response bytes remain bounded across successful pages and separate products");

Console.WriteLine($"PASS: {assertions} Scaleway regional network checks.");

static string Id(int value) => value.ToString("x8", System.Globalization.CultureInfo.InvariantCulture) + "-2222-3333-4444-555555555555";
static HttpResponseMessage Response(string value) => new(HttpStatusCode.OK) { Content = new StringContent(value, Encoding.UTF8, "application/json") };
sealed record RequestEvidence(string Method, string Scheme, string Host, string Path, string Query, string? Token);
sealed class FixtureHandler(Func<HttpRequestMessage, int, HttpResponseMessage> response) : HttpMessageHandler
{
    public List<RequestEvidence> Requests { get; } = [];
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var uri = request.RequestUri!;
        Requests.Add(new(request.Method.Method, uri.Scheme, uri.Host, uri.AbsolutePath, uri.Query, request.Headers.TryGetValues("X-Auth-Token", out var tokens) ? tokens.Single() : null));
        return Task.FromResult(response(request, Requests.Count));
    }
}
sealed class NonSeekableStream(byte[] bytes) : MemoryStream(bytes)
{
    public override bool CanSeek => false;
}
