using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Opscope;
using Opscope.Cloud;

const string Account = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const string Group = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const string OtherAccount = "cccccccccccccccccccccccccccccccc";
const string OtherGroup = "dddddddddddddddddddddddddddddddd";
const string Region = "us-south";
const string Secret = "fixture-private-ibm-iam-access-token";
const string Version = "2026-10-06";
var assertions = 0;
void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); assertions++; }
Dictionary<string, string> Options() => new(StringComparer.Ordinal) { ["account"] = Account, ["resource-group"] = Group, ["region"] = Region };
JsonElement Data(AnalysisReport report) => JsonSerializer.SerializeToElement(report.Data, ReportSecurity.JsonOptions);
string State(AnalysisReport report) => Data(report).GetProperty("coverage").GetProperty("state").GetString()!;
JsonElement Resources(AnalysisReport report) => Data(report).GetProperty("resources");
JsonElement Checks(AnalysisReport report) => Data(report).GetProperty("configurationEvidence").GetProperty("checks");
string Crn(string kind, string id, string location = Region, string account = Account) => $"crn:v1:bluemix:public:is:{location}:a/{account}::{kind}:{id}";
JsonObject Parent(string region = Region) => new() { ["id"] = Id(1), ["crn"] = Crn("vpc", Id(1), region), ["name"] = "PRIVATE-PARENT-NAME", ["href"] = $"https://{region}.iaas.cloud.ibm.com/v1/vpcs/{Id(1)}" };
JsonObject Resource(string kind, int number, string region = Region)
{
    var id = Id(number);
    var row = new JsonObject
    {
        ["id"] = id, ["crn"] = Crn(kind, id, kind == "subnet" ? region + "-1" : region),
        ["resource_group"] = new JsonObject { ["id"] = Group, ["name"] = "PRIVATE-GROUP-NAME", ["href"] = "https://resource-controller.cloud.ibm.com/v2/resource_groups/" + Group },
        ["name"] = "PRIVATE-RESOURCE-NAME", ["tags"] = new JsonArray("PRIVATE-TAG"), ["unexpected"] = Secret,
        ["created_at"] = "2026-10-01T00:00:00Z", ["href"] = $"https://{region}.iaas.cloud.ibm.com/v1/{Path(kind)}/{id}"
    };
    if (kind == "vpc")
    {
        row["status"] = "available"; row["classic_access"] = false;
        row["health_state"] = "ok"; row["health_reasons"] = new JsonArray();
        row["cse_source_ips"] = new JsonArray(new JsonObject { ["ip"] = "192.0.2.1" });
        row["dns"] = new JsonObject { ["resolver"] = new JsonObject { ["type"] = "system" } };
    }
    else if (kind == "subnet")
    {
        row["vpc"] = Parent(region); row["zone"] = new JsonObject { ["name"] = region + "-1" };
        row["status"] = "available"; row["ip_version"] = "ipv4"; row["ipv4_cidr_block"] = "192.0.2.0/24";
        row["available_ipv4_address_count"] = 251; row["total_ipv4_address_count"] = 256;
    }
    else
    {
        row["vpc"] = Parent(region);
        row["rules"] = new JsonArray(new JsonObject
        {
            ["id"] = "PRIVATE-RULE-ID", ["direction"] = "inbound", ["protocol"] = "tcp", ["port_min"] = 22,
            ["port_max"] = 22, ["remote"] = new JsonObject { ["cidr_block"] = "0.0.0.0/0" }
        });
        row["targets"] = new JsonArray(new JsonObject { ["id"] = "PRIVATE-TARGET-ID", ["name"] = "PRIVATE-TARGET-NAME", ["resource_type"] = "network_interface" });
    }
    return row;
}
JsonObject Vpc(int number = 1, string region = Region) => Resource("vpc", number, region);
JsonObject Subnet(int number = 2, string region = Region) => Resource("subnet", number, region);
JsonObject SecurityGroup(int number = 3, string region = Region) => Resource("security-group", number, region);
HttpResponseMessage GroupResponse(string account = Account, string group = Group) => Response(new JsonObject { ["id"] = group, ["account_id"] = account, ["name"] = "PRIVATE-GROUP-NAME", ["state"] = "ACTIVE" }.ToJsonString());
string Next(string path, string cursor = "next-page", string region = Region, string group = Group) => $"https://{region}.iaas.cloud.ibm.com/v1/{path}?version={Version}&generation=2&resource_group.id={group}&limit=100&start={Uri.EscapeDataString(cursor)}";
HttpResponseMessage Collection(string path, IEnumerable<JsonNode?> rows, int total, string? next = null, int padding = 0)
{
    var root = new JsonObject { [path] = new JsonArray(rows.ToArray()), ["total_count"] = total, ["limit"] = 100, ["first"] = new JsonObject { ["href"] = Next(path) } };
    if (next is not null) root["next"] = new JsonObject { ["href"] = next };
    if (padding != 0) root["unselected_metadata"] = new string('x', padding);
    return Response(root.ToJsonString());
}
HttpResponseMessage Normal(HttpRequestMessage request, int _) => request.RequestUri!.AbsolutePath switch
{
    "/v1/vpcs" => Collection("vpcs", [Vpc()], 1),
    "/v1/subnets" => Collection("subnets", [Subnet()], 1),
    "/v1/security_groups" => Collection("security_groups", [SecurityGroup()], 1),
    _ => throw new InvalidOperationException("Unexpected provider path")
};
async Task<(AnalysisReport Report, FixtureHandler Handler)> Read(Func<HttpRequestMessage, int, HttpResponseMessage>? response = null,
    IReadOnlyDictionary<string, string>? options = null, string? credential = Secret, string operation = "networks", bool interceptGroup = true)
{
    var handler = new FixtureHandler((request, number) => interceptGroup && request.RequestUri!.Host == "resource-controller.cloud.ibm.com"
        ? GroupResponse() : (response ?? Normal)(request, number));
    using var client = new HttpClient(handler);
    return (await new IbmVpcProvider(client, _ => credential).CollectAsync(operation, options ?? Options()), handler);
}

var valid = await Read();
Check(valid.Report.OperationSucceeded && State(valid.Report) == "complete", "The three scoped network products complete independently of service health");
var resources = Resources(valid.Report);
Check(resources.GetArrayLength() == 3 && resources.EnumerateArray().Select(resource => resource.GetProperty("type").GetString()).SequenceEqual(new[] { "network.vpc", "network.subnet", "network.securityGroup" }), "VPCs, subnets and security groups retain distinct resource types");
Check(resources[0].GetProperty("properties").GetProperty("classicAccess").ValueKind == JsonValueKind.False, "Observed classic-access false remains an observation");
Check(resources[1].GetProperty("properties").GetProperty("status").GetString() == "available" && resources[1].GetProperty("properties").GetProperty("ipVersion").GetString() == "ipv4", "Subnet metadata retains native state and IP family without its addresses");
Check(resources[2].GetProperty("properties").GetProperty("ruleCount").GetInt32() == 1 && resources[2].GetProperty("properties").GetProperty("targetCount").GetInt32() == 1, "Security-group aggregate counts do not copy rules or targets");
Check(Data(valid.Report).GetProperty("scope").GetProperty("region").GetString() == Region && resources.EnumerateArray().All(resource => resource.GetProperty("account").GetString() == Account && resource.GetProperty("region").GetString() == Region), "Every resource agrees with the configured account and regional scope");
Check(valid.Handler.Requests.Count == 4 && valid.Handler.Requests[0].Host == "resource-controller.cloud.ibm.com" && valid.Handler.Requests[0].Path == "/v2/resource_groups/" + Group, "The explicit resource group is bound to its account before regional enumeration");
Check(valid.Handler.Requests.All(request => request.Method == "GET" && request.Scheme == "https" && request.Token == Secret && request.AuthorizationScheme == "Bearer"), "Only authenticated HTTPS GET reads are sent");
Check(valid.Handler.Requests.Skip(1).All(request => request.Host == Region + ".iaas.cloud.ibm.com" && Query(request.Query).Count == 4 && Query(request.Query)["version"] == Version && Query(request.Query)["generation"] == "2" && Query(request.Query)["resource_group.id"] == Group && Query(request.Query)["limit"] == "100"), "VPC requests use the pinned version, generation, exact resource-group filter and page size");
Check(Data(valid.Report).GetProperty("configurationEvidence").GetProperty("source").GetString() == "ibm-vpc-fixed-read" && Checks(valid.Report).GetArrayLength() == 3 && Checks(valid.Report).EnumerateArray().All(check => check.GetProperty("state").GetString() == "complete" && check.GetProperty("observations").GetProperty("expectedResources").GetInt32() == 1), "Product checks expose observed and expected counts with their precise source");
var raw = JsonSerializer.Serialize(valid.Report, ReportSecurity.JsonOptions);
Check(new[] { Secret, "PRIVATE-", "192.0.2.", "0.0.0.0", "crn:", "ipv4_cidr_block", "port_min", "port_max", "cse_source_ips", "health_reasons" }.All(value => !raw.Contains(value, StringComparison.Ordinal)), "Names, tags, credentials, CRNs, addresses and raw security configuration never enter the report");
var redacted = ReportSecurity.Serialize(valid.Report);
Check(!redacted.Contains(Account, StringComparison.Ordinal) && !redacted.Contains(Group, StringComparison.Ordinal) && !redacted.Contains(Id(1), StringComparison.Ordinal) && !redacted.Contains(Id(2), StringComparison.Ordinal) && !redacted.Contains(Id(3), StringComparison.Ordinal), "Exports redact account, resource group, network and parent identities");
Check(!valid.Report.Findings.Any(), "Network metadata does not imply effective access or health findings");

foreach (var mutation in new Action<Dictionary<string, string>>[]
{
    options => options.Remove("account"), options => options.Remove("resource-group"), options => options.Remove("region"),
    options => options["account"] = "short", options => options["account"] = Account + "," + OtherAccount,
    options => options["resource-group"] = "../group", options => options["resource-group"] = "g" + Group[1..],
    options => options["region"] = Region + "-1", options => options["region"] = "https://127.0.0.1", options => options["region"] = "other-region",
    options => options["endpoint"] = "https://untrusted.invalid", options => options["api-url"] = "https://untrusted.invalid",
    options => options["resource"] = Id(1), options => options["regions"] = "us-south,eu-de"
})
{
    var options = Options(); mutation(options); var invalid = await Read(options: options);
    Check(!invalid.Report.OperationSucceeded && State(invalid.Report) == "not_configured" && invalid.Handler.Requests.Count == 0, "Invalid and ambiguous scope or endpoint overrides remain offline");
}
foreach (var token in new[] { "", "\r\nprivate", "secret with space", "secret-é", new string('x', 16385) })
{
    var invalid = await Read(credential: token);
    Check(State(invalid.Report) == "not_configured" && invalid.Handler.Requests.Count == 0, "Missing or malformed credentials do not send HTTP requests");
}
var unsupported = await Read(operation: "delete");
Check(State(unsupported.Report) == "unsupported" && unsupported.Handler.Requests.Count == 0, "Unsupported operations cannot issue provider reads");

foreach (var groupBody in new[] { GroupResponse(OtherAccount), GroupResponse(group: OtherGroup), Response("{}"), Response("{\"id\":\"" + Group + "\",\"account_id\":\"" + Account + "\",\"account_id\":\"" + OtherAccount + "\"}") })
{
    var invalid = await Read((_, _) => groupBody, interceptGroup: false);
    Check(!invalid.Report.OperationSucceeded && invalid.Handler.Requests.Count == 1 && Resources(invalid.Report).GetArrayLength() == 0, "Unverified resource-group ownership prevents regional reads even for otherwise empty collections");
}
var empty = await Read((request, _) => Collection(request.RequestUri!.AbsolutePath.Split('/')[^1], [], 0));
Check(empty.Report.OperationSucceeded && State(empty.Report) == "complete" && Resources(empty.Report).GetArrayLength() == 0 && Checks(empty.Report).EnumerateArray().All(check => check.GetProperty("observations").GetProperty("expectedResources").GetInt32() == 0), "Verified scope plus three explicit zero totals establishes only an empty supported inventory");

foreach (var body in new[] { "{}", "[]", "null", "{\"vpcs\":[]}", "{\"vpcs\":[],\"limit\":100,\"total_count\":null}", "{\"vpcs\":[],\"limit\":100,\"total_count\":\"0\"}", "{\"vpcs\":[],\"limit\":100,\"total_count\":-1}", "{\"vpcs\":{},\"limit\":100,\"total_count\":0}", "{\"vpcs\":[],\"limit\":100,\"total_count\":0,\"total_count\":1}", "PRIVATE-PROVIDER-BODY" })
{
    var malformed = await Read((_, _) => Response(body));
    Check(!malformed.Report.OperationSucceeded && Resources(malformed.Report).GetArrayLength() == 0 && !JsonSerializer.Serialize(malformed.Report).Contains("PRIVATE-PROVIDER-BODY", StringComparison.Ordinal), "Malformed collection envelopes never establish empty or expose raw provider text");
}
foreach (var mutation in new Action<JsonObject>[]
{
    row => row["resource_group"]!["id"] = OtherGroup, row => row.Remove("resource_group"), row => row["id"] = "bad-id",
    row => row["crn"] = Crn("vpc", Id(1), account: OtherAccount), row => row["crn"] = Crn("vpc", Id(1), "eu-de"),
    row => row["crn"] = Crn("subnet", Id(1)), row => row["crn"] = Crn("vpc", Id(9)), row => row.Remove("crn"),
    row => row["crn"] = Crn("vpc", Id(1)).Replace(":public:", ":dedicated:", StringComparison.Ordinal)
})
{
    var mismatch = await Read((request, number) =>
    {
        if (request.RequestUri!.AbsolutePath != "/v1/vpcs") return Normal(request, number);
        var row = Vpc(); mutation(row); return Collection("vpcs", [row], 1);
    });
    Check(State(mismatch.Report) == "partial" && !mismatch.Report.OperationSucceeded && Resources(mismatch.Report).GetArrayLength() == 2, "Unverified account, resource group, location, type or resource identity is omitted while other product evidence survives");
}
foreach (var mutation in new Action<JsonObject>[]
{
    row => row["zone"]!["name"] = "eu-de-1", row => row["zone"]!["name"] = Region + "-4", row => row.Remove("zone"),
    row => row["crn"] = Crn("subnet", Id(2), Region), row => row["crn"] = Crn("subnet", Id(2), Region + "-2")
})
{
    var mismatch = await Read((request, number) =>
    {
        if (request.RequestUri!.AbsolutePath != "/v1/subnets") return Normal(request, number);
        var row = Subnet(); mutation(row); return Collection("subnets", [row], 1);
    });
    Check(State(mismatch.Report) == "partial" && Resources(mismatch.Report).GetArrayLength() == 2, "Zonal subnet CRNs must match an explicit supported zone in the selected region");
}
var duplicate = await Read((request, number) => request.RequestUri!.AbsolutePath == "/v1/vpcs" ? Collection("vpcs", [Vpc(), Vpc()], 2) : Normal(request, number));
Check(State(duplicate.Report) == "partial" && Resources(duplicate.Report).GetArrayLength() == 3, "Duplicate identities are counted once and make enumeration incomplete");
var optional = await Read((request, number) =>
{
    if (request.RequestUri!.AbsolutePath != "/v1/vpcs") return Normal(request, number);
    var row = Vpc(); row.Remove("classic_access"); row.Remove("status"); return Collection("vpcs", [row], 1);
});
Check(optional.Report.OperationSucceeded && !Resources(optional.Report)[0].GetProperty("properties").TryGetProperty("classicAccess", out _), "Missing optional projection fields stay unknown without inventing false or invalidating enumeration");
var invalidProjection = await Read((request, number) =>
{
    if (request.RequestUri!.AbsolutePath != "/v1/vpcs") return Normal(request, number);
    var row = Vpc(); row["classic_access"] = "false"; row["status"] = "PRIVATE-UNKNOWN-STATE"; return Collection("vpcs", [row], 1);
});
Check(State(invalidProjection.Report) == "partial" && !JsonSerializer.Serialize(invalidProjection.Report).Contains("PRIVATE-UNKNOWN-STATE", StringComparison.Ordinal) && !Resources(invalidProjection.Report)[0].GetProperty("properties").TryGetProperty("classicAccess", out _), "Malformed selected metadata remains unknown and does not copy arbitrary text");
foreach (var path in new[] { "subnets", "security_groups" })
{
    var invalidParent = await Read((request, number) =>
    {
        if (request.RequestUri!.AbsolutePath != "/v1/" + path) return Normal(request, number);
        var row = path == "subnets" ? Subnet() : SecurityGroup(); row["vpc"]!["crn"] = Crn("vpc", Id(1), account: OtherAccount);
        return Collection(path, [row], 1);
    });
    Check(State(invalidParent.Report) == "partial" && Resources(invalidParent.Report).GetArrayLength() == 2, "Parent references require verified account and region before joining them to a subnet or security group");
}

foreach (var (status, expected) in new[] { (HttpStatusCode.Unauthorized, "permission_denied"), (HttpStatusCode.Forbidden, "permission_denied"), (HttpStatusCode.TooManyRequests, "rate_limited"), (HttpStatusCode.BadGateway, "failed") })
{
    var denied = await Read((_, _) => new(status) { Content = new StringContent("PRIVATE-PROVIDER-BODY " + Secret) }, interceptGroup: false);
    Check(!denied.Report.OperationSucceeded && State(denied.Report) == expected && denied.Handler.Requests.Count == 1 && !JsonSerializer.Serialize(denied.Report).Contains("PRIVATE-PROVIDER-BODY", StringComparison.Ordinal), "Scope-preflight HTTP failures retain coverage without exposing provider bodies");
    Check(Checks(denied.Report).EnumerateArray().All(check => !check.TryGetProperty("observations", out _)), "Unrequested products after preflight rejection do not publish observed zero");
}
var partlyDenied = await Read((request, number) => request.RequestUri!.AbsolutePath == "/v1/subnets" ? new(HttpStatusCode.Forbidden) : Normal(request, number));
Check(State(partlyDenied.Report) == "partial" && Resources(partlyDenied.Report).GetArrayLength() == 2, "Successful product evidence survives a separate denied source");
Check(!Checks(partlyDenied.Report)[1].TryGetProperty("observations", out _), "Denied product rows remain unknown rather than observed zero");
var rateLimited = await Read((_, _) => new(HttpStatusCode.TooManyRequests));
Check(State(rateLimited.Report) == "rate_limited" && rateLimited.Handler.Requests.Count == 2 && Checks(rateLimited.Report)[1].GetProperty("state").GetString() == "not_requested" && Checks(rateLimited.Report)[2].GetProperty("state").GetString() == "not_requested", "Quota rejection stops without retrying or querying later products");
var timeout = await Read((_, _) => throw new OperationCanceledException());
Check(State(timeout.Report) == "timed_out" && timeout.Handler.Requests.Count == 2, "A provider deadline timeout stops later products");
var redirect = await Read((_, _) => new(HttpStatusCode.Redirect) { Headers = { Location = new Uri("https://untrusted.invalid/credential-sink") } });
Check(!redirect.Report.OperationSucceeded && redirect.Handler.Requests.All(request => request.Host is "resource-controller.cloud.ibm.com" or "us-south.iaas.cloud.ibm.com"), "Redirect locations never become requested destinations");
using (var cancel = new CancellationTokenSource())
{
    cancel.Cancel(); var handler = new FixtureHandler(Normal); using var client = new HttpClient(handler);
    try { await new IbmVpcProvider(client, _ => Secret).CollectAsync("networks", Options(), cancel.Token); throw new InvalidOperationException("Caller cancellation was ignored"); }
    catch (OperationCanceledException) { Check(handler.Requests.Count == 0, "Caller cancellation propagates before provider requests"); }
}

var paged = await Read((request, number) =>
{
    if (request.RequestUri!.AbsolutePath != "/v1/vpcs") return Collection(request.RequestUri.AbsolutePath.Split('/')[^1], [], 0);
    return Query(request.RequestUri.Query).ContainsKey("start") ? Collection("vpcs", [Vpc(101)], 101)
        : Collection("vpcs", Enumerable.Range(1, 100).Select(value => Vpc(value)), 101, Next("vpcs", "cursor+/=safe"));
});
Check(paged.Report.OperationSucceeded && Resources(paged.Report).GetArrayLength() == 101 && paged.Handler.Requests.Count == 5 && Query(paged.Handler.Requests[2].Query)["start"] == "cursor+/=safe", "Only a validated encoded cursor is carried into a reconstructed fixed request");
foreach (var next in new[]
{
    "https://untrusted.invalid/v1/vpcs?start=foreign", "http://us-south.iaas.cloud.ibm.com/v1/vpcs?start=insecure",
    Next("subnets"), Next("vpcs", region: "eu-de"), Next("vpcs", group: OtherGroup),
    Next("vpcs").Replace("generation=2", "generation=1", StringComparison.Ordinal),
    Next("vpcs").Replace(Version, "2027-01-01", StringComparison.Ordinal),
    Next("vpcs") + "&start=duplicate", Next("vpcs") + "&endpoint=https://untrusted.invalid", Next("vpcs") + "#fragment",
    Next("vpcs").Replace("start=next-page", "start=", StringComparison.Ordinal), Next("vpcs", new string('x', 1025))
})
{
    var malicious = await Read((request, number) => request.RequestUri!.AbsolutePath == "/v1/vpcs"
        ? Collection("vpcs", [Vpc()], 2, next) : Collection(request.RequestUri.AbsolutePath.Split('/')[^1], [], 0));
    Check(State(malicious.Report) == "partial" && malicious.Handler.Requests.Count == 4 && malicious.Handler.Requests.All(request => !request.Query.Contains("start=", StringComparison.Ordinal)), "Foreign or ambiguous pagination links cannot supply a follow-up URL or query");
}
var repeat = await Read((request, _) => request.RequestUri!.AbsolutePath == "/v1/vpcs"
    ? Query(request.RequestUri.Query).ContainsKey("start") ? Collection("vpcs", [Vpc(2)], 3, Next("vpcs")) : Collection("vpcs", [Vpc()], 3, Next("vpcs"))
    : Collection(request.RequestUri.AbsolutePath.Split('/')[^1], [], 0));
Check(State(repeat.Report) == "partial" && repeat.Handler.Requests.Count <= 5, "Repeated pagination cursors stop enumeration");
var changedTotal = await Read((request, _) => request.RequestUri!.AbsolutePath == "/v1/vpcs"
    ? Query(request.RequestUri.Query).ContainsKey("start") ? Collection("vpcs", [Vpc(2)], 3) : Collection("vpcs", [Vpc()], 2, Next("vpcs"))
    : Collection(request.RequestUri.AbsolutePath.Split('/')[^1], [], 0));
Check(State(changedTotal.Report) == "partial", "Changing collection totals prevent a complete claim");
foreach (var rateLimit in new[] { true, false })
{
    var interrupted = await Read((request, _) =>
    {
        if (request.RequestUri!.AbsolutePath != "/v1/vpcs") throw new InvalidOperationException("Quota and timeout failures must stop later products");
        if (!Query(request.RequestUri.Query).ContainsKey("start")) return Collection("vpcs", Enumerable.Range(1, 100).Select(value => Vpc(value)), 101, Next("vpcs"));
        if (rateLimit) return new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        throw new OperationCanceledException();
    });
    Check(State(interrupted.Report) == "partial" && Resources(interrupted.Report).GetArrayLength() == 100 && interrupted.Handler.Requests.Count == 3 && Checks(interrupted.Report)[1].GetProperty("state").GetString() == "not_requested", "Quota and timeout failures after a useful page retain partial evidence and stop later products");
}
var budget = await Read((request, _) =>
{
    if (request.RequestUri!.AbsolutePath != "/v1/vpcs") throw new InvalidOperationException("The exhausted global resource budget cannot query another product");
    var query = Query(request.RequestUri.Query); var page = query.TryGetValue("start", out var cursor) ? int.Parse(cursor, CultureInfo.InvariantCulture) : 1;
    return Collection("vpcs", Enumerable.Range((page - 1) * 100 + 1, 100).Select(value => Vpc(value)), 1001, Next("vpcs", (page + 1).ToString(CultureInfo.InvariantCulture)));
});
Check(State(budget.Report) == "partial" && Resources(budget.Report).GetArrayLength() == 1000 && budget.Handler.Requests.Count == 11, "The global resource and per-product page limits bound enumeration");
var oversized = await Read((_, _) => Response(new string('x', 4 * 1024 * 1024 + 1)));
Check(State(oversized.Report) == "partial" && oversized.Handler.Requests.Count == 2 && Resources(oversized.Report).GetArrayLength() == 0, "Content-Length budget stops later product reads before parsing an oversized response");
var streamed = await Read((_, _) => new(HttpStatusCode.OK) { Content = new StreamContent(new NonSeekableStream(new byte[4 * 1024 * 1024 + 1])) });
Check(State(streamed.Report) == "partial" && streamed.Handler.Requests.Count == 2, "Unknown-length streams are bounded during reading");
var aggregated = await Read((request, _) =>
{
    var path = request.RequestUri!.AbsolutePath.Split('/')[^1];
    if (path != "vpcs") return Collection(path, [], 0, padding: 3 * 1024 * 1024);
    var next = Query(request.RequestUri.Query).ContainsKey("start");
    return Collection("vpcs", Enumerable.Range(next ? 101 : 1, 100).Select(value => Vpc(value)), 200, next ? null : Next("vpcs"), 3 * 1024 * 1024);
});
Check(State(aggregated.Report) == "partial" && Resources(aggregated.Report).GetArrayLength() == 200 && aggregated.Handler.Requests.Count == 4, "The aggregate byte budget spans pages, products and scope verification");

Console.WriteLine($"PASS: {assertions} IBM regional VPC checks.");

static string Id(int value) => "r006-" + value.ToString("x8", CultureInfo.InvariantCulture) + "-2222-3333-4444-555555555555";
static string Path(string kind) => kind switch { "vpc" => "vpcs", "subnet" => "subnets", _ => "security_groups" };
static HttpResponseMessage Response(string value) => new(HttpStatusCode.OK) { Content = new StringContent(value, Encoding.UTF8, "application/json") };
static Dictionary<string, string> Query(string query) => query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries).Select(pair => pair.Split('=', 2)).ToDictionary(pair => Uri.UnescapeDataString(pair[0]), pair => Uri.UnescapeDataString(pair.Length == 2 ? pair[1] : ""), StringComparer.Ordinal);
sealed record RequestEvidence(string Method, string Scheme, string Host, string Path, string Query, string? AuthorizationScheme, string? Token);
sealed class FixtureHandler(Func<HttpRequestMessage, int, HttpResponseMessage> response) : HttpMessageHandler
{
    public List<RequestEvidence> Requests { get; } = [];
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); var uri = request.RequestUri!;
        Requests.Add(new(request.Method.Method, uri.Scheme, uri.Host, uri.AbsolutePath, uri.Query, request.Headers.Authorization?.Scheme, request.Headers.Authorization?.Parameter));
        return Task.FromResult(response(request, Requests.Count));
    }
}
sealed class NonSeekableStream(byte[] bytes) : MemoryStream(bytes)
{
    public override bool CanSeek => false;
}
