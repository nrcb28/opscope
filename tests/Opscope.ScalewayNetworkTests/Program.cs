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
Dictionary<string, string> ZonalOptions(string zone = "fr-par-1") => new(StringComparer.Ordinal) { ["project"] = Project, ["region"] = zone[..^2], ["zone"] = zone };
JsonElement Data(AnalysisReport report) => JsonSerializer.SerializeToElement(report.Data, ReportSecurity.JsonOptions);
string State(AnalysisReport report) => Data(report).GetProperty("coverage").GetProperty("state").GetString()!;
JsonElement ProductCheck(AnalysisReport report, string check) => Data(report).GetProperty("configurationEvidence").GetProperty("checks").EnumerateArray().Single(value => value.GetProperty("check").GetString() == check);
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
JsonObject Gateway(int id = 3, string zone = "fr-par-1") => new()
{
    ["id"] = Id(id), ["project_id"] = Project, ["zone"] = zone, ["status"] = "running",
    ["bastion_enabled"] = false, ["smtp_enabled"] = true, ["is_legacy"] = false,
    ["name"] = "PRIVATE-GATEWAY-NAME", ["tags"] = new JsonArray("PRIVATE-GATEWAY-TAG"),
    ["ipv4"] = new JsonObject { ["address"] = "192.0.2.30" }, ["bastion_allowed_ips"] = new JsonArray("192.0.2.0/24"),
    ["gateway_networks"] = new JsonArray(new JsonObject { ["private_network_id"] = Id(900), ["ipam_ip_id"] = Secret }),
    ["version"] = "PRIVATE-GATEWAY-SOFTWARE", ["unexpected"] = Secret
};
JsonObject LoadBalancer(int id = 4, string zone = "fr-par-1") => new()
{
    ["id"] = Id(id), ["project_id"] = Project, ["zone"] = zone, ["region"] = zone[..^2], ["status"] = "ready",
    ["frontend_count"] = 0, ["backend_count"] = 2, ["private_network_count"] = 0, ["route_count"] = 0,
    ["name"] = "PRIVATE-LOAD-BALANCER-NAME", ["description"] = Secret, ["tags"] = new JsonArray("PRIVATE-LOAD-BALANCER-TAG"),
    ["ip"] = new JsonArray(new JsonObject { ["ip_address"] = "192.0.2.40" }),
    ["subscriber"] = new JsonObject { ["email"] = "private-subscriber@example.invalid" },
    ["certificates"] = new JsonArray(new JsonObject { ["private_key"] = Secret }),
    ["instances"] = new JsonArray(new JsonObject { ["id"] = Id(901), ["ip_address"] = "192.0.2.41" })
};
HttpResponseMessage JsonResponse(string kind, IEnumerable<JsonNode?> rows, int total, int padding = 0)
{
    var root = new JsonObject { [kind] = new JsonArray(rows.ToArray()), ["total_count"] = total };
    if (padding != 0) root["unselected_metadata"] = new string('x', padding);
    return Response(root.ToJsonString());
}
HttpResponseMessage Normal(HttpRequestMessage request, int _) => request.RequestUri!.AbsolutePath.EndsWith("/vpcs", StringComparison.Ordinal)
    ? JsonResponse("vpcs", [Vpc()], 1) : JsonResponse("private_networks", [Network()], 1);
string CollectionName(HttpRequestMessage request) => request.RequestUri!.AbsolutePath.Split('/')[^1] switch
{
    "vpcs" => "vpcs", "private-networks" => "private_networks", "gateways" => "gateways", "lbs" => "lbs",
    _ => throw new InvalidOperationException("Unlisted fixed product request")
};
HttpResponseMessage ZonalNormal(HttpRequestMessage request, int _) => CollectionName(request) switch
{
    "vpcs" => JsonResponse("vpcs", [Vpc(region: request.RequestUri!.AbsolutePath.Split('/')[4])], 1),
    "private_networks" => JsonResponse("private_networks", [Network(region: request.RequestUri!.AbsolutePath.Split('/')[4])], 1),
    "gateways" => JsonResponse("gateways", [Gateway(zone: request.RequestUri!.AbsolutePath.Split('/')[4])], 1),
    "lbs" => JsonResponse("lbs", [LoadBalancer(zone: request.RequestUri!.AbsolutePath.Split('/')[4])], 1),
    _ => throw new InvalidOperationException("Unlisted fixed product request")
};
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
    options => options["project"] = Project + "\n", options => options["region"] = "fr-par\n",
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
var zoneMismatch = await Read(options: zoneOptions);
Check(!zoneMismatch.Report.OperationSucceeded && State(zoneMismatch.Report) == "not_configured" && zoneMismatch.Handler.Requests.Count == 0, "A supplied zone outside the explicit region is rejected before any regional or zonal request");

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
Check(Data(budget.Report).GetProperty("configurationEvidence").GetProperty("checks")[1].GetProperty("state").GetString() == "not_requested", "A product omitted by the global bound remains explicitly unrequested");

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

var regionalSelection = Data(valid.Report).GetProperty("configurationEvidence");
Check(regionalSelection.GetProperty("source").GetString() == "scaleway-vpc-v2" && !regionalSelection.GetProperty("selection").GetProperty("zonalProductsRequested").GetBoolean(), "Region-only evidence preserves its established source and explicitly leaves zonal products unrequested");
Check(regionalSelection.GetProperty("selection").GetProperty("region").GetString() == "fr-par" && !regionalSelection.GetProperty("selection").TryGetProperty("zone", out _), "A missing zone remains absent rather than inferred from the configured region");

var zonal = await Read(ZonalNormal, ZonalOptions());
var zonalData = Data(zonal.Report);
var zonalResources = zonalData.GetProperty("resources").EnumerateArray().ToArray();
Check(zonal.Report.OperationSucceeded && State(zonal.Report) == "complete" && zonalResources.Length == 4, "An explicit compatible zone adds gateway and load-balancer metadata to the two regional products");
Check(zonalResources.Select(resource => resource.GetProperty("type").GetString()).SequenceEqual(new[] { "network.vpc", "network.privateNetwork", "network.gateway", "network.load-balancer" }), "Regional and zonal products retain four distinct normalized resource types");
Check(zonal.Handler.Requests.Select(request => request.Path).SequenceEqual(new[] { "/vpc/v2/regions/fr-par/vpcs", "/vpc/v2/regions/fr-par/private-networks", "/vpc-gw/v2/zones/fr-par-1/gateways", "/lb/v1/zones/fr-par-1/lbs" }), "Only the two approved regional and two approved zonal routes are constructed");
Check(zonal.Handler.Requests.All(request => request.Method == "GET" && request.Host == "api.scaleway.com" && request.Scheme == "https" && request.Query == $"?project_id={Project}&page=1&page_size=100" + (request.Path.EndsWith("/gateways", StringComparison.Ordinal) ? "&include_legacy=true" : "") && request.Token == Secret), "All four products share exact project filtering and fixed backend-only HTTPS GET authentication, with gateway legacy inclusion explicit");
var selection = zonalData.GetProperty("configurationEvidence").GetProperty("selection");
Check(zonalData.GetProperty("configurationEvidence").GetProperty("source").GetString() == "scaleway-network-fixed-read" && selection.GetProperty("zonalProductsRequested").GetBoolean() && selection.GetProperty("zone").GetString() == "fr-par-1", "Mixed evidence declares its fixed network source and explicit zonal selection");
Check(zonalData.GetProperty("scope").GetProperty("zone").GetString() == "fr-par-1" && zonalData.GetProperty("coverage").GetProperty("completedScopes").GetInt32() == 1, "A compatible zone is retained in the declared scope and all selected products can complete it");
Check(zonalData.GetProperty("configurationEvidence").GetProperty("checks").EnumerateArray().Select(check => check.GetProperty("check").GetString()).SequenceEqual(new[] { "vpcs", "private-networks", "gateways", "load-balancers" }), "Each selected product has its own observation check");
var gatewayProperties = zonalResources[2].GetProperty("properties");
var lbProperties = zonalResources[3].GetProperty("properties");
Check(gatewayProperties.GetProperty("state").GetString() == "running" && !gatewayProperties.GetProperty("bastionEnabled").GetBoolean() && gatewayProperties.GetProperty("smtpEnabled").GetBoolean() && !gatewayProperties.GetProperty("isLegacy").GetBoolean(), "Gateway lifecycle and explicit false/true flags survive without becoming a health verdict");
Check(lbProperties.GetProperty("state").GetString() == "ready" && lbProperties.GetProperty("frontendCount").GetInt32() == 0 && lbProperties.GetProperty("backendCount").GetInt32() == 2 && lbProperties.GetProperty("privateNetworkCount").GetInt32() == 0 && lbProperties.GetProperty("routeCount").GetInt32() == 0, "Load-balancer metadata preserves genuine zero counts independently of availability");
Check(zonalResources[2].GetProperty("id").GetString() == $"vpc-gw/zones/fr-par-1/gateways/{Id(3)}" && zonalResources[3].GetProperty("id").GetString() == $"lb/zones/fr-par-1/lbs/{Id(4)}" && zonalResources.Skip(2).All(resource => resource.GetProperty("region").GetString() == "fr-par" && resource.GetProperty("properties").GetProperty("zone").GetString() == "fr-par-1"), "Zonal resource identities include the exact selected zone while their region remains explicit");
var zonalRaw = JsonSerializer.Serialize(zonal.Report, ReportSecurity.JsonOptions);
Check(new[] { Secret, "PRIVATE-GATEWAY-NAME", "PRIVATE-GATEWAY-TAG", "PRIVATE-LOAD-BALANCER-NAME", "PRIVATE-LOAD-BALANCER-TAG", "PRIVATE-GATEWAY-SOFTWARE", "192.0.2.", "private-subscriber", Id(900), Id(901) }.All(value => !zonalRaw.Contains(value, StringComparison.Ordinal)) && !zonalData.GetRawText().Contains("\"certificates\":", StringComparison.Ordinal) && !zonalData.GetRawText().Contains("\"gateway_networks\":", StringComparison.Ordinal), "Zonal reads discard names, tags, software strings, addresses, subscribers, certificates, nested networks and underlying instance identities before reports");
var zonalRedacted = ReportSecurity.Serialize(zonal.Report);
using var zonalRedactedDocument = JsonDocument.Parse(zonalRedacted);
var redactedLoadBalancer = zonalRedactedDocument.RootElement.GetProperty("data").GetProperty("resources").EnumerateArray()
    .Single(resource => resource.GetProperty("type").GetString() == "network.load-balancer");
Check(new[] { Project, Id(1), Id(2), Id(3), Id(4) }.All(value => !zonalRedacted.Contains(value, StringComparison.Ordinal)) &&
    redactedLoadBalancer.GetProperty("properties").GetProperty("frontendCount").GetInt32() == 0,
    "Exports redact every zonal identity while preserving numeric evidence");
Check(!zonal.Report.Findings.Any() && zonal.Report.Warnings!.Any(warning => warning.Contains("do not establish", StringComparison.Ordinal)), "Gateway and load-balancer configuration do not manufacture an isolation, reachability or health assessment");

foreach (var zone in new[] { "fr-par-1", "fr-par-2", "nl-ams-1", "nl-ams-2", "nl-ams-3", "pl-waw-1", "pl-waw-2", "pl-waw-3" })
{
    var selected = await Read(ZonalNormal, ZonalOptions(zone));
    Check(selected.Report.OperationSucceeded && selected.Handler.Requests.Count == 4 && selected.Handler.Requests.Skip(2).All(request => request.Path.Contains($"/zones/{zone}/", StringComparison.Ordinal)), "Every explicitly supported zone retains its own gateway and load-balancer routes");
}
foreach (var zone in new[] { "fr-par-3", "fr-par", "fr-par-0", "fr-par-10", "FR-PAR-1", "fr-par-1\n", "fr-par-\n1", "fr-par-1,fr-par-2", "../zone", "https://untrusted.invalid" })
{
    var options = Options(); options["zone"] = zone;
    var rejected = await Read(ZonalNormal, options);
    Check(State(rejected.Report) == "not_configured" && rejected.Handler.Requests.Count == 0, "Unapproved, malformed and ambiguous zones cannot initiate any network read");
}

var zonalEmpty = await Read((request, _) => JsonResponse(CollectionName(request), [], 0), ZonalOptions());
Check(zonalEmpty.Report.OperationSucceeded && Data(zonalEmpty.Report).GetProperty("resources").GetArrayLength() == 0 && Data(zonalEmpty.Report).GetProperty("configurationEvidence").GetProperty("checks").EnumerateArray().All(check => check.GetProperty("observations").GetProperty("observedResources").GetInt32() == 0), "Only completed explicit empty envelopes establish zero observations for all four selected products");

foreach (var kind in new[] { "gateways", "lbs" })
{
    foreach (var mutation in new Action<JsonObject>[]
    {
        row => row["id"] = "invalid", row => row.Remove("id"), row => row["project_id"] = OtherProject, row => row.Remove("project_id"),
        row => row["zone"] = "fr-par-2", row => row["zone"] = "nl-ams-1", row => row.Remove("zone"), row => row["zone"] = "fr-par-1\n"
    })
    {
        var mismatch = await Read((request, number) =>
        {
            if (CollectionName(request) != kind) return ZonalNormal(request, number);
            var row = kind == "gateways" ? Gateway() : LoadBalancer(); mutation(row);
            return JsonResponse(kind, [row], 1);
        }, ZonalOptions());
        Check(State(mismatch.Report) == "partial" && Data(mismatch.Report).GetProperty("resources").GetArrayLength() == 3 && ProductCheck(mismatch.Report, kind == "gateways" ? "gateways" : "load-balancers").GetProperty("state").GetString() != "complete", "A foreign or missing zonal identity is omitted without discarding independent valid products");
    }
}
var foreignLbRegion = await Read((request, number) =>
{
    if (CollectionName(request) != "lbs") return ZonalNormal(request, number);
    var row = LoadBalancer(); row["region"] = "nl-ams"; return JsonResponse("lbs", [row], 1);
}, ZonalOptions());
Check(State(foreignLbRegion.Report) == "partial" && Data(foreignLbRegion.Report).GetProperty("resources").GetArrayLength() == 3, "A supplied load-balancer region must agree with the configured region and its selected zone");
var omittedLbRegion = await Read((request, number) =>
{
    if (CollectionName(request) != "lbs") return ZonalNormal(request, number);
    var row = LoadBalancer(); row.Remove("region"); return JsonResponse("lbs", [row], 1);
}, ZonalOptions());
Check(omittedLbRegion.Report.OperationSucceeded && Data(omittedLbRegion.Report).GetProperty("resources").GetArrayLength() == 4, "The deprecated optional load-balancer region is not required when exact zone identity is verified");

var optionalUnknown = await Read((request, number) =>
{
    var kind = CollectionName(request);
    if (kind is not ("gateways" or "lbs")) return ZonalNormal(request, number);
    JsonObject row = new() { ["id"] = Id(kind == "gateways" ? 3 : 4), ["project_id"] = Project, ["zone"] = "fr-par-1" };
    return JsonResponse(kind, [row], 1);
}, ZonalOptions());
var optionalResources = Data(optionalUnknown.Report).GetProperty("resources").EnumerateArray().Skip(2).Select(resource => resource.GetProperty("properties")).ToArray();
Check(optionalUnknown.Report.OperationSucceeded && optionalResources.All(properties => !properties.TryGetProperty("state", out _)), "Absent optional lifecycle metadata remains unknown without fabricating a failed read");
Check(!optionalResources[0].TryGetProperty("bastionEnabled", out _) && !optionalResources[1].TryGetProperty("frontendCount", out _), "Absent flags and counts are not converted to false or zero");
var explicitNulls = await Read((request, number) =>
{
    var kind = CollectionName(request);
    if (kind is not ("gateways" or "lbs")) return ZonalNormal(request, number);
    var row = kind == "gateways" ? Gateway() : LoadBalancer();
    foreach (var field in kind == "gateways" ? new[] { "status", "bastion_enabled", "smtp_enabled", "is_legacy" } : new[] { "status", "frontend_count", "backend_count", "private_network_count", "route_count" }) row[field] = null;
    return JsonResponse(kind, [row], 1);
}, ZonalOptions());
Check(explicitNulls.Report.OperationSucceeded && Data(explicitNulls.Report).GetProperty("resources").EnumerateArray().Skip(2).All(resource => resource.GetProperty("properties").EnumerateObject().Select(property => property.Name).SequenceEqual(new[] { "zone" })), "Explicit null optional values remain unknown without synthetic lifecycle, booleans or counts");
var legacyGateway = await Read((request, number) =>
{
    if (CollectionName(request) != "gateways") return ZonalNormal(request, number);
    var row = Gateway(); row["is_legacy"] = true; row["status"] = "unknown_status"; return JsonResponse("gateways", [row], 1);
}, ZonalOptions());
var legacyProperties = Data(legacyGateway.Report).GetProperty("resources")[2].GetProperty("properties");
Check(legacyGateway.Report.OperationSucceeded && legacyProperties.GetProperty("isLegacy").GetBoolean() && legacyProperties.GetProperty("state").GetString() == "unknown_status", "Explicit legacy inclusion retains a legacy gateway and its documented unknown lifecycle state without a health conclusion");

foreach (var (kind, field, value) in new (string Kind, string Field, JsonNode? Value)[]
{
    ("gateways", "status", JsonValue.Create("PRIVATE-STATE")), ("gateways", "bastion_enabled", JsonValue.Create("false")),
    ("gateways", "smtp_enabled", JsonValue.Create(0)), ("gateways", "is_legacy", new JsonObject()),
    ("lbs", "status", JsonValue.Create("PRIVATE-STATE")), ("lbs", "frontend_count", JsonValue.Create(-1)),
    ("lbs", "backend_count", JsonValue.Create("0")), ("lbs", "private_network_count", JsonValue.Create(1.5)),
    ("lbs", "route_count", JsonValue.Create((long)int.MaxValue + 1))
})
{
    var malformed = await Read((request, number) =>
    {
        if (CollectionName(request) != kind) return ZonalNormal(request, number);
        var row = kind == "gateways" ? Gateway() : LoadBalancer(); row[field] = value?.DeepClone(); return JsonResponse(kind, [row], 1);
    }, ZonalOptions());
    var check = ProductCheck(malformed.Report, kind == "gateways" ? "gateways" : "load-balancers");
    Check(State(malformed.Report) == "partial" && Data(malformed.Report).GetProperty("resources").GetArrayLength() == 4 && check.GetProperty("state").GetString() == "partial" && !JsonSerializer.Serialize(malformed.Report).Contains("PRIVATE-STATE", StringComparison.Ordinal), "Malformed optional zonal values remain unknown and make only their selected source incomplete");
}

foreach (var kind in new[] { "gateways", "lbs" })
{
    var checkName = kind == "gateways" ? "gateways" : "load-balancers";
    var deniedProduct = await Read((request, number) => CollectionName(request) == kind ? new(HttpStatusCode.Forbidden) { Content = new StringContent(Secret) } : ZonalNormal(request, number), ZonalOptions());
    Check(State(deniedProduct.Report) == "partial" && Data(deniedProduct.Report).GetProperty("resources").GetArrayLength() == 3 && ProductCheck(deniedProduct.Report, checkName).GetProperty("state").GetString() == "permission_denied" && !ProductCheck(deniedProduct.Report, checkName).TryGetProperty("observations", out _), "Independent denied zonal products do not erase regional observations or invent zero counts");
}
foreach (var interrupted in new[] { "quota", "timeout", "bytes" })
{
    var stopped = await Read((request, number) =>
    {
        if (CollectionName(request) == "lbs") throw new InvalidOperationException("An interrupted gateway read cannot request load balancers");
        if (CollectionName(request) != "gateways") return ZonalNormal(request, number);
        return interrupted switch
        {
            "quota" => new(HttpStatusCode.TooManyRequests),
            "timeout" => throw new OperationCanceledException(),
            _ => Response(new string('x', 4 * 1024 * 1024 + 1))
        };
    }, ZonalOptions());
    Check(State(stopped.Report) == "partial" && stopped.Handler.Requests.Count == 3 && Data(stopped.Report).GetProperty("resources").GetArrayLength() == 2, "Quota, deadline and response-byte failures stop later zonal reads while retaining completed regional evidence");
    Check(ProductCheck(stopped.Report, "load-balancers").GetProperty("state").GetString() != "complete" && !ProductCheck(stopped.Report, "load-balancers").TryGetProperty("observations", out _), "An unrequested load-balancer collection remains unknown after a safety stop");
}
foreach (var status in new[] { HttpStatusCode.Created, HttpStatusCode.NoContent, HttpStatusCode.PartialContent })
{
    var unusualSuccess = await Read((request, number) =>
    {
        var response = ZonalNormal(request, number); response.StatusCode = status; return response;
    }, ZonalOptions());
    Check(!unusualSuccess.Report.OperationSucceeded && Data(unusualSuccess.Report).GetProperty("resources").GetArrayLength() == 0, "Only HTTP200 list responses can establish complete observations");
}

foreach (var body in new[]
{
    "{\"gateways\":[],\"total_count\":0,\"gateways\":[{}]}",
    "{\"gateways\":[{\"id\":\"" + Id(3) + "\",\"id\":\"" + Id(4) + "\",\"project_id\":\"" + Project + "\",\"zone\":\"fr-par-1\"}],\"total_count\":1}"
})
{
    var ambiguous = await Read((request, number) => CollectionName(request) == "gateways" ? Response(body) : ZonalNormal(request, number), ZonalOptions());
    Check(State(ambiguous.Report) == "partial" && Data(ambiguous.Report).GetProperty("resources").GetArrayLength() == 3 && ProductCheck(ambiguous.Report, "gateways").GetProperty("state").GetString() != "complete", "Duplicate zonal collection or identity keys cannot establish an accepted observation");
}
var gatewayPaged = await Read((request, number) =>
{
    if (CollectionName(request) != "gateways") return ZonalNormal(request, number);
    return request.RequestUri!.Query.Contains("page=1&", StringComparison.Ordinal)
        ? JsonResponse("gateways", Enumerable.Range(10, 100).Select(id => Gateway(id)), 101)
        : JsonResponse("gateways", [Gateway(110)], 101);
}, ZonalOptions());
Check(gatewayPaged.Report.OperationSucceeded && Data(gatewayPaged.Report).GetProperty("resources").GetArrayLength() == 104 && gatewayPaged.Handler.Requests.Count == 5 && gatewayPaged.Handler.Requests[3].Path == "/vpc-gw/v2/zones/fr-par-1/gateways" && gatewayPaged.Handler.Requests[3].Query.Contains("page=2&", StringComparison.Ordinal), "Gateway pagination advances only the approved path and zone before continuing to load balancers");
var zonalDuplicate = await Read((request, number) => CollectionName(request) == "lbs" ? JsonResponse("lbs", [LoadBalancer(), LoadBalancer()], 2) : ZonalNormal(request, number), ZonalOptions());
Check(State(zonalDuplicate.Report) == "partial" && Data(zonalDuplicate.Report).GetProperty("resources").GetArrayLength() == 4 && ProductCheck(zonalDuplicate.Report, "load-balancers").GetProperty("observations").GetProperty("observedResources").GetInt32() == 1, "Duplicate zonal resource identities are not counted twice");

var rejectedRowsBudget = await Read((request, _) =>
{
    if (CollectionName(request) != "vpcs") throw new InvalidOperationException("Rejected source rows must still exhaust the global source budget");
    return JsonResponse("vpcs", Enumerable.Range(1, 100).Select(_ => (JsonNode?)new JsonObject { ["id"] = "bad" }), 1001);
}, ZonalOptions());
Check(State(rejectedRowsBudget.Report) == "partial" && rejectedRowsBudget.Handler.Requests.Count == 10 && Data(rejectedRowsBudget.Report).GetProperty("resources").GetArrayLength() == 0, "Invalid source rows count toward the shared1000-row budget instead of enabling unlimited reads");
Check(Data(rejectedRowsBudget.Report).GetProperty("configurationEvidence").GetProperty("checks").EnumerateArray().Skip(1).All(check => check.GetProperty("state").GetString() != "complete" && !check.TryGetProperty("observations", out _)), "Products skipped after rejected-row exhaustion do not manufacture successful empty reads");

Console.WriteLine($"PASS: {assertions} Scaleway regional and zonal network checks.");

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
