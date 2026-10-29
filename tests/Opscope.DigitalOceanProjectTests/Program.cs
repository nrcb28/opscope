using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Opscope;
using Opscope.Cloud;

const string Project = "11111111-1111-1111-1111-111111111111";
const string OtherProject = "22222222-2222-2222-2222-222222222222";
const string VolumeId = "33333333-3333-3333-3333-333333333333";
const string LoadBalancerId = "44444444-4444-4444-4444-444444444444";
const string VpcId = "55555555-5555-5555-5555-555555555555";
const string DirectFirewallId = "66666666-6666-6666-6666-666666666666";
const string TagFirewallId = "77777777-7777-7777-7777-777777777777";
const string Secret = "PRIVATE-DIGITALOCEAN-ACCESS-TOKEN";
const string Region = "nyc1";
const string DropletId = "101";
var assertions = 0;
void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); assertions++; }
Dictionary<string, string> Options() => new(StringComparer.Ordinal) { ["project"] = Project };
JsonElement Data(AnalysisReport report) => JsonSerializer.SerializeToElement(report.Data, ReportSecurity.JsonOptions);
JsonElement Resources(AnalysisReport report) => Data(report).GetProperty("resources");
JsonElement Checks(AnalysisReport report) => Data(report).GetProperty("configurationEvidence").GetProperty("checks");
JsonElement CheckData(AnalysisReport report, string name) => Checks(report).EnumerateArray().Single(check => check.GetProperty("check").GetString() == name);
string State(AnalysisReport report) => Data(report).GetProperty("coverage").GetProperty("state").GetString()!;
JsonElement Resource(AnalysisReport report, string type) => Resources(report).EnumerateArray().Single(resource => resource.GetProperty("type").GetString() == type);
JsonElement Properties(AnalysisReport report, string type) => Resource(report, type).GetProperty("properties");
bool Unknown(JsonElement parent, string key) => !parent.TryGetProperty(key, out var value) || value.ValueKind == JsonValueKind.Null;
JsonObject ProjectBody(string id = Project) => new() { ["project"] = new JsonObject { ["id"] = id, ["name"] = "PRIVATE-PROJECT-NAME", ["owner_uuid"] = "PRIVATE-OWNER", ["description"] = Secret } };
string ResourcePath(string urn) => urn.Split(':')[1] switch
{
    "droplet" => "/v2/droplets/" + urn.Split(':')[2],
    "volume" => "/v2/volumes/" + urn.Split(':')[2],
    "loadbalancer" => "/v2/load_balancers/" + urn.Split(':')[2],
    "vpc" => "/v2/vpcs/" + urn.Split(':')[2],
    _ => "/v2/domains/unused.example"
};
JsonObject Membership(string urn, string status = "ok") => new()
{
    ["urn"] = urn, ["status"] = status, ["assigned_at"] = "2026-10-29T10:00:00Z",
    ["links"] = new JsonObject { ["self"] = "https://api.digitalocean.com" + ResourcePath(urn) },
    ["unselected_metadata"] = Secret
};
JsonObject[] Members() => [Membership("do:droplet:" + DropletId), Membership("do:volume:" + VolumeId), Membership("do:loadbalancer:" + LoadBalancerId)];
HttpResponseMessage Page(string key, IEnumerable<JsonNode?> rows, int total, string? next = null, int padding = 0)
{
    var root = new JsonObject { [key] = new JsonArray(rows.ToArray()), ["meta"] = new JsonObject { ["total"] = total } };
    if (next is not null) root["links"] = new JsonObject { ["pages"] = new JsonObject { ["next"] = next } };
    if (padding > 0) root["unselected_metadata"] = new string('x', padding);
    return Response(root.ToJsonString());
}
JsonObject Droplet(long id = 101) => new()
{
    ["id"] = id, ["name"] = "PRIVATE-DROPLET-NAME", ["status"] = "active",
    ["vcpus"] = 0, ["memory"] = 0, ["disk"] = 0, ["region"] = new JsonObject { ["slug"] = Region },
    ["vpc_uuid"] = VpcId, ["tags"] = new JsonArray("PRIVATE-MEMBER-TAG"),
    ["networks"] = new JsonObject { ["v4"] = new JsonArray(new JsonObject { ["ip_address"] = "192.0.2.13", ["netmask"] = "255.255.255.0", ["gateway"] = "192.0.2.1" }) },
    ["user_data"] = Secret, ["image"] = new JsonObject { ["name"] = "PRIVATE-IMAGE" }
};
JsonObject Volume() => new()
{
    ["id"] = VolumeId, ["name"] = "PRIVATE-VOLUME-NAME", ["size_gigabytes"] = 0,
    ["region"] = new JsonObject { ["slug"] = Region }, ["filesystem_label"] = "PRIVATE-FILESYSTEM",
    ["tags"] = new JsonArray("PRIVATE-VOLUME-TAG"), ["description"] = Secret
};
JsonObject LoadBalancer() => new()
{
    ["id"] = LoadBalancerId, ["project_id"] = Project, ["name"] = "PRIVATE-LB-NAME",
    ["status"] = "active", ["type"] = "REGIONAL", ["network"] = "EXTERNAL", ["size_unit"] = 1,
    ["redirect_http_to_https"] = false, ["enable_proxy_protocol"] = false,
    ["region"] = new JsonObject { ["slug"] = Region }, ["vpc_uuid"] = VpcId,
    ["ip"] = "192.0.2.14", ["ipv6"] = "2001:db8::14", ["domains"] = new JsonArray(new JsonObject { ["name"] = "PRIVATE-DOMAIN.example" }),
    ["forwarding_rules"] = new JsonArray(new JsonObject { ["certificate_id"] = "PRIVATE-CERTIFICATE", ["entry_port"] = 443 }),
    ["health_check"] = new JsonObject { ["path"] = "/PRIVATE-HEALTH-PATH" }, ["description"] = Secret
};
JsonObject Vpc() => new()
{
    ["id"] = VpcId, ["urn"] = "do:vpc:" + VpcId, ["name"] = "PRIVATE-VPC-NAME",
    ["region"] = Region, ["default"] = false, ["ip_range"] = "10.0.0.0/20", ["description"] = Secret
};
JsonObject Ingress(string address = "0.0.0.0/0", string? action = null)
{
    var rule = new JsonObject { ["protocol"] = "tcp", ["ports"] = "22", ["sources"] = new JsonObject { ["addresses"] = new JsonArray(address) } };
    if (action is not null) rule["action"] = action;
    return rule;
}
JsonObject Firewall(bool tag = false) => new()
{
    ["id"] = tag ? TagFirewallId : DirectFirewallId, ["name"] = "PRIVATE-FIREWALL-NAME", ["status"] = "succeeded",
    ["droplet_ids"] = tag ? new JsonArray() : new JsonArray(101),
    ["tags"] = tag ? new JsonArray("PRIVATE-MEMBER-TAG") : new JsonArray(),
    ["inbound_rules"] = new JsonArray(Ingress()), ["outbound_rules"] = new JsonArray(),
    ["pending_changes"] = new JsonArray(new JsonObject { ["droplet_id"] = 999, ["status"] = "waiting" }), ["description"] = Secret
};
HttpResponseMessage Normal(HttpRequestMessage request, int number) => request.RequestUri!.AbsolutePath switch
{
    "/v2/projects/" + Project => Response(ProjectBody().ToJsonString()),
    "/v2/projects/" + Project + "/resources" => Page("resources", Members(), 3),
    "/v2/droplets/" + DropletId => Wrapped("droplet", Droplet()),
    "/v2/volumes/" + VolumeId => Wrapped("volume", Volume()),
    "/v2/load_balancers/" + LoadBalancerId => Wrapped("load_balancer", LoadBalancer()),
    "/v2/vpcs/" + VpcId => Wrapped("vpc", Vpc()),
    "/v2/firewalls" => Page("firewalls", [Firewall(), Firewall(true)], 2),
    _ => throw new InvalidOperationException("Unexpected provider request path: " + request.RequestUri.AbsolutePath + " (" + number + ")")
};
async Task<(AnalysisReport Report, FixtureHandler Handler)> Read(Func<HttpRequestMessage, int, HttpResponseMessage>? response = null,
    IReadOnlyDictionary<string, string>? options = null, string? credential = Secret, string operation = "inventory")
{
    var handler = new FixtureHandler(response ?? Normal);
    using var client = new HttpClient(handler);
    var provider = new DigitalOceanProjectProvider(client, name => name == "DIGITALOCEAN_ACCESS_TOKEN" ? credential : null);
    return (await provider.CollectAsync(operation, options ?? Options()), handler);
}
string Next(string path = "/v2/projects/" + Project + "/resources", int page = 2) => $"https://api.digitalocean.com{path}?per_page=100&page={page}";

var inventory = await Read();
Check(inventory.Report.OperationSucceeded && State(inventory.Report) == "complete", "Project inventory completes its selected visible resource reads");
Check(Resources(inventory.Report).GetArrayLength() == 4 && Resources(inventory.Report).EnumerateArray().Select(resource => resource.GetProperty("type").GetString()).ToHashSet().SetEquals(["compute.vm", "storage.volume", "network.load-balancer", "network.vpc"]), "Inventory retains project droplets, volumes, load balancers and their referenced VPCs");
Check(inventory.Handler.Requests.Count == 6 && inventory.Handler.Requests[0].Path == "/v2/projects/" + Project && inventory.Handler.Requests[1].Path == "/v2/projects/" + Project + "/resources", "The exact project ID is verified before listing membership and following selected resource IDs");
Check(inventory.Handler.Requests.All(request => request.Method == "GET" && request.Scheme == "https" && request.Host == "api.digitalocean.com" && request.AuthorizationScheme == "Bearer" && request.Token == Secret), "Only authenticated GET reads to the fixed DigitalOcean HTTPS host are sent");
Check(inventory.Handler.Requests.Where(request => request.Path.EndsWith("/resources", StringComparison.Ordinal)).All(request => Query(request.Query).Count == 2 && Query(request.Query)["per_page"] == "100" && Query(request.Query)["page"] == "1"), "Membership pagination uses a bounded page size and explicit first page");
Check(Properties(inventory.Report, "compute.vm").GetProperty("vcpus").GetInt32() == 0 && Properties(inventory.Report, "compute.vm").GetProperty("memoryMb").GetInt32() == 0 && Properties(inventory.Report, "compute.vm").GetProperty("diskGb").GetInt32() == 0 && Properties(inventory.Report, "storage.volume").GetProperty("sizeGigabytes").GetInt32() == 0, "Explicit numeric zeros remain observations");
Check(Properties(inventory.Report, "network.load-balancer").GetProperty("redirectHttpToHttps").ValueKind == JsonValueKind.False && Properties(inventory.Report, "network.load-balancer").GetProperty("proxyProtocol").ValueKind == JsonValueKind.False && Properties(inventory.Report, "network.vpc").GetProperty("defaultNetwork").ValueKind == JsonValueKind.False, "Explicit false configuration remains an observation");
Check(Properties(inventory.Report, "network.vpc").GetProperty("relation").GetString() == "referenced-by-project-resource" && Properties(inventory.Report, "network.vpc").GetProperty("referringResourceCount").GetInt32() == 2, "A deduplicated VPC observation states its resource-reference relationship rather than project ownership");
Check(Data(inventory.Report).GetProperty("configurationEvidence").GetProperty("source").GetString() == "digitalocean-project-fixed-read" && Data(inventory.Report).GetProperty("configurationEvidence").GetProperty("scopeVerification").GetProperty("source").GetString() == "digitalocean-project-v2" && Data(inventory.Report).GetProperty("configurationEvidence").GetProperty("scopeVerification").GetProperty("state").GetString() == "verified", "Configuration evidence names the fixed reader and authoritative project-ID verification");
Check(Checks(inventory.Report).EnumerateArray().Select(check => check.GetProperty("check").GetString()).ToHashSet().SetEquals(["project-resources", "droplets", "volumes", "load-balancers", "vpcs"]) && Checks(inventory.Report).EnumerateArray().All(check => check.GetProperty("state").GetString() == "complete"), "Inventory preserves separate membership and product-source coverage");
var raw = JsonSerializer.Serialize(inventory.Report, ReportSecurity.JsonOptions);
Check(new[] { Secret, "PRIVATE-", "192.0.2.", "2001:db8:", "10.0.0.0", "certificate_id", "forwarding_rules", "user_data", "filesystem_label", "owner_uuid" }.All(value => !raw.Contains(value, StringComparison.Ordinal)), "Names, tags, addresses, CIDRs, raw rules, certificate metadata and provider secrets never enter inventory evidence");
var redacted = ReportSecurity.Serialize(inventory.Report);
Check(new[] { Project, VolumeId, LoadBalancerId, VpcId, "do:droplet:" + DropletId }.All(value => !redacted.Contains(value, StringComparison.Ordinal)), "Shared export redaction removes project and resource identities");
Check(!inventory.Report.Findings.Any(), "Lifecycle and network metadata do not imply application health or effective reachability");

var posture = await Read(operation: "posture");
Check(posture.Report.OperationSucceeded && State(posture.Report) == "complete" && Resources(posture.Report).EnumerateArray().Count(resource => resource.GetProperty("type").GetString() == "network.firewall") == 2, "Posture includes firewalls associated directly and by exact selected-droplet tags");
Check(posture.Handler.Requests.All(request => !request.Path.StartsWith("/v2/volumes/", StringComparison.Ordinal) && !request.Path.StartsWith("/v2/load_balancers/", StringComparison.Ordinal) && !request.Path.StartsWith("/v2/vpcs/", StringComparison.Ordinal)), "Posture does not query unrelated inventory products");
var firewallProperties = Resources(posture.Report).EnumerateArray().Where(resource => resource.GetProperty("type").GetString() == "network.firewall").Select(resource => resource.GetProperty("properties")).ToArray();
Check(firewallProperties.Any(properties => properties.GetProperty("directDropletCount").GetInt32() == 1 && properties.GetProperty("tagDropletCount").GetInt32() == 0) && firewallProperties.Any(properties => properties.GetProperty("directDropletCount").GetInt32() == 0 && properties.GetProperty("tagDropletCount").GetInt32() == 1), "Direct and tag membership counts remain distinct without retaining tag text");
Check(firewallProperties.All(properties => properties.GetProperty("observedDropletCount").GetInt32() == 1 && properties.GetProperty("inboundRuleCount").GetInt32() == 1 && properties.GetProperty("observedGlobalIngressRuleCount").GetInt32() == 1), "Firewall properties retain bounded membership and global-ingress observations");
Check(posture.Report.Findings.Any(finding => finding.Code == "DIGITALOCEAN_WORLD_INGRESS"), "A validated allowed global ingress rule produces the existing configuration finding");
Check(!JsonSerializer.Serialize(posture.Report, ReportSecurity.JsonOptions).Contains("PRIVATE-", StringComparison.Ordinal) && !JsonSerializer.Serialize(posture.Report, ReportSecurity.JsonOptions).Contains("0.0.0.0/0", StringComparison.Ordinal), "Tag matching and rule interpretation never export raw tag, address or rule contents");
Check(Checks(posture.Report).EnumerateArray().Select(check => check.GetProperty("check").GetString()).ToHashSet().SetEquals(["project-resources", "droplets", "firewalls"]), "Posture coverage names only its required sources");

foreach (var mutate in new Action<Dictionary<string, string>>[]
{
    options => options.Remove("project"), options => options["project"] = "not-a-project", options => options["project"] = Project + "," + OtherProject,
    options => options["project"] = "../" + Project, options => options["project"] = "https://127.0.0.1", options => options["endpoint"] = "https://untrusted.invalid",
    options => options["api-url"] = "https://untrusted.invalid", options => options["projects"] = Project + "," + OtherProject
})
{
    var options = Options(); mutate(options); var invalid = await Read(options: options);
    Check(!invalid.Report.OperationSucceeded && State(invalid.Report) == "not_configured" && invalid.Handler.Requests.Count == 0, "Invalid or ambiguous project and endpoint overrides fail before network access");
}
foreach (var token in new[] { "", "private\r\nheader", "private with space", "private-é", new string('x', 16385) })
{
    var invalid = await Read(credential: token);
    Check(!invalid.Report.OperationSucceeded && State(invalid.Report) == "not_configured" && invalid.Handler.Requests.Count == 0, "Missing or malformed bearer credentials remain offline");
}
foreach (var operation in new[] { "delete", "metrics", "health", "networks" })
{
    var invalid = await Read(operation: operation);
    Check(State(invalid.Report) == "unsupported" && invalid.Handler.Requests.Count == 0, "The project reader cannot run unsupported operations");
}
foreach (var body in new[] { ProjectBody(OtherProject).ToJsonString(), "{}", "null", "[]", "{\"project\":{\"id\":\"" + Project + "\",\"id\":\"" + OtherProject + "\"}}" })
{
    var invalid = await Read((_, _) => Response(body));
    Check(!invalid.Report.OperationSucceeded && invalid.Handler.Requests.Count == 1 && Resources(invalid.Report).GetArrayLength() == 0 && Data(invalid.Report).GetProperty("configurationEvidence").GetProperty("scopeVerification").GetProperty("state").GetString() != "verified", "Missing, contradictory or mismatched project identity prevents product reads");
}
foreach (var (status, expected) in new[] { (HttpStatusCode.Unauthorized, "permission_denied"), (HttpStatusCode.Forbidden, "permission_denied"), (HttpStatusCode.TooManyRequests, "rate_limited"), (HttpStatusCode.BadGateway, "failed") })
{
    var failed = await Read((_, _) => new(status) { Content = new StringContent("PRIVATE-PROVIDER-BODY " + Secret) });
    Check(State(failed.Report) == expected && !failed.Report.OperationSucceeded && failed.Handler.Requests.Count == 1 && !JsonSerializer.Serialize(failed.Report).Contains("PRIVATE-PROVIDER-BODY", StringComparison.Ordinal), "Scope-preflight failures preserve their classification without exposing bodies");
}
var empty = await Read((request, number) => request.RequestUri!.AbsolutePath.EndsWith("/resources", StringComparison.Ordinal) ? Page("resources", [], 0) : Normal(request, number));
Check(empty.Report.OperationSucceeded && Resources(empty.Report).GetArrayLength() == 0 && empty.Handler.Requests.Count == 2, "A verified project and explicit completed zero membership total establish only an empty visible supported inventory");
foreach (var body in new[] { "{}", "[]", "null", "{\"resources\":[]}", "{\"resources\":[],\"meta\":{\"total\":\"0\"}}", "{\"resources\":[],\"meta\":{\"total\":-1}}", "{\"resources\":[],\"meta\":{\"total\":0,\"total\":1}}", "{\"resources\":{},\"meta\":{\"total\":0}}", "PRIVATE-PROVIDER-BODY" })
{
    var invalid = await Read((request, number) => request.RequestUri!.AbsolutePath.EndsWith("/resources", StringComparison.Ordinal) ? Response(body) : Normal(request, number));
    Check(!invalid.Report.OperationSucceeded && Resources(invalid.Report).GetArrayLength() == 0 && !JsonSerializer.Serialize(invalid.Report).Contains("PRIVATE-PROVIDER-BODY", StringComparison.Ordinal), "Invalid membership envelopes cannot certify an empty inventory or leak provider text");
}
foreach (var mutate in new Action<JsonObject>[]
{
    row => row["urn"] = "do:droplet:../101", row => row["urn"] = "do:droplet:0", row => row["urn"] = "do:droplet:101?x=private",
    row => row["urn"] = "do:droplet:101:extra", row => row["status"] = "not_found", row => row["status"] = "service_down",
    row => row["links"]!["self"] = "https://untrusted.invalid/v2/droplets/101",
    row => row["links"]!["self"] = "https://api.digitalocean.com/v2/droplets/102",
    row => row["links"]!["self"] = "https://api.digitalocean.com/v2/droplets/101?endpoint=private"
})
{
    var invalid = await Read((request, number) =>
    {
        if (!request.RequestUri!.AbsolutePath.EndsWith("/resources", StringComparison.Ordinal)) return Normal(request, number);
        var row = Membership("do:droplet:" + DropletId); mutate(row); return Page("resources", [row], 1);
    });
    Check(!invalid.Report.OperationSucceeded && Resources(invalid.Report).GetArrayLength() == 0 && invalid.Handler.Requests.Count == 2, "Malformed or unconfirmed membership and foreign self links cannot select a provider detail request");
}
var duplicate = await Read((request, number) => request.RequestUri!.AbsolutePath.EndsWith("/resources", StringComparison.Ordinal) ? Page("resources", [Membership("do:droplet:" + DropletId), Membership("do:droplet:" + DropletId)], 2) : Normal(request, number));
Check(!duplicate.Report.OperationSucceeded && Resources(duplicate.Report).EnumerateArray().Count(resource => resource.GetProperty("type").GetString() == "compute.vm") == 1 && duplicate.Handler.Requests.Count(request => request.Path == "/v2/droplets/" + DropletId) == 1, "Repeated membership IDs are read once and retain incomplete source coverage");
var hidden = await Read((request, number) => request.RequestUri!.AbsolutePath.EndsWith("/resources", StringComparison.Ordinal) ? Page("resources", [Membership("do:domain:unused.example")], 1) : Normal(request, number));
Check(Resources(hidden.Report).GetArrayLength() == 0 && hidden.Handler.Requests.Count == 2, "Unsupported project-resource types never become arbitrary service paths");
foreach (var (path, key, makeRow, mutate) in new (string, string, Func<JsonObject>, Action<JsonObject>)[]
{
    ("/v2/droplets/" + DropletId, "droplet", () => Droplet(), row => row["id"] = 102),
    ("/v2/volumes/" + VolumeId, "volume", Volume, row => row["id"] = OtherProject),
    ("/v2/load_balancers/" + LoadBalancerId, "load_balancer", LoadBalancer, row => row["id"] = OtherProject),
    ("/v2/load_balancers/" + LoadBalancerId, "load_balancer", LoadBalancer, row => row["project_id"] = OtherProject),
    ("/v2/vpcs/" + VpcId, "vpc", Vpc, row => row["id"] = OtherProject),
    ("/v2/vpcs/" + VpcId, "vpc", Vpc, row => row["region"] = "sfo3"),
    ("/v2/vpcs/" + VpcId, "vpc", Vpc, row => row["urn"] = "do:vpc:" + OtherProject)
})
{
    var invalid = await Read((request, number) =>
    {
        if (request.RequestUri!.AbsolutePath != path) return Normal(request, number);
        var row = makeRow(); mutate(row); return Wrapped(key, row);
    });
    Check(!invalid.Report.OperationSucceeded && State(invalid.Report) == "partial" && Resources(invalid.Report).GetArrayLength() < 4, "Detail identities, project references and VPC locations must agree with their selected relationship");
}
var optional = await Read((request, number) =>
{
    if (request.RequestUri!.AbsolutePath != "/v2/load_balancers/" + LoadBalancerId) return Normal(request, number);
    var row = LoadBalancer(); row.Remove("redirect_http_to_https"); row.Remove("enable_proxy_protocol"); return Wrapped("load_balancer", row);
});
Check(optional.Report.OperationSucceeded && Unknown(Properties(optional.Report, "network.load-balancer"), "redirectHttpToHttps") && Unknown(Properties(optional.Report, "network.load-balancer"), "proxyProtocol"), "Missing optional booleans remain unknown without invalidating identity enumeration");
var invalidOptional = await Read((request, number) =>
{
    if (request.RequestUri!.AbsolutePath != "/v2/load_balancers/" + LoadBalancerId) return Normal(request, number);
    var row = LoadBalancer(); row["redirect_http_to_https"] = "false"; row["status"] = "PRIVATE-UNKNOWN-STATE"; return Wrapped("load_balancer", row);
});
Check(!invalidOptional.Report.OperationSucceeded && Unknown(Properties(invalidOptional.Report, "network.load-balancer"), "redirectHttpToHttps") && !JsonSerializer.Serialize(invalidOptional.Report).Contains("PRIVATE-UNKNOWN-STATE", StringComparison.Ordinal), "Supplied invalid metadata stays unknown and cannot support complete coverage");
var globalBalancer = await Read((request, number) =>
{
    if (request.RequestUri!.AbsolutePath != "/v2/load_balancers/" + LoadBalancerId) return Normal(request, number);
    var row = LoadBalancer(); row["type"] = "GLOBAL"; row.Remove("region"); row.Remove("vpc_uuid"); return Wrapped("load_balancer", row);
});
Check(globalBalancer.Report.OperationSucceeded && Resource(globalBalancer.Report, "network.load-balancer").GetProperty("region").GetString() == "global" && Properties(globalBalancer.Report, "network.load-balancer").GetProperty("type").GetString() == "GLOBAL" && Properties(globalBalancer.Report, "network.vpc").GetProperty("referringResourceCount").GetInt32() == 1, "A global load balancer does not invent a regional VPC or region reference");
var missingVpc = await Read((request, number) =>
{
    if (request.RequestUri!.AbsolutePath != "/v2/droplets/" + DropletId) return Normal(request, number);
    var row = Droplet(); row.Remove("vpc_uuid"); return Wrapped("droplet", row);
});
Check(!missingVpc.Report.OperationSucceeded && Resources(missingVpc.Report).EnumerateArray().Any(resource => resource.GetProperty("type").GetString() == "compute.vm"), "An omitted permission-dependent VPC reference does not erase the useful droplet or prove no VPC association");

foreach (var next in new[]
{
    Next().Replace("https:", "http:", StringComparison.Ordinal), Next().Replace("api.digitalocean.com", "untrusted.invalid", StringComparison.Ordinal),
    Next("/v2/projects/" + OtherProject + "/resources"), Next("/v2/firewalls"), Next(page: 1), Next(page: 3),
    Next() + "&page=2", Next() + "&endpoint=https://untrusted.invalid", Next() + "#fragment",
    Next().Replace("per_page=100", "per_page=200", StringComparison.Ordinal), Next().Replace("page=2", "page=02", StringComparison.Ordinal),
    Next().Replace("https://", "https://private-user@", StringComparison.Ordinal), Next() + "&%70age=2"
})
{
    var invalid = await Read((request, number) => request.RequestUri!.AbsolutePath.EndsWith("/resources", StringComparison.Ordinal) ? Page("resources", [Membership("do:droplet:" + DropletId)], 2, next) : Normal(request, number));
    Check(!invalid.Report.OperationSucceeded && invalid.Handler.Requests.Count(request => request.Path.EndsWith("/resources", StringComparison.Ordinal)) == 1 && invalid.Handler.Requests.All(request => request.Host == "api.digitalocean.com"), "Foreign, repeated, ambiguous and noncanonical pagination cannot supply a follow-up request");
}
var paged = await Read((request, number) =>
{
    if (!request.RequestUri!.AbsolutePath.EndsWith("/resources", StringComparison.Ordinal)) return Normal(request, number);
    return Query(request.RequestUri.Query)["page"] == "1" ? Page("resources", [Membership("do:droplet:" + DropletId)], 3, Next()) : Page("resources", [Membership("do:volume:" + VolumeId), Membership("do:loadbalancer:" + LoadBalancerId)], 3);
});
Check(paged.Report.OperationSucceeded && Resources(paged.Report).GetArrayLength() == 4 && paged.Handler.Requests.Count(request => request.Path.EndsWith("/resources", StringComparison.Ordinal)) == 2, "Validated next-page metadata is reconstructed using the same fixed membership route");
var changingTotal = await Read((request, number) =>
{
    if (!request.RequestUri!.AbsolutePath.EndsWith("/resources", StringComparison.Ordinal)) return Normal(request, number);
    return Query(request.RequestUri.Query)["page"] == "1" ? Page("resources", [Membership("do:droplet:" + DropletId)], 3, Next()) : Page("resources", [Membership("do:volume:" + VolumeId)], 2);
});
Check(!changingTotal.Report.OperationSucceeded && CheckData(changingTotal.Report, "project-resources").GetProperty("state").GetString() != "complete", "Changing membership totals cannot support complete coverage");
var shortCollection = await Read((request, number) => request.RequestUri!.AbsolutePath.EndsWith("/resources", StringComparison.Ordinal) ? Page("resources", [Membership("do:droplet:" + DropletId)], 2) : Normal(request, number));
Check(!shortCollection.Report.OperationSucceeded, "A missing next page when the returned count is below the declared total stays incomplete");
var tooManyRows = await Read((request, number) => request.RequestUri!.AbsolutePath.EndsWith("/resources", StringComparison.Ordinal) ? Page("resources", Enumerable.Range(1, 101).Select(value => Membership("do:droplet:" + value)), 101) : Normal(request, number));
Check(!tooManyRows.Report.OperationSucceeded && tooManyRows.Handler.Requests.Count == 2, "Oversized collection pages are rejected before selecting detail resources");

var partlyDenied = await Read((request, number) => request.RequestUri!.AbsolutePath == "/v2/volumes/" + VolumeId ? new(HttpStatusCode.Forbidden) : Normal(request, number));
Check(!partlyDenied.Report.OperationSucceeded && State(partlyDenied.Report) == "partial" && Resources(partlyDenied.Report).GetArrayLength() == 3 && CheckData(partlyDenied.Report, "volumes").GetProperty("state").GetString() == "permission_denied", "A denied independent product retains other verified resources and its own unavailable state");
var quota = await Read((request, number) => number == 3 ? new(HttpStatusCode.TooManyRequests) : Normal(request, number));
Check(!quota.Report.OperationSucceeded && quota.Handler.Requests.Count == 3 && Checks(quota.Report).EnumerateArray().Any(check => check.GetProperty("state").GetString() == "not_requested"), "Quota rejection stops without retrying or querying remaining sources");
var timeout = await Read((request, number) => number == 3 ? throw new OperationCanceledException() : Normal(request, number));
Check(!timeout.Report.OperationSucceeded && timeout.Handler.Requests.Count == 3 && Checks(timeout.Report).EnumerateArray().Any(check => check.GetProperty("state").GetString() == "not_requested"), "Deadline failure stops later source reads without losing the verified project state");
var redirect = await Read((_, _) => new(HttpStatusCode.Redirect) { Headers = { Location = new Uri("https://untrusted.invalid/credential-sink") } });
Check(!redirect.Report.OperationSucceeded && redirect.Handler.Requests.Count == 1 && redirect.Handler.Requests.All(request => request.Host == "api.digitalocean.com"), "Redirect targets cannot receive credentials or become follow-up destinations");

foreach (var mutate in new Action<JsonObject>[]
{
    row => row.Remove("tags"), row => row["tags"] = null, row => row["tags"] = "PRIVATE-MEMBER-TAG",
    row => row["tags"] = new JsonArray(new JsonObject { ["private"] = Secret }), row => row.Remove("droplet_ids"),
    row => row["droplet_ids"] = null, row => row["droplet_ids"] = new JsonArray("101")
})
{
    var missingMembership = await Read((request, number) =>
    {
        if (request.RequestUri!.AbsolutePath != "/v2/firewalls") return Normal(request, number);
        var row = Firewall(); mutate(row); return Page("firewalls", [row], 1);
    }, operation: "posture");
    Check(!missingMembership.Report.OperationSucceeded && CheckData(missingMembership.Report, "firewalls").GetProperty("state").GetString() != "complete", "Missing or invalid permission-dependent firewall membership cannot establish a complete no-match result");
}
var noDropletTags = await Read((request, number) =>
{
    if (request.RequestUri!.AbsolutePath != "/v2/droplets/" + DropletId) return Normal(request, number);
    var row = Droplet(); row.Remove("tags"); return Wrapped("droplet", row);
}, operation: "posture");
Check(!noDropletTags.Report.OperationSucceeded && Resources(noDropletTags.Report).EnumerateArray().Any(resource => resource.GetProperty("type").GetString() == "network.firewall"), "Unavailable droplet tags leave tag membership unknown while direct membership remains useful");
var unrelated = await Read((request, number) =>
{
    if (request.RequestUri!.AbsolutePath != "/v2/firewalls") return Normal(request, number);
    var row = Firewall(true); row["tags"] = new JsonArray("PRIVATE-NONMATCHING-TAG"); return Page("firewalls", [row], 1);
}, operation: "posture");
Check(unrelated.Report.OperationSucceeded && Resources(unrelated.Report).EnumerateArray().All(resource => resource.GetProperty("type").GetString() != "network.firewall") && !unrelated.Report.Findings.Any(), "Explicit nonmatching IDs and tags do not associate an unrelated firewall with the project");
var overlap = await Read((request, number) =>
{
    if (request.RequestUri!.AbsolutePath != "/v2/firewalls") return Normal(request, number);
    var row = Firewall(); row["tags"] = new JsonArray("PRIVATE-MEMBER-TAG"); return Page("firewalls", [row], 1);
}, operation: "posture");
Check(Properties(overlap.Report, "network.firewall").GetProperty("directDropletCount").GetInt32() == 1 && Properties(overlap.Report, "network.firewall").GetProperty("tagDropletCount").GetInt32() == 1 && Properties(overlap.Report, "network.firewall").GetProperty("observedDropletCount").GetInt32() == 1, "The union of direct and tag membership does not double-count the same droplet");
foreach (var action in new[] { "deny", "PRIVATE-UNKNOWN-ACTION" })
{
    var notAllowed = await Read((request, number) =>
    {
        if (request.RequestUri!.AbsolutePath != "/v2/firewalls") return Normal(request, number);
        var row = Firewall(); row["inbound_rules"] = new JsonArray(Ingress(action: action)); return Page("firewalls", [row], 1);
    }, operation: "posture");
    Check(!notAllowed.Report.Findings.Any(finding => finding.Code == "DIGITALOCEAN_WORLD_INGRESS") && !JsonSerializer.Serialize(notAllowed.Report).Contains("PRIVATE-UNKNOWN-ACTION", StringComparison.Ordinal), "Denied or invalid rule actions cannot become an allowed global-ingress finding");
}
var ipv6 = await Read((request, number) =>
{
    if (request.RequestUri!.AbsolutePath != "/v2/firewalls") return Normal(request, number);
    var row = Firewall(); row["inbound_rules"] = new JsonArray(Ingress("::/0")); return Page("firewalls", [row], 1);
}, operation: "posture");
Check(ipv6.Report.Findings.Any(finding => finding.Code == "DIGITALOCEAN_WORLD_INGRESS"), "A validated IPv6 default route is interpreted without exporting the address");
var noRules = await Read((request, number) =>
{
    if (request.RequestUri!.AbsolutePath != "/v2/firewalls") return Normal(request, number);
    var row = Firewall(); row["inbound_rules"] = new JsonArray(); return Page("firewalls", [row], 1);
}, operation: "posture");
Check(Properties(noRules.Report, "network.firewall").GetProperty("inboundRuleCount").GetInt32() == 0 && Properties(noRules.Report, "network.firewall").GetProperty("observedGlobalIngressRuleCount").GetInt32() == 0 && !noRules.Report.Findings.Any(), "Explicit empty inbound rules preserve a genuine zero without certifying effective protection");
var missingRules = await Read((request, number) =>
{
    if (request.RequestUri!.AbsolutePath != "/v2/firewalls") return Normal(request, number);
    var row = Firewall(); row.Remove("inbound_rules"); return Page("firewalls", [row], 1);
}, operation: "posture");
Check(Unknown(Properties(missingRules.Report, "network.firewall"), "inboundRuleCount") && Unknown(Properties(missingRules.Report, "network.firewall"), "observedGlobalIngressRuleCount"), "Missing optional rule arrays remain unknown instead of observed zero");

using (var cancellation = new CancellationTokenSource())
{
    cancellation.Cancel(); var handler = new FixtureHandler(Normal); using var client = new HttpClient(handler);
    try { await new DigitalOceanProjectProvider(client, _ => Secret).CollectAsync("inventory", Options(), cancellation.Token); throw new InvalidOperationException("Caller cancellation was ignored"); }
    catch (OperationCanceledException) { Check(handler.Requests.Count == 0, "Caller cancellation propagates before any HTTP request"); }
}
using (var cancellation = new CancellationTokenSource())
{
    var handler = new FixtureHandler((request, number) =>
    {
        if (number == 3) { cancellation.Cancel(); cancellation.Token.ThrowIfCancellationRequested(); }
        return Normal(request, number);
    });
    using var client = new HttpClient(handler);
    try { await new DigitalOceanProjectProvider(client, _ => Secret).CollectAsync("inventory", Options(), cancellation.Token); throw new InvalidOperationException("Caller cancellation was ignored"); }
    catch (OperationCanceledException) { Check(handler.Requests.Count == 3, "Caller cancellation during a provider read propagates and stops remaining requests"); }
}
var oversized = await Read((request, number) => number == 3 ? Response(new string('x', 4 * 1024 * 1024 + 1)) : Normal(request, number));
Check(!oversized.Report.OperationSucceeded && oversized.Handler.Requests.Count == 3, "A declared response over four MiB stops further source reads");
var streamed = await Read((request, number) => number == 3 ? new(HttpStatusCode.OK) { Content = new StreamContent(new NonSeekableStream(new byte[4 * 1024 * 1024 + 1])) } : Normal(request, number));
Check(!streamed.Report.OperationSucceeded && streamed.Handler.Requests.Count == 3, "Unknown-length streams are bounded while reading and cannot trigger later requests");
var aggregated = await Read((request, number) =>
{
    var response = Normal(request, number);
    if (number is not (3 or 4 or 5)) return response;
    var root = JsonNode.Parse(response.Content.ReadAsStringAsync().GetAwaiter().GetResult())!;
    response.Dispose(); root["unselected_metadata"] = new string('x', 3 * 1024 * 1024); return Response(root.ToJsonString());
});
Check(!aggregated.Report.OperationSucceeded && aggregated.Handler.Requests.Count <= 5 && Resources(aggregated.Report).GetArrayLength() >= 1, "The eight-MiB aggregate budget spans membership and independent product responses while retaining earlier evidence");
var callBudget = await Read((request, number) =>
{
    var path = request.RequestUri!.AbsolutePath;
    if (path == "/v2/projects/" + Project + "/resources") return Page("resources", Enumerable.Range(1, 100).Select(value => Membership("do:droplet:" + value)), 100);
    if (path.StartsWith("/v2/droplets/", StringComparison.Ordinal)) { var row = Droplet(long.Parse(path.Split('/')[^1], CultureInfo.InvariantCulture)); row.Remove("vpc_uuid"); return Wrapped("droplet", row); }
    return Normal(request, number);
});
Check(!callBudget.Report.OperationSucceeded && callBudget.Handler.Requests.Count <= 60 && Resources(callBudget.Report).GetArrayLength() > 0 && Resources(callBudget.Report).GetArrayLength() <= 58, "The whole-collection sixty-request budget bounds individually selected detail reads");
var pageBudget = await Read((request, number) =>
{
    if (!request.RequestUri!.AbsolutePath.EndsWith("/resources", StringComparison.Ordinal)) return Normal(request, number);
    var page = int.Parse(Query(request.RequestUri.Query)["page"], CultureInfo.InvariantCulture);
    return Page("resources", Enumerable.Range((page - 1) * 100 + 1, 100).Select(value => Membership("do:droplet:" + value)), 1001, Next(page: page + 1));
});
Check(!pageBudget.Report.OperationSucceeded && pageBudget.Handler.Requests.Count(request => request.Path.EndsWith("/resources", StringComparison.Ordinal)) <= 10 && pageBudget.Handler.Requests.Count <= 60, "Membership page and global source-row limits prevent unbounded enumeration");

var exhaustedAfterMembership = await Read((request, number) =>
{
    var response = Normal(request, number);
    if (request.RequestUri!.AbsolutePath.EndsWith("/resources", StringComparison.Ordinal)) response.Headers.Add("ratelimit-remaining", "0");
    return response;
});
Check(!exhaustedAfterMembership.Report.OperationSucceeded && exhaustedAfterMembership.Handler.Requests.Count == 2 && Resources(exhaustedAfterMembership.Report).GetArrayLength() == 0 && CheckData(exhaustedAfterMembership.Report, "project-resources").GetProperty("state").GetString() == "complete", "A successful membership response with zero remaining quota is retained while product requests stop before network access");
Check(CheckData(exhaustedAfterMembership.Report, "project-resources").GetProperty("observations").GetProperty("observedResources").GetInt32() == 3 && Checks(exhaustedAfterMembership.Report).EnumerateArray().Where(check => check.GetProperty("check").GetString() != "project-resources").All(check => Unknown(check, "observations")), "A quota-exhausted membership read keeps its actual observations without inventing product zeros");
var exhaustedAfterFinalVpc = await Read((request, number) =>
{
    var response = Normal(request, number);
    if (request.RequestUri!.AbsolutePath == "/v2/vpcs/" + VpcId) response.Headers.Add("ratelimit-remaining", "0");
    return response;
});
Check(exhaustedAfterFinalVpc.Report.OperationSucceeded && exhaustedAfterFinalVpc.Handler.Requests.Count == 6 && Resources(exhaustedAfterFinalVpc.Report).GetArrayLength() == 4, "Zero quota remaining on the final successful VPC response does not invalidate already completed observations");
foreach (var address in new[] { "0:0:0:0:0:0:0:0/0", "203.0.113.42/0" })
{
    var globalPrefix = await Read((request, number) =>
    {
        if (request.RequestUri!.AbsolutePath != "/v2/firewalls") return Normal(request, number);
        var row = Firewall(); row["inbound_rules"] = new JsonArray(Ingress(address)); return Page("firewalls", [row], 1);
    }, operation: "posture");
    Check(globalPrefix.Report.Findings.Any(finding => finding.Code == "DIGITALOCEAN_WORLD_INGRESS") && Properties(globalPrefix.Report, "network.firewall").GetProperty("observedGlobalIngressRuleCount").GetInt32() == 1, "Parsed IPv4 and expanded IPv6 zero-length prefixes establish global ingress regardless of address spelling");
}
foreach (var mutate in new Action<JsonObject>[]
{
    rule => rule["protocol"] = "PRIVATE-UNKNOWN-PROTOCOL", rule => rule["ports"] = "PRIVATE-NONPORT",
    rule => rule["action"] = "PRIVATE-UNKNOWN-ACTION", rule => rule["sources"]!["addresses"] = new JsonArray("PRIVATE-NONADDRESS")
})
{
    var malformedRule = await Read((request, number) =>
    {
        if (request.RequestUri!.AbsolutePath != "/v2/firewalls") return Normal(request, number);
        var rule = Ingress(); mutate(rule); var row = Firewall(); row["inbound_rules"] = new JsonArray(rule); return Page("firewalls", [row], 1);
    }, operation: "posture");
    Check(!malformedRule.Report.OperationSucceeded && Unknown(Properties(malformedRule.Report, "network.firewall"), "observedGlobalIngressRuleCount") && !malformedRule.Report.Findings.Any(finding => finding.Code == "DIGITALOCEAN_WORLD_INGRESS"), "Malformed or unknown rule fields leave the global-ingress count unknown rather than zero");
}
foreach (var invalidUrn in new[] { false, true })
{
    var incompleteMembership = await Read((request, number) =>
    {
        if (!request.RequestUri!.AbsolutePath.EndsWith("/resources", StringComparison.Ordinal)) return Normal(request, number);
        return invalidUrn ? Page("resources", [Membership("do:droplet:../101")], 1)
            : Page("resources", [Membership("do:droplet:" + DropletId)], 2, "https://untrusted.invalid/v2/projects/" + Project + "/resources?per_page=100&page=2");
    });
    Check(!incompleteMembership.Report.OperationSucceeded && Data(incompleteMembership.Report).GetProperty("coverage").GetProperty("completedScopes").GetInt32() == 0 && new[] { "droplets", "volumes", "load-balancers", "vpcs" }.All(name => CheckData(incompleteMembership.Report, name).GetProperty("state").GetString() != "complete"), "Incomplete pagination or invalid membership prevents downstream product sources from claiming complete zero observations");
    Check(new[] { "volumes", "load-balancers" }.All(name => Unknown(CheckData(incompleteMembership.Report, name), "observations")), "Products absent from an incomplete membership read remain unavailable rather than observed empty");
}
var unverifiedVpcDependencies = await Read((request, number) =>
{
    if (request.RequestUri!.AbsolutePath == "/v2/droplets/" + DropletId) return new(HttpStatusCode.Forbidden);
    if (request.RequestUri.AbsolutePath != "/v2/load_balancers/" + LoadBalancerId) return Normal(request, number);
    var row = LoadBalancer(); row["type"] = "GLOBAL"; row.Remove("region"); row.Remove("vpc_uuid"); return Wrapped("load_balancer", row);
});
Check(!unverifiedVpcDependencies.Report.OperationSucceeded && CheckData(unverifiedVpcDependencies.Report, "vpcs").GetProperty("state").GetString() == "partial" && Unknown(CheckData(unverifiedVpcDependencies.Report, "vpcs"), "observations") && unverifiedVpcDependencies.Handler.Requests.All(request => !request.Path.StartsWith("/v2/vpcs/", StringComparison.Ordinal)), "A denied droplet read cannot establish empty VPC references even when a separate global load balancer has no regional VPC");
var unverifiedFirewallDependencies = await Read((request, number) => request.RequestUri!.AbsolutePath == "/v2/droplets/" + DropletId ? new(HttpStatusCode.Forbidden) : Normal(request, number), operation: "posture");
Check(!unverifiedFirewallDependencies.Report.OperationSucceeded && CheckData(unverifiedFirewallDependencies.Report, "firewalls").GetProperty("state").GetString() == "partial" && Unknown(CheckData(unverifiedFirewallDependencies.Report, "firewalls"), "observations") && Resources(unverifiedFirewallDependencies.Report).GetArrayLength() == 0, "A denied selected-droplet read leaves firewall association unknown instead of a complete empty project result");
foreach (var (path, key, makeRow) in new (string, string, Func<JsonObject>)[]
{
    ("/v2/droplets/" + DropletId, "droplet", () => Droplet()), ("/v2/volumes/" + VolumeId, "volume", Volume),
    ("/v2/load_balancers/" + LoadBalancerId, "load_balancer", LoadBalancer), ("/v2/vpcs/" + VpcId, "vpc", Vpc)
})
{
    var trailingNewline = await Read((request, number) =>
    {
        if (request.RequestUri!.AbsolutePath != path) return Normal(request, number);
        var row = makeRow(); if (key == "vpc") row["region"] = Region + "\n"; else row["region"]!["slug"] = Region + "\n";
        return Wrapped(key, row);
    });
    Check(!trailingNewline.Report.OperationSucceeded && Resources(trailingNewline.Report).GetArrayLength() < 4, "Source regions with a trailing newline cannot satisfy an exact region identity");
}

Console.WriteLine($"PASS: {assertions} DigitalOcean project identity, VPC references, load-balancer metadata, firewall membership, coverage and privacy checks.");

static HttpResponseMessage Response(string value) => new(HttpStatusCode.OK) { Content = new StringContent(value, Encoding.UTF8, "application/json") };
static HttpResponseMessage Wrapped(string key, JsonObject row) => Response(new JsonObject { [key] = row }.ToJsonString());
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
