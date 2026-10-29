using System.Text.Json;
using System.Text.Json.Nodes;
using Opscope;
using Opscope.Cloud;

const string Project = "example-project";
const string ClusterName = "private-cluster";
const string PoolName = "private-pool";
const string Location = "europe-west1-b";
const string Secret = "RAW-PRIVATE-SECRET";
var assertions = 0;
void Check(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); assertions++; }
Dictionary<string, string> Options() => new(StringComparer.Ordinal) { ["project"] = Project, ["gcp-services"] = "gke" };
JsonElement Data(AnalysisReport report) => JsonSerializer.SerializeToElement(report.Data, ReportSecurity.JsonOptions);
JsonElement Clusters(AnalysisReport report) => Data(report).GetProperty("resources");
JsonElement Pools(AnalysisReport report, int cluster = 0) => Clusters(report)[cluster].GetProperty("properties").GetProperty("nodePools");
string Coverage(AnalysisReport report) => Data(report).GetProperty("coverage").GetProperty("state").GetString()!.ToLowerInvariant();
JsonObject Pool(string name = PoolName) => new()
{
    ["name"] = name, ["status"] = "RUNNING", ["version"] = "1.33.1-gke.1234000", ["initialNodeCount"] = 2,
    ["autoscaling"] = new JsonObject { ["enabled"] = true, ["minNodeCount"] = 0, ["maxNodeCount"] = 5, ["totalMinNodeCount"] = 0, ["totalMaxNodeCount"] = 15, ["locationPolicy"] = "BALANCED" },
    ["management"] = new JsonObject { ["autoRepair"] = true, ["autoUpgrade"] = false },
    ["config"] = new JsonObject { ["serviceAccount"] = "private@example.invalid", ["metadata"] = new JsonObject { ["startup-script"] = Secret }, ["labels"] = new JsonObject { ["private"] = Secret } },
    ["instanceGroupUrls"] = new JsonArray("https://private.invalid/"), ["podIpv4CidrSize"] = 24, ["statusMessage"] = Secret, ["unexpected"] = Secret
};
JsonObject Cluster(JsonArray? pools = null, string name = ClusterName, string project = Project, string location = Location) => new()
{
    ["name"] = name, ["location"] = location,
    ["selfLink"] = $"https://container.googleapis.com/v1/projects/{project}/locations/{location}/clusters/{name}",
    ["status"] = "RUNNING", ["currentMasterVersion"] = "1.33.1-gke.1234000", ["currentNodeVersion"] = "1.33.1-gke.1234000", ["currentNodeCount"] = 2,
    ["nodePools"] = pools ?? new JsonArray(Pool()), ["masterAuth"] = new JsonObject { ["clientCertificate"] = Secret }, ["endpoint"] = "private.invalid"
};
async Task<(AnalysisReport Report, FixtureRunner Runner)> Read(JsonElement? rows = null, IReadOnlyDictionary<string, string>? options = null)
{
    var runner = new FixtureRunner((_, _) => rows ?? JsonSerializer.SerializeToElement(new JsonArray(Cluster())));
    return (await new GcpProvider(runner).CollectAsync("services", options ?? Options()), runner);
}
Task<(AnalysisReport Report, FixtureRunner Runner)> ReadNode(JsonNode rows, IReadOnlyDictionary<string, string>? options = null) => Read(JsonSerializer.SerializeToElement(rows), options);

var valid = await Read();
var evidence = Pools(valid.Report);
var child = evidence.GetProperty("pools")[0];
var parentId = $"//container.googleapis.com/projects/{Project}/locations/{Location}/clusters/{ClusterName}";
Check(valid.Report.OperationSucceeded && Coverage(valid.Report) == "complete" && Clusters(valid.Report).GetArrayLength() == 1, "Observed node-pool metadata completes the explicitly selected GKE source");
Check(evidence.GetProperty("state").GetString() == "complete" && evidence.GetProperty("observedCount").GetInt32() == 1 && evidence.GetProperty("returnedCount").GetInt32() == 1, "Per-cluster source evidence preserves observed and returned node-pool counts");
Check(child.GetProperty("resourceId").GetString() == parentId + "/nodePools/" + PoolName && child.GetProperty("state").GetString() == "RUNNING" && child.GetProperty("version").GetString() == "1.33.1-gke.1234000", "Every pool has a derived canonical identity under its verified parent and selected status/version metadata");
Check(child.GetProperty("initialNodeCount").GetInt32() == 2 && child.GetProperty("autoscaling").GetProperty("minNodeCount").GetInt32() == 0 && !child.GetProperty("management").GetProperty("autoUpgrade").GetBoolean(), "Configured counts and explicit zero/false observations remain distinct from unknown values");
Check(valid.Runner.Calls.Count == 2 && valid.Runner.Calls.All(call => call.Tool == "gcloud") && valid.Runner.Calls[1].Arguments.Take(3).SequenceEqual(new[] { "container", "clusters", "list" }), "Node pools reuse the existing verified-project and cluster-list reads without additional calls");
const string Projection = "json(name,location,selfLink,status,currentMasterVersion,currentNodeVersion,currentNodeCount,nodePools.name,nodePools.status,nodePools.version,nodePools.initialNodeCount,nodePools.autoscaling.enabled,nodePools.autoscaling.minNodeCount,nodePools.autoscaling.maxNodeCount,nodePools.autoscaling.totalMinNodeCount,nodePools.autoscaling.totalMaxNodeCount,nodePools.autoscaling.locationPolicy,nodePools.management.autoRepair,nodePools.management.autoUpgrade)";
var clusterArguments = valid.Runner.Calls[1].Arguments;
Check(clusterArguments[clusterArguments.ToList().IndexOf("--format") + 1] == Projection, "The source projection contains exactly selected GKE fields and excludes configuration, credentials and URLs");
var raw = JsonSerializer.Serialize(valid.Report, ReportSecurity.JsonOptions);
Check(new[] { Secret, "private@example.invalid", "private.invalid", "masterAuth", "instanceGroupUrls", "podIpv4CidrSize", "startup-script" }.All(value => !raw.Contains(value, StringComparison.Ordinal)), "Even an untrusted runner returning extra configuration and secrets cannot place them in the normalized report");
var redacted = ReportSecurity.Serialize(valid.Report);
Check(new[] { Project, ClusterName, PoolName, parentId, Secret }.All(value => !redacted.Contains(value, StringComparison.Ordinal)), "Redacted exports omit project, parent and child identities and unselected provider text");
Check(!valid.Report.Findings.Any() && valid.Report.Warnings!.Any(warning => warning.Contains("do not prove", StringComparison.Ordinal)), "GKE control-plane metadata does not create an availability or security finding");

foreach (var field in new[] { "nodePools", "observedCount", "returnedCount", "pools", "initialNodeCount", "autoscaling", "enabled", "minNodeCount", "maxNodeCount", "totalMinNodeCount", "totalMaxNodeCount", "locationPolicy", "management", "autoRepair", "autoUpgrade" })
{
    var collision = await ReadNode(new JsonArray(Cluster(name: field.ToLowerInvariant())));
    using var exported = JsonDocument.Parse(ReportSecurity.Serialize(collision.Report));
    var projected = exported.RootElement.GetProperty("data").GetProperty("resources")[0].GetProperty("properties").GetProperty("nodePools");
    Check(projected.GetProperty("observedCount").GetInt32() == 1 && projected.GetProperty("pools")[0].GetProperty("management").TryGetProperty("autoUpgrade", out _), "A private cluster name matching a fixed schema key cannot rename or erase the node-pool schema");
}

var zero = await ReadNode(new JsonArray(Cluster(new JsonArray())));
var repeatedParent = await ReadNode(new JsonArray(Cluster(), Cluster()));
Check(Coverage(repeatedParent.Report) == "partial" && Clusters(repeatedParent.Report).GetArrayLength() == 1 && Pools(repeatedParent.Report).GetProperty("observedCount").GetInt32() == 1, "Repeated canonical parents cannot duplicate clusters or their pool observations");
Check(Data(repeatedParent.Report).GetProperty("coverage").GetProperty("completedScopes").GetInt32() == 0, "Duplicate service identity prevents claiming a fully completed project scope");
Check(zero.Report.OperationSucceeded && Pools(zero.Report).GetProperty("state").GetString() == "complete" && Pools(zero.Report).GetProperty("observedCount").GetInt32() == 0 && Pools(zero.Report).GetProperty("returnedCount").GetInt32() == 0, "Only an observed empty node-pool array establishes complete zero-pool evidence");
foreach (var source in new JsonNode?[] { null, JsonValue.Create("unavailable"), new JsonObject(), JsonValue.Create(0) })
{
    var cluster = Cluster(); cluster["nodePools"] = source;
    var unknown = await ReadNode(new JsonArray(cluster));
    Check(!unknown.Report.OperationSucceeded && Coverage(unknown.Report) == "partial" && Clusters(unknown.Report).GetArrayLength() == 1 && Pools(unknown.Report).GetProperty("state").GetString() == "partial", "A malformed or null node-pool source preserves useful cluster metadata with partial source coverage");
    Check(!Pools(unknown.Report).TryGetProperty("observedCount", out _) && !Pools(unknown.Report).TryGetProperty("returnedCount", out _) && Pools(unknown.Report).GetProperty("pools").GetArrayLength() == 0, "Unavailable node-pool evidence does not manufacture an empty observation or zero count");
    Check(Data(unknown.Report).GetProperty("coverage").GetProperty("completedScopes").GetInt32() == 0, "A project with an incomplete GKE child source cannot be counted as fully completed");
}
var absent = Cluster(); absent.Remove("nodePools");
var missing = await ReadNode(new JsonArray(absent));
Check(Coverage(missing.Report) == "partial" && !Pools(missing.Report).TryGetProperty("observedCount", out _), "An omitted node-pool array remains unknown rather than empty");
var minimal = await ReadNode(new JsonArray(Cluster(new JsonArray(new JsonObject { ["name"] = PoolName }))));
var unknownChild = Pools(minimal.Report).GetProperty("pools")[0];
Check(minimal.Report.OperationSucceeded && !unknownChild.TryGetProperty("state", out _) && !unknownChild.TryGetProperty("version", out _) && !unknownChild.TryGetProperty("initialNodeCount", out _) && !unknownChild.GetProperty("autoscaling").EnumerateObject().Any() && !unknownChild.GetProperty("management").EnumerateObject().Any(), "A verified pool identity can be observed while absent optional metadata remains unknown without invented values");

foreach (var mutation in new Action<JsonObject>[]
{
    pool => pool["name"] = "../other", pool => pool["name"] = "pool-", pool => pool["name"] = "private\npool", pool => pool.Remove("name"),
    pool => pool["name"] = new string('a', 64), pool => pool["name"] = 123
})
{
    var pool = Pool(); mutation(pool);
    var invalid = await ReadNode(new JsonArray(Cluster(new JsonArray(pool))));
    Check(Coverage(invalid.Report) == "partial" && Clusters(invalid.Report).GetArrayLength() == 1 && Pools(invalid.Report).GetProperty("pools").GetArrayLength() == 0 && !Pools(invalid.Report).TryGetProperty("observedCount", out _), "Malformed child identity is omitted and cannot establish a zero-pool result");
}
var malformedRows = await ReadNode(new JsonArray(Cluster(new JsonArray(null, JsonValue.Create("bad-row"), Pool()))));
Check(Coverage(malformedRows.Report) == "partial" && Pools(malformedRows.Report).GetProperty("observedCount").GetInt32() == 1 && Pools(malformedRows.Report).GetProperty("returnedCount").GetInt32() == 3, "Independent valid child observations survive malformed rows with explicit partial coverage");
var duplicate = await ReadNode(new JsonArray(Cluster(new JsonArray(Pool(), Pool()))));
Check(Coverage(duplicate.Report) == "partial" && Pools(duplicate.Report).GetProperty("pools").GetArrayLength() == 1 && Pools(duplicate.Report).GetProperty("returnedCount").GetInt32() == 2, "Repeated node-pool identities are deduplicated per parent and remain partial");

foreach (var mutation in new Action<JsonObject>[]
{
    pool => pool["status"] = Secret, pool => pool["version"] = Secret, pool => pool["version"] = "1.33.1\n-gke.1234", pool => pool["initialNodeCount"] = -1,
    pool => pool["initialNodeCount"] = "0", pool => pool["initialNodeCount"] = 1.5, pool => pool["autoscaling"]!["enabled"] = "false",
    pool => pool["autoscaling"]!["locationPolicy"] = Secret, pool => pool["management"]!["autoRepair"] = "true", pool => pool["management"] = Secret
})
{
    var pool = Pool(); mutation(pool);
    var invalid = await ReadNode(new JsonArray(Cluster(new JsonArray(pool))));
    Check(Coverage(invalid.Report) == "partial" && Pools(invalid.Report).GetProperty("pools").GetArrayLength() == 1 && !JsonSerializer.Serialize(invalid.Report, ReportSecurity.JsonOptions).Contains(Secret, StringComparison.Ordinal), "Invalid selected metadata becomes unknown while useful pool identity survives and arbitrary provider strings are not reflected");
}
foreach (var status in new[] { "STATUS_UNSPECIFIED", "PROVISIONING", "RUNNING", "RUNNING_WITH_ERROR", "RECONCILING", "STOPPING", "ERROR" })
{
    var pool = Pool(); pool["status"] = status;
    var supported = await ReadNode(new JsonArray(Cluster(new JsonArray(pool))));
    Check(supported.Report.OperationSucceeded && Pools(supported.Report).GetProperty("pools")[0].GetProperty("state").GetString() == status, "Known GKE node-pool status values remain observations without derived health");
}
foreach (var version in new[] { "1.6.13-gke.1", "1.33.1", "1.34.0-gke.1234567890" })
{
    var pool = Pool(); pool["version"] = version;
    var supported = await ReadNode(new JsonArray(Cluster(new JsonArray(pool))));
    Check(supported.Report.OperationSucceeded && Pools(supported.Report).GetProperty("pools")[0].GetProperty("version").GetString() == version, "Only bounded numeric GKE version syntax enters pool evidence");
}

foreach (var mutation in new Action<JsonObject>[]
{
    cluster => cluster["selfLink"] = $"https://container.googleapis.com/v1/projects/{Project}/locations/{Location}/clusters/other-cluster",
    cluster => cluster["selfLink"] = $"https://container.googleapis.com/v1/projects/{Project}/locations/us-central1-a/clusters/{ClusterName}",
    cluster => cluster["selfLink"] = $"https://container.googleapis.com/v1/projects/other-project/locations/{Location}/clusters/{ClusterName}",
    cluster => cluster["selfLink"] = $"https://container.googleapis.com/v1/projects/{Project}/locations/{Location}/clusters/{ClusterName}?alt=json",
    cluster => cluster["selfLink"] = $"https://container.googleapis.com/v1/projects/{Project}/locations/{Location}/clusters/{ClusterName}/nodePools/other",
    cluster => cluster["selfLink"] = $"https://container.googleapis.com/v1/projects/{Project}/locations/{Location}/clusters/%70rivate-cluster",
    cluster => cluster["selfLink"] = $"http://container.googleapis.com/v1/projects/{Project}/locations/{Location}/clusters/{ClusterName}",
    cluster => cluster["location"] = "europe-west1-b/other", cluster => cluster["name"] = "private\n-cluster"
})
{
    var cluster = Cluster(); mutation(cluster);
    var rejected = await ReadNode(new JsonArray(cluster));
    Check(Coverage(rejected.Report) == "partial" && Clusters(rejected.Report).GetArrayLength() == 0, "A canonical parent link must agree exactly with the selected project, location and cluster name before associating node pools");
}
foreach (var version in new[] { "v1", "v1beta1" })
{
    var cluster = Cluster(); cluster["selfLink"] = $"https://container.googleapis.com/{version}/projects/{Project}/zones/{Location}/clusters/{ClusterName}";
    var legacy = await ReadNode(new JsonArray(cluster));
    Check(legacy.Report.OperationSucceeded && Pools(legacy.Report).GetProperty("pools")[0].GetProperty("resourceId").GetString() == parentId + "/nodePools/" + PoolName, "Exact legacy zonal GKE links normalize to the same canonical parent-child identity");
}
var regional = Cluster(location: "europe-west1");
var regionalReport = await ReadNode(new JsonArray(regional));
Check(regionalReport.Report.OperationSucceeded, "Exact regional locations parent links remain supported");
regional["selfLink"] = $"https://container.googleapis.com/v1/projects/{Project}/zones/europe-west1/clusters/{ClusterName}";
var invalidRegional = await ReadNode(new JsonArray(regional.DeepClone()));
Check(Clusters(invalidRegional.Report).GetArrayLength() == 0, "A regional location cannot masquerade as a legacy zone");
var repeatedNames = await ReadNode(new JsonArray(Cluster(), Cluster(name: "another-cluster")));
Check(repeatedNames.Report.OperationSucceeded && Pools(repeatedNames.Report, 0).GetProperty("pools")[0].GetProperty("resourceId").GetString() != Pools(repeatedNames.Report, 1).GetProperty("pools")[0].GetProperty("resourceId").GetString(), "Identical pool names in different verified clusters retain distinct scoped identities");

foreach (var field in new[] { "status", "currentMasterVersion", "currentNodeVersion" })
{
    var cluster = Cluster(); cluster[field] = Secret;
    var sanitized = await ReadNode(new JsonArray(cluster));
    Check(Coverage(sanitized.Report) == "partial" && !JsonSerializer.Serialize(sanitized.Report, ReportSecurity.JsonOptions).Contains(Secret, StringComparison.Ordinal), "Parent GKE status and version fields use the same bounded safe metadata contract");
}
var duplicateArrayText = new JsonArray(Cluster()).ToJsonString().Replace("\"nodePools\":", "\"nodePools\":[],\"nodePools\":", StringComparison.Ordinal);
using (var document = JsonDocument.Parse(duplicateArrayText))
{
    var ambiguous = await Read(document.RootElement.Clone());
    Check(Coverage(ambiguous.Report) == "partial" && Pools(ambiguous.Report).GetProperty("pools").GetArrayLength() == 0 && !Pools(ambiguous.Report).TryGetProperty("returnedCount", out _), "Duplicate source-array keys cannot choose a convenient complete or empty interpretation");
}
var duplicateNameText = new JsonArray(Cluster()).ToJsonString().Replace($"\"name\":\"{PoolName}\"", $"\"name\":\"other-pool\",\"name\":\"{PoolName}\"", StringComparison.Ordinal);
using (var document = JsonDocument.Parse(duplicateNameText))
{
    var ambiguous = await Read(document.RootElement.Clone());
    Check(Coverage(ambiguous.Report) == "partial" && Pools(ambiguous.Report).GetProperty("pools").GetArrayLength() == 0, "Duplicate pool-name keys cannot establish child identity");
}

var excessive = await ReadNode(new JsonArray(Cluster(new JsonArray(Enumerable.Range(0, 101).Select(index => (JsonNode?)Pool("pool-" + index)).ToArray()))));
Check(Coverage(excessive.Report) == "partial" && Pools(excessive.Report).GetProperty("pools").GetArrayLength() == 100 && Pools(excessive.Report).GetProperty("observedCount").GetInt32() == 100 && Pools(excessive.Report).GetProperty("returnedCount").GetInt32() == 101, "A cluster retains at most 100 pool rows while exposing source truncation");
var manyClusters = await ReadNode(new JsonArray(Enumerable.Range(0, 12).Select(cluster => (JsonNode?)Cluster(new JsonArray(Enumerable.Range(0, 100).Select(pool => (JsonNode?)Pool("pool-" + pool)).ToArray()), "cluster-" + cluster)).ToArray()));
Check(Coverage(manyClusters.Report) == "partial" && Clusters(manyClusters.Report).GetArrayLength() == 12 && Clusters(manyClusters.Report).EnumerateArray().Sum(cluster => cluster.GetProperty("properties").GetProperty("nodePools").GetProperty("pools").GetArrayLength()) == 1000, "The aggregate 1,000-pool bound keeps every useful cluster while capping retained child evidence");
using (var exported = JsonDocument.Parse(ReportSecurity.Serialize(manyClusters.Report)))
{
    var output = exported.RootElement;
    Check(output.GetProperty("warnings").EnumerateArray().Any(warning => warning.GetString()!.Contains("Redaction context exceeded", StringComparison.Ordinal)), "Maximum topology can exhaust the separate bounded redaction context and must explicitly disclose text omission");
    Check(output.GetProperty("data").GetProperty("resources")[0].GetProperty("properties").GetProperty("nodePools").GetProperty("observedCount").GetInt32() == 100, "Context-limited redaction preserves fixed topology keys and observed numeric evidence");
    Check(output.GetProperty("kind").GetString() == "[redacted-context-limit]", "Incomplete redaction context fails closed instead of exporting incompletely protected text");
}
Check(Pools(manyClusters.Report, 10).GetProperty("state").GetString() == "partial" && !Pools(manyClusters.Report, 10).TryGetProperty("observedCount", out _), "A later cluster omitted by the aggregate bound remains unknown rather than showing zero pools");
var multiOptions = Options(); multiOptions.Remove("project"); multiOptions["projects"] = "first-project,second-project,third-project";
var multiRunner = new FixtureRunner((project, _) => JsonSerializer.SerializeToElement(new JsonArray(Enumerable.Range(0, 4).Select(cluster => (JsonNode?)Cluster(new JsonArray(Enumerable.Range(0, 100).Select(pool => (JsonNode?)Pool("pool-" + pool)).ToArray()), "cluster-" + cluster, project)).ToArray())));
var multi = await new GcpProvider(multiRunner).CollectAsync("services", multiOptions);
Check(Coverage(multi) == "partial" && Clusters(multi).EnumerateArray().Sum(cluster => cluster.GetProperty("properties").GetProperty("nodePools").GetProperty("pools").GetArrayLength()) == 1000 && multiRunner.Calls.Count == 6, "The child bound spans all explicitly configured projects without extra API calls or per-project resets");
var invalidBudget = new JsonArray(Enumerable.Range(0, 10).Select(index => (JsonNode?)Cluster(new JsonArray(Enumerable.Range(0, 100).Select(_ => (JsonNode?)new JsonObject()).ToArray()), "invalid-cluster-" + index)).Append(Cluster()).ToArray());
var consumed = await ReadNode(invalidBudget);
Check(Pools(consumed.Report, 10).GetProperty("pools").GetArrayLength() == 0 && !Pools(consumed.Report, 10).TryGetProperty("observedCount", out _), "Invalid source rows consume the aggregate processing bound and cannot force unbounded inspection");
using (var cancelled = new CancellationTokenSource())
{
    cancelled.Cancel(); var runner = new FixtureRunner((_, _) => throw new InvalidOperationException("No cancelled read may run"));
    try { await new GcpProvider(runner).CollectAsync("services", Options(), cancelled.Token); throw new InvalidOperationException("Cancellation swallowed"); }
    catch (OperationCanceledException) { Check(runner.Calls.Count == 0, "Caller cancellation is preserved before project and service queries"); }
}
Console.WriteLine($"PASS: {assertions} GKE parent identity, node-pool metadata, limits, unknown-value and privacy assertions.");

sealed class FixtureRunner(Func<string, IReadOnlyList<string>, JsonElement> clusterRows) : ICloudCommandRunner
{
    public List<(string Tool, IReadOnlyList<string> Arguments)> Calls { get; } = [];
    public Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); Calls.Add((tool, arguments.ToArray()));
        if (arguments.Take(2).SequenceEqual(new[] { "projects", "describe" }))
            return Task.FromResult(JsonSerializer.SerializeToElement(new { projectId = arguments[2], projectNumber = "123456789012" }));
        if (!arguments.Take(3).SequenceEqual(new[] { "container", "clusters", "list" })) throw new InvalidOperationException("Unexpected service query");
        var index = arguments.ToList().IndexOf("--project");
        return Task.FromResult(clusterRows(arguments[index + 1], arguments));
    }
}
