using System.Globalization;
using System.Text.Json;
using Opscope;
using Opscope.Cloud;

var checks = 0;
void Check(bool condition, string message) { checks++; if (!condition) throw new InvalidOperationException(message); }
void Reject(Action action, string message) { try { action(); throw new InvalidOperationException(message); } catch (InvalidOperationException error) when (error.Message != message) { checks++; } }
JsonElement Data(AnalysisReport report) => JsonSerializer.SerializeToElement(report.Data, ReportSecurity.JsonOptions);
string State(AnalysisReport report) => Data(report).GetProperty("coverage").GetProperty("state").GetString()!;
var scope = new Dictionary<string, string> { ["context"] = "private-cluster-context", ["namespaces"] = "private-namespace" };
Check(KubernetesProvider.IsValidContext("reader") && !KubernetesProvider.IsValidContext("--server=untrusted"), "Startup context validation accepts literal context names only");
Check(KubernetesProvider.IsValidNamespaceAllowlist("one, two") && !KubernetesProvider.IsValidNamespaceAllowlist("one,one") && !KubernetesProvider.IsValidNamespaceAllowlist("one,,two") && !KubernetesProvider.IsValidNamespaceAllowlist(null), "Startup namespace validation accepts a bounded distinct allowlist");

foreach (var kind in KubernetesCommandRunner.Columns.Keys)
{
    var arguments = MetadataArguments(kind, "private-namespace");
    Check(KubernetesCommandRunner.Validate(arguments) == kind, "The exact metadata grammar must allow " + kind);
    Check(!arguments.Any(value => value.Contains(".env", StringComparison.Ordinal) || value.Contains(".command", StringComparison.Ordinal) || value.Contains(".note", StringComparison.Ordinal)), "Metadata projections must omit pod execution data and event messages");
}
var metricPath = "/apis/metrics.k8s.io/v1beta1/namespaces/private-namespace/pods?limit=100";
Check(KubernetesCommandRunner.Validate(["--context", "reader", "--request-timeout=10s", "get", "--raw", metricPath]) == "metrics", "Only the closed namespace metric path may use raw JSON");
Check(KubernetesCommandRunner.Validate(["--context", "reader", "--request-timeout=10s", "get", "--raw", metricPath + "&continue=a%2Fb"]) == "metrics", "An escaped opaque continuation remains within the fixed metric route");
foreach (var arguments in new IReadOnlyList<string>[]
{
    ["--context", "reader", "--request-timeout=10s", "delete", "pods", "--all"],
    ["--context", "reader", "--request-timeout=10s", "get", "secrets", "--all-namespaces"],
    ["--context", "reader", "--request-timeout=10s", "get", "pods", "--namespace", "private-namespace", "--chunk-size=100", "--no-headers", "--output=json"],
    ["--context", "reader", "--request-timeout=10s", "get", "pods", "--all-namespaces", "--chunk-size=100", "--no-headers", "--output=custom-columns=" + KubernetesCommandRunner.Columns["pods"]],
    ["--context", "reader", "--request-timeout=10s", "get", "--raw", "/api/v1/namespaces/private-namespace/secrets"],
    ["--context", "reader", "--request-timeout=10s", "get", "--raw", "/apis/metrics.k8s.io/v1beta1/namespaces/../pods?limit=100"],
    ["--context", "reader", "--request-timeout=10s", "get", "--raw", metricPath + "&watch=true"],
    ["--context", "reader", "--request-timeout=10s", "get", "--raw", metricPath + "&continue=a&token=secret"],
    ["--context", "reader", "--request-timeout=10s", "get", "nodes", "--chunk-size=100", "--no-headers", "--output=custom-columns=" + KubernetesCommandRunner.Columns["nodes"], "--kubeconfig", "untrusted.yml"]
}) Reject(() => KubernetesCommandRunner.Validate(arguments), "Unsafe kubectl grammar accepted");

var projection = KubernetesCommandRunner.ParseProjection("pods", "private-pod uid-private Running true,false 1,2\nmalformed\ninvalid/name uid Running true 0\n");
Check(projection.GetProperty("rows").GetArrayLength() == 1 && projection.GetProperty("malformedRows").GetInt32() == 2, "Projection parsing rejects malformed records and names");
var unknown = KubernetesCommandRunner.ParseProjection("deployments", "workload uid 3 <none> <unknown>\n");
Check(unknown.GetProperty("rows")[0].GetProperty("available").ValueKind == JsonValueKind.Null, "Unavailable replica fields are null, not zero");
var largeProjection = KubernetesCommandRunner.ParseProjection("namespaces", string.Concat(Enumerable.Range(0, 1001).Select(i => "ns-" + i + " uid Active\n")));
Check(largeProjection.GetProperty("rows").GetArrayLength() == 1000 && largeProjection.GetProperty("truncated").GetBoolean(), "Projected output has an exact 1000-row retention bound");

foreach (var (quantity, expected) in new[] { ("1", 1000d), ("100m", 100d), ("500u", .5d), ("250000000n", 250d), ("1.25", 1250d), ("1e-3", 1d), ("1k", 1000000d), ("0", 0d) })
    Check(KubernetesProvider.TryCpuMillicores(quantity, out var value) && Math.Abs(value - expected) < .000001, "CPU quantity conversion: " + quantity);
foreach (var quantity in new[] { "-1", "NaN", "2Gi", "1e100", "1000000001m", "https://invalid" })
    Check(!KubernetesProvider.TryCpuMillicores(quantity, out _), "Invalid/overflow CPU quantity must be unavailable: " + quantity);
foreach (var (quantity, expected) in new[] { ("1Ki", 1024L), ("1.5Mi", 1572864L), ("1.5", 2L), ("1m", 1L), ("1e3", 1000L), ("0", 0L) })
    Check(KubernetesProvider.TryMemoryBytes(quantity, out var value) && value == expected, "Memory quantity conversion: " + quantity);
foreach (var quantity in new[] { "-1Mi", "9Ei", "1e100", "1ki", "NaN" })
    Check(!KubernetesProvider.TryMemoryBytes(quantity, out _), "Invalid/overflow memory quantity must be unavailable: " + quantity);

var inventoryRunner = new FakeRunner((_, args, _) => Metadata(args));
var inventory = await new KubernetesProvider(inventoryRunner).CollectAsync("inventory", new Dictionary<string, string>(scope) { ["kubernetes-nodes"] = "true" });
Check(inventory.OperationSucceeded && State(inventory) == "complete", "Complete required metadata reads may succeed despite observed warning findings");
Check(inventoryRunner.Calls.Count == 8 && Data(inventory).GetProperty("resources").GetArrayLength() == 8, "All permitted workload, namespace, node, service and event projections are present");
Check(inventoryRunner.Calls.All(call => call.Tool == "kubectl" && KubernetesCommandRunner.Validate(call.Arguments) != "metrics"), "Inventory uses only validated projected read commands");
Check(inventory.Findings.Any(item => item.Code == "KUBERNETES_POD_NOT_READY") && inventory.Findings.Any(item => item.Code == "KUBERNETES_WORKLOAD_REPLICAS"), "Running-unready pods and unavailable desired replicas remain visible");
Check(Data(inventory).GetProperty("cluster").GetProperty("cloudCorrelationVerified").GetBoolean() == false, "Cluster names never establish an infrastructure-cloud identity match");
var redacted = ReportSecurity.Serialize(inventory);
foreach (var forbidden in new[] { "private-cluster-context", "private-namespace", "private-pod", "private-node", "private-event", "PRIVATE_RAW_SECRET", "uid-private" })
    Check(!redacted.Contains(forbidden, StringComparison.Ordinal), "Cluster output redacts identifiers and excludes unknown source fields: " + forbidden);
Check(!JsonSerializer.Serialize(inventory.Data, ReportSecurity.JsonOptions).Contains("PRIVATE_RAW_SECRET", StringComparison.Ordinal), "Unknown source fields are excluded even from full reports");
var healthRunner = new FakeRunner((_, args, _) => Metadata(args));
var health = await new KubernetesProvider(healthRunner).CollectAsync("health", scope);
Check(health.OperationSucceeded && healthRunner.Calls.All(call => call.Arguments[4] is not ("nodes" or "services")), "Default health reads neither node inventory nor service configuration");
var twoNamespaces = await new KubernetesProvider(new FakeRunner((_, args, _) => Metadata(args))).CollectAsync("inventory", new Dictionary<string, string>(scope) { ["namespaces"] = "one,two" });
Check(twoNamespaces.OperationSucceeded && Data(twoNamespaces).GetProperty("coverage").GetProperty("completedScopes").GetInt32() == 2, "Two namespaces retain independently completed coverage");

foreach (var settings in new[]
{
    new Dictionary<string, string>(),
    new Dictionary<string, string> { ["context"] = "reader" },
    new Dictionary<string, string>(scope) { ["namespaces"] = "*" },
    new Dictionary<string, string>(scope) { ["namespaces"] = "one,,two" },
    new Dictionary<string, string>(scope) { ["namespaces"] = "one,one" },
    new Dictionary<string, string>(scope) { ["namespaces"] = "../../other" },
    new Dictionary<string, string>(scope) { ["kubernetes-nodes"] = "yes" },
    new Dictionary<string, string>(scope) { ["context"] = "--server=https://untrusted.invalid" }
})
{
    var runner = new FakeRunner((_, _, _) => throw new Exception("Unexpected provider call"));
    var result = await new KubernetesProvider(runner).CollectAsync("inventory", settings);
    Check(!result.OperationSucceeded && State(result) == "not_configured" && runner.Calls.Count == 0, "Invalid cluster scopes are rejected before any credential or provider call");
}
var unsupportedRunner = new FakeRunner((_, _, _) => throw new Exception("Unexpected provider call"));
Check(!((await new KubernetesProvider(unsupportedRunner).CollectAsync("delete", scope)).OperationSucceeded) && unsupportedRunner.Calls.Count == 0, "Unsupported operations do not invoke kubectl");
var wrongScopeRunner = new FakeRunner((_, _, _) => Element(new { kind = "namespaces", rows = new[] { new { name = "other-namespace", state = "Active" } }, truncated = false, malformedRows = 0 }));
var wrongScope = await new KubernetesProvider(wrongScopeRunner).CollectAsync("inventory", scope);
Check(!wrongScope.OperationSucceeded && wrongScopeRunner.Calls.Count == 1 && Data(wrongScope).GetProperty("resources").GetArrayLength() == 0, "A namespace mismatch stops subsequent resource reads");
var denied = await new KubernetesProvider(new FakeRunner((_, _, _) => throw new KubernetesQueryException("permission_denied", "PRIVATE_RAW_SECRET"))).CollectAsync("inventory", scope);
Check(!denied.OperationSucceeded && State(denied) == "permission_denied" && !ReportSecurity.Serialize(denied).Contains("PRIVATE_RAW_SECRET", StringComparison.Ordinal), "RBAC failures have explicit sanitized coverage");
var timedOut = await new KubernetesProvider(new FakeRunner((_, _, _) => throw new OperationCanceledException("PRIVATE_RAW_SECRET"))).CollectAsync("inventory", scope);
Check(!timedOut.OperationSucceeded && State(timedOut) == "timed_out", "Internal read deadlines do not become successful empty inventory");
using (var cancelled = new CancellationTokenSource())
{
    cancelled.Cancel();
    try { await new KubernetesProvider(inventoryRunner).CollectAsync("inventory", scope, cancelled.Token); throw new Exception("Cancelled collection accepted"); }
    catch (OperationCanceledException) { checks++; }
}
using (var cancelledDuringRead = new CancellationTokenSource())
{
    var cancelRunner = new FakeRunner((_, _, _) => { cancelledDuringRead.Cancel(); throw new OperationCanceledException(cancelledDuringRead.Token); });
    try { await new KubernetesProvider(cancelRunner).CollectAsync("inventory", scope, cancelledDuringRead.Token); throw new Exception("Mid-read user cancellation became partial success"); }
    catch (OperationCanceledException) { Check(cancelRunner.Calls.Count == 1, "Caller cancellation propagates immediately instead of starting more namespace reads"); }
}

var metricsRunner = new FakeRunner((_, _, token) => { Check(token.CanBeCanceled, "Metric reads receive the total collection deadline"); return Metrics("private-namespace"); });
var metrics = await new KubernetesProvider(metricsRunner).CollectAsync("metrics", scope);
var series = Data(metrics).GetProperty("metrics");
Check(metrics.OperationSucceeded && series.GetArrayLength() == 2, "A real pod observation produces CPU and memory with separate units");
Check(series[0].GetProperty("unit").GetString() == "millicores" && series[0].GetProperty("points")[0].GetProperty("value").GetDouble() == 250, "Container CPU nanocores and millicores aggregate into real pod millicores");
Check(Data(metrics).GetProperty("coverage").GetProperty("enumeratedResources").GetInt32() == 1, "CPU and memory series count one observed pod rather than reporting zero resources or double counting it");
Check(series[1].GetProperty("unit").GetString() == "bytes" && series[1].GetProperty("points")[0].GetProperty("value").GetInt64() == 1572864, "Container binary memory quantities aggregate into bytes");
Check(!series[0].TryGetProperty("samplingPeriodSeconds", out _) && series[0].GetProperty("observedWindow").GetString() == "30s", "Metrics Server observations do not invent a periodic historical cadence");
Check(metricsRunner.Calls.All(call => call.Arguments.Count == 6 && call.Arguments[5].StartsWith(metricPath, StringComparison.Ordinal)), "Metrics reads stay under the explicitly allowed namespace");
foreach (var forbidden in new[] { "private-namespace", "private-pod", "private-cluster-context", "PRIVATE_RAW_SECRET" }) Check(!ReportSecurity.Serialize(metrics).Contains(forbidden, StringComparison.Ordinal), "Metric labels redact cluster identities: " + forbidden);
var zeroMetrics = await new KubernetesProvider(new FakeRunner((_, _, _) => Metrics("private-namespace", cpu: "0", memory: "0", second: false))).CollectAsync("metrics", scope);
Check(zeroMetrics.OperationSucceeded && Data(zeroMetrics).GetProperty("metrics").EnumerateArray().All(item => item.GetProperty("points")[0].GetProperty("value").GetDouble() == 0), "Actual zero observations stay zero");
var emptyMetrics = await new KubernetesProvider(new FakeRunner((_, _, _) => Element(new { kind = "PodMetricsList", apiVersion = "metrics.k8s.io/v1beta1", items = Array.Empty<object>() }))).CollectAsync("metrics", scope);
Check(emptyMetrics.OperationSucceeded && State(emptyMetrics) == "no_data" && Data(emptyMetrics).GetProperty("metrics").GetArrayLength() == 0, "An empty successful Metrics Server read remains no_data without synthesized zeros");
foreach (var response in new[]
{
    Metrics("other-namespace"), Metrics("private-namespace", timestamp: DateTimeOffset.UtcNow.AddHours(-1)),
    Metrics("private-namespace", timestamp: DateTimeOffset.UtcNow.AddHours(1)), Metrics("private-namespace", window: "99h"),
    Metrics("private-namespace", window: "0s"), Metrics("private-namespace", cpu: "NaN", memory: "-1", second: false),
    Element(new { kind = "SecretList", apiVersion = "v1", items = Array.Empty<object>() })
})
{
    var result = await new KubernetesProvider(new FakeRunner((_, _, _) => response)).CollectAsync("metrics", scope);
    Check(!result.OperationSucceeded, "Wrong scope, stale/future times, invalid windows/quantities and foreign envelopes cannot claim complete metrics");
}
var missingMetrics = await new KubernetesProvider(new FakeRunner((_, _, _) => throw new KubernetesQueryException("unavailable", "PRIVATE_RAW_SECRET"))).CollectAsync("metrics", scope);
Check(!missingMetrics.OperationSucceeded && Data(missingMetrics).GetProperty("metrics").GetArrayLength() == 0, "Missing Metrics Server does not create zero CPU or memory");
var pages = 0;
var repeatedTime = DateTimeOffset.UtcNow.AddSeconds(-30);
var repeatedPages = await new KubernetesProvider(new FakeRunner((_, args, _) => { pages++; Check(KubernetesCommandRunner.Validate(args) == "metrics", "Continued metric paths retain the fixed grammar"); return Metrics("private-namespace", timestamp: repeatedTime, continuation: "repeated"); })).CollectAsync("metrics", scope);
Check(!repeatedPages.OperationSucceeded && pages == 2 && Data(repeatedPages).GetProperty("metrics").GetArrayLength() == 2, "Repeated continuations stop after two pages and duplicate samples are not retained twice");
var oversizedRunner = new FakeRunner((_, args, _) => args[4] == "namespaces" ? Metadata(args) : Element(new { kind = args[4], rows = Enumerable.Range(0, 1100).Select(index => new { name = "pod-" + index, state = "Running", ready = "true", restarts = "0" }).ToArray(), truncated = false, malformedRows = 0 }));
var bounded = await new KubernetesProvider(oversizedRunner).CollectAsync("inventory", scope);
Check(!bounded.OperationSucceeded && Data(bounded).GetProperty("resources").GetArrayLength() == 1000, "The entire collection has a 1000-resource bound even with an injected oversized page");

const string nodeReference = "gce://project-alpha/europe-west1-b/node-one";
const string gcpResourceId = "//compute.googleapis.com/projects/project-alpha/zones/europe-west1-b/instances/node-one";
var gcpResource = new CloudResource("gcp", "project-alpha", "europe-west1-b", gcpResourceId, "compute.googleapis.com/Instance", "node-one");
var gcpInventory = Infrastructure("gcp", [gcpResource]);
var clusterReferences = ClusterReferences(("node-one", nodeReference));
var linked = KubernetesInfrastructureLinker.Correlate(clusterReferences, [gcpInventory]);
Check(linked.State == "verified_node_references" && linked.NodeReferencesVerified && !linked.ClusterIdentityVerified && linked.MatchedNodes == 1, "An exact current GCP node reference can match infrastructure without asserting cluster identity");
Check(linked.Links is [{ Provider: "gcp", Account: "project-alpha", Region: "europe-west1-b", ResourceId: gcpResourceId, NodeId: "cluster/nodes/node-one" }], "A verified link retains exact provider, account, zone and canonical resource identity");
var applied = KubernetesInfrastructureLinker.Apply(clusterReferences, [gcpInventory]);
Check(applied.OperationSucceeded && !Data(applied).GetProperty("cluster").GetProperty("cloudCorrelationVerified").GetBoolean() && Data(applied).GetProperty("infrastructureCorrelation").GetProperty("nodeReferencesVerified").GetBoolean(), "Applying links preserves collection success and the unverified cluster identity");
Check(!JsonSerializer.Serialize(applied.Data, ReportSecurity.JsonOptions).Contains("CLOUD_SECRET", StringComparison.Ordinal), "Infrastructure correlation never copies arbitrary cloud resource properties");
var partialLinks = KubernetesInfrastructureLinker.Correlate(ClusterTwoReferences(("node-one", nodeReference), ("node-two", "aws:///eu-west-1a/i-0123456789abcdef0")), [gcpInventory]);
Check(partialLinks.State == "partial_node_references" && partialLinks.MatchedNodes == 1 && partialLinks.UnmatchedNodes == 1 && !partialLinks.ClusterIdentityVerified, "Unsupported or account-less node references remain unmatched beside a verified reference");
Check(!KubernetesInfrastructureLinker.Correlate(ClusterReferences(("same-name", "")), [gcpInventory]).NodeReferencesVerified, "Similar node and cloud names never establish a link");
foreach (var invalidReference in new[]
{
    "gce://project-alpha/europe-west1-b/node-one?token=PRIVATE_SECRET", "gce://project-alpha/europe-west1-b/../node-one",
    "gce://project-alpha/europe-west1-b/node%2Done", "gce://project-alpha/europe-west1-b/node-one#fragment",
    "https://compute.googleapis.com/projects/project-alpha/zones/europe-west1-b/instances/node-one",
    "gce://project-beta/europe-west1-b/node-one", "gce://project-alpha/europe-west1-c/node-one",
    "azure:///subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/pool/virtualMachines/1"
}) Check(!KubernetesInfrastructureLinker.Correlate(ClusterReferences(("node-one", invalidReference)), [gcpInventory]).NodeReferencesVerified, "Malformed, foreign, mismatched or unsupported references cannot establish a link");
foreach (var invalidCloud in new[]
{
    gcpInventory with { OperationSucceeded = false }, gcpInventory with { CollectedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-6) },
    gcpInventory with { CollectedAtUtc = DateTimeOffset.UtcNow.AddMinutes(3) }, gcpInventory with { Kind = "cloud.gcp.health" },
    Infrastructure("gcp", [gcpResource], coverage: "partial"), Infrastructure("gcp", [gcpResource], completed: 0),
    Infrastructure("gcp", [gcpResource], accounts: ["project-beta"]),
    Infrastructure("gcp", [gcpResource with { Account = "project-beta" }]),
    Infrastructure("gcp", [gcpResource with { Region = "europe-west1" }]),
    Infrastructure("gcp", [gcpResource with { Type = "container.googleapis.com/Cluster" }]),
    Infrastructure("gcp", [gcpResource with { Id = "[redacted-identifier]" }]),
    Infrastructure("gcp", [gcpResource, gcpResource])
}) Check(!KubernetesInfrastructureLinker.Correlate(clusterReferences, [invalidCloud]).NodeReferencesVerified, "Incomplete, stale, redacted, ambiguous or out-of-scope cloud evidence never verifies a reference");
Check(!KubernetesInfrastructureLinker.Correlate(clusterReferences, [gcpInventory, gcpInventory]).NodeReferencesVerified, "A canonical resource duplicated across reports remains ambiguous");
foreach (var invalidCluster in new[]
{
    clusterReferences with { OperationSucceeded = false }, clusterReferences with { CollectedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-6) },
    clusterReferences with { Kind = "cluster/kubernetes/metrics" }, ClusterReferences(("node-one", nodeReference), coverage: "partial"),
    ClusterReferences(("node-one", nodeReference), includesNodes: false), ClusterReferences(("node-one", nodeReference), account: "other-context"),
    ClusterTwoReferences(("node-one", nodeReference), ("node-two", nodeReference))
}) Check(!KubernetesInfrastructureLinker.Correlate(invalidCluster, [gcpInventory]).NodeReferencesVerified, "Failed, stale, incomplete, unrequested, mismatched or duplicate node evidence never establishes links");
Check(!KubernetesInfrastructureLinker.Correlate(clusterReferences, Enumerable.Repeat(gcpInventory, 21).ToArray()).NodeReferencesVerified, "Correlation rejects more than twenty infrastructure reports");
Check(!KubernetesInfrastructureLinker.Correlate(clusterReferences, [Infrastructure("gcp", Enumerable.Repeat(gcpResource, 10001).ToArray())]).NodeReferencesVerified, "Correlation rejects an inventory exceeding the ten-thousand-resource bound");
const string azureAccount = "00000000-0000-0000-0000-000000000001";
const string azureId = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/PrivateGroup/providers/Microsoft.Compute/virtualMachines/PrivateVm";
var azureResource = new CloudResource("azure", azureAccount, "westeurope", azureId, "Microsoft.Compute/virtualMachines", "PrivateVm");
var azureInventory = Infrastructure("azure", [azureResource], accounts: [azureAccount]);
var azureCluster = ClusterReferences(("azure-node", "azure://" + azureId));
foreach (var group in new[] { ".", "..", "group." })
    Check(!KubernetesInfrastructureLinker.IsSupportedReference("azure://" + azureId.Replace("PrivateGroup", group, StringComparison.Ordinal)), "Azure provider references reject dot segments and invalid trailing-period resource groups");
var azureLink = KubernetesInfrastructureLinker.Correlate(azureCluster, [azureInventory]);
Check(azureLink.NodeReferencesVerified && !azureLink.ClusterIdentityVerified && azureLink.Links[0].Account == azureAccount && azureLink.Links[0].Region == "westeurope", "Azure links require the exact subscription/resource path and retain the inventory-observed region");
Check(KubernetesInfrastructureLinker.Correlate(ClusterReferences(("azure-node", "azure://" + azureId.ToLowerInvariant())), [azureInventory]).NodeReferencesVerified, "Azure resource ID comparison follows case-insensitive ARM identity semantics");
Check(!KubernetesInfrastructureLinker.Correlate(azureCluster, [azureInventory with { Warnings = ["Azure resource inventory reached a row limit; results are incomplete."] }]).NodeReferencesVerified, "Azure truncation warnings block a complete-reference claim");
Check(!KubernetesInfrastructureLinker.Correlate(azureCluster, [azureInventory with { Warnings = Enumerable.Repeat("Observation", 129).ToArray() }]).NodeReferencesVerified, "Correlation bounds its traversal of Azure coverage warnings");
Check(!KubernetesInfrastructureLinker.Correlate(azureCluster, [azureInventory with { Warnings = [new string('x', 2049)] }]).NodeReferencesVerified, "Correlation rejects oversized unstructured coverage warnings");
Check(!KubernetesInfrastructureLinker.Correlate(azureCluster, [Infrastructure("azure", [azureResource], accounts: ["00000000-0000-0000-0000-000000000002"])]).NodeReferencesVerified, "Azure subscription allowlists cannot be widened by a resource or node path");
Check(!KubernetesInfrastructureLinker.Correlate(azureCluster, [Infrastructure("azure", [azureResource with { Account = "00000000-0000-0000-0000-000000000002" }], accounts: [azureAccount])]).NodeReferencesVerified, "Azure account and canonical resource ID must agree");
var scopedReferenceRunner = new FakeRunner((_, args, _) => args[4] == "nodes" ? Element(new { kind = "nodes", rows = new[] { new { name = "node-one", ready = "True", infrastructureResourceId = nodeReference } }, truncated = false, malformedRows = 0 }) : Metadata(args));
var referenceInventory = await new KubernetesProvider(scopedReferenceRunner).CollectAsync("inventory", new Dictionary<string, string>(scope) { ["kubernetes-nodes"] = "true" });
Check(Data(referenceInventory).GetProperty("resources").EnumerateArray().Single(resource => resource.GetProperty("type").GetString() == "kubernetes.node").GetProperty("properties").GetProperty("infrastructureResourceId").GetString() == nodeReference, "Only the opted-in fixed node projection retains a canonical infrastructure reference");
Check(!Data(referenceInventory).GetProperty("infrastructureCorrelation").GetProperty("nodeReferencesVerified").GetBoolean(), "Collection alone does not verify a provider reference without backend inventory");
var invalidReferenceRunner = new FakeRunner((_, args, _) => args[4] == "nodes" ? Element(new { kind = "nodes", rows = new[] { new { name = "node-one", ready = "True", infrastructureResourceId = "https://untrusted.invalid/PRIVATE_SECRET" } }, truncated = false, malformedRows = 0 }) : Metadata(args));
var invalidReferenceInventory = await new KubernetesProvider(invalidReferenceRunner).CollectAsync("inventory", new Dictionary<string, string>(scope) { ["kubernetes-nodes"] = "true" });
Check(!JsonSerializer.Serialize(invalidReferenceInventory.Data, ReportSecurity.JsonOptions).Contains("PRIVATE_SECRET", StringComparison.Ordinal), "Invalid infrastructure references are omitted even from full cluster reports");
Check(!ReportSecurity.Serialize(referenceInventory).Contains(nodeReference, StringComparison.Ordinal), "Shared reports redact the complete infrastructure reference");
Check(!ReportSecurity.Serialize(applied).Contains("cluster/nodes/node-one", StringComparison.Ordinal), "Shared correlation output redacts node identifiers");

Console.WriteLine($"Kubernetes scoped metadata, grammar, metrics, privacy and bounds passed ({checks} checks).");

static JsonElement Element(object value) => JsonSerializer.SerializeToElement(value);
static AnalysisReport ClusterReferences((string Name, string Reference) node, string coverage = "complete", bool includesNodes = true, string account = "private-cluster-context") => ClusterReferenceSet([node], coverage, includesNodes, account);
static AnalysisReport ClusterTwoReferences((string Name, string Reference) first, (string Name, string Reference) second) => ClusterReferenceSet([first, second]);
static AnalysisReport ClusterReferenceSet((string Name, string Reference)[] nodes, string coverage = "complete", bool includesNodes = true, string account = "private-cluster-context") => new("cluster/kubernetes/inventory", DateTimeOffset.UtcNow, [], new
{
    provider = "kubernetes", operation = "inventory", cluster = new { includesNodes, cloudCorrelationVerified = false },
    scope = new { accounts = new[] { "private-cluster-context" }, namespaces = new[] { "private-namespace" } },
    resources = nodes.Select(node => new CloudResource("kubernetes", account, "cluster", "cluster/nodes/" + node.Name, "kubernetes.node", node.Name, new { infrastructureResourceId = node.Reference })).ToArray(),
    coverage = new { state = coverage, expectedScopes = 1, completedScopes = 1 }
});
static AnalysisReport Infrastructure(string provider, CloudResource[] resources, string coverage = "complete", int completed = 1, string[]? accounts = null) => new("cloud." + provider + ".inventory", DateTimeOffset.UtcNow, [], new
{
    provider, operation = "inventory", resources = resources.Select(resource => resource with { Properties = new { password = "CLOUD_SECRET" } }).ToArray(),
    scope = provider == "gcp" ? (object)new { accounts = accounts ?? new[] { "project-alpha" } } : new { subscriptions = accounts ?? Array.Empty<string>() },
    coverage = new { state = coverage, expectedScopes = 1, completedScopes = completed }
});
static IReadOnlyList<string> MetadataArguments(string kind, string ns)
{
    var args = new List<string> { "--context", "reader", "--request-timeout=10s", "get", kind };
    if (kind == "namespaces") args.Add(ns); else if (kind != "nodes") args.AddRange(["--namespace", ns]);
    args.AddRange(["--chunk-size=100", "--no-headers", "--output=custom-columns=" + KubernetesCommandRunner.Columns[kind]]);
    return args;
}
static JsonElement Metadata(IReadOnlyList<string> args)
{
    var kind = KubernetesCommandRunner.Validate(args);
    var name = kind == "namespaces" ? args[5] : kind == "nodes" ? "private-node" : kind == "events.events.k8s.io" ? "private-event" : kind == "pods" ? "private-pod" : "private-" + kind;
    return Element(new { kind, rows = new[] { new { name, uid = "uid-private", state = kind == "namespaces" ? "Active" : "Running", ready = kind == "nodes" ? "False" : "true,false", restarts = "1,2", desired = "3", available = "2", updated = "2", type = kind == "services" ? "ClusterIP" : "Warning", ports = "80,443", reason = "BackOff", observedAt = DateTimeOffset.UtcNow.ToString("O"), count = "1", cpu = "4", memory = "8Gi", version = "v1.31.3", environment = "PRIVATE_RAW_SECRET" } }, truncated = false, malformedRows = 0 });
}
static JsonElement Metrics(string ns, DateTimeOffset? timestamp = null, string window = "30s", string cpu = "125000000n", string memory = "1Mi", bool second = true, string continuation = "") => Element(new
{
    apiVersion = "metrics.k8s.io/v1beta1", kind = "PodMetricsList", metadata = new { @continue = continuation },
    items = new[] { new { metadata = new { name = "private-pod", @namespace = ns }, timestamp = (timestamp ?? DateTimeOffset.UtcNow.AddSeconds(-30)).ToString("O", CultureInfo.InvariantCulture), window,
        containers = second ? new[] { new { name = "private-container", usage = new { cpu, memory } }, new { name = "second-container", usage = new { cpu = "125m", memory = "512Ki" } } } : new[] { new { name = "private-container", usage = new { cpu, memory } } }, secret = "PRIVATE_RAW_SECRET" } }
});

sealed class FakeRunner(Func<string, IReadOnlyList<string>, CancellationToken, JsonElement> respond) : ICloudCommandRunner
{
    public List<(string Tool, IReadOnlyList<string> Arguments)> Calls { get; } = [];
    public Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    { cancellationToken.ThrowIfCancellationRequested(); Calls.Add((tool, arguments.ToArray())); return Task.FromResult(respond(tool, arguments, cancellationToken)); }
}
