using System.Text.Json;
using System.Text.Json.Nodes;
using Opscope;
using Opscope.Cloud;

const string Project = "private-project-123";
const string Region = "europe-west1";
const string Zone = "europe-west1-b";
string[] types = ["compute.googleapis.com/Instance", "compute.googleapis.com/Disk", "compute.googleapis.com/Address", "compute.googleapis.com/Network", "compute.googleapis.com/Firewall", "container.googleapis.com/Cluster", "sqladmin.googleapis.com/Instance", "run.googleapis.com/Service", "storage.googleapis.com/Bucket"];
var count = 0;
var directory = Path.Combine(Path.GetTempPath(), "opscope-gcp-drift-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(directory);
var path = Path.Combine(directory, "private-baseline.json");
try
{
    var baseReport = Report([Resource("host-a", "RUNNING"), Resource("host-b", "TERMINATED")]);
    var same = await Compare(baseReport, Report([Resource("host-b", "TERMINATED"), Resource("host-a", "RUNNING")]));
    Check(same.OperationSucceeded && Coverage(same) == "Complete", "Matching complete scopes permit a completed comparison");
    Check(Changes(same).GetArrayLength() == 0 && Drift(same).GetProperty("comparedResources").GetInt32() == 2, "Resource ordering does not produce drift");
    Check(Drift(same).GetProperty("comparedFields").GetInt32() == 4, "Only shared region and state fields are compared");
    Check(Drift(same).GetProperty("absenceAssessmentAvailable").GetBoolean(), "Complete matching scopes expose bounded absence assessment");

    var changed = await Compare(baseReport, Report([Resource("host-a", "STOPPED"), Resource("host-c", "RUNNING")]));
    Check(changed.OperationSucceeded && Changes(changed).GetArrayLength() == 3, "Known changed, added and missing observations remain distinct");
    Check(Drift(changed).GetProperty("addedResources").GetInt32() == 1 && Drift(changed).GetProperty("missingResources").GetInt32() == 1 && Drift(changed).GetProperty("changedResources").GetInt32() == 1, "Distinct change counts are preserved");
    var changedEntry = Changes(changed).EnumerateArray().Single(row => row.GetProperty("changeType").GetString() == "Changed");
    Check(changedEntry.GetProperty("fields").EnumerateArray().Select(field => field.GetString()).SequenceEqual(["state"]), "Changed evidence names only the observed changed fields");
    Check(changed.Findings.All(finding => finding.Severity == FindingSeverity.Info), "Observation differences do not imply security violations");
    Check(!ReportSecurity.Serialize(changed).Contains(Project, StringComparison.Ordinal) && !ReportSecurity.Serialize(changed).Contains("host-a", StringComparison.Ordinal), "Shared drift output redacts project and resource identities");
    var full = ReportSecurity.Serialize(changed, false);
    Check(!full.Contains("TERMINATED", StringComparison.Ordinal) && !full.Contains("expectedValue", StringComparison.Ordinal) && !full.Contains(path, StringComparison.Ordinal), "Baseline values and private paths are not emitted");

    var partialCurrent = Report([Resource("host-a", "STOPPED"), Resource("host-c", "RUNNING")], complete: false);
    var partial = await Compare(baseReport, partialCurrent);
    Check(!partial.OperationSucceeded && Coverage(partial) == "Partial", "Partial live inventory cannot establish complete drift coverage");
    Check(Changes(partial).GetArrayLength() == 1 && Changes(partial)[0].GetProperty("changeType").GetString() == "Changed", "Partial live reads suppress missing and added assessments but preserve shared changes");
    Check(!Drift(partial).GetProperty("absenceAssessmentAvailable").GetBoolean(), "Partial live coverage explicitly disables absence assessment");
    var partialBaseline = await Compare(Report([Resource("host-a", "RUNNING"), Resource("host-b", "RUNNING")], complete: false), Report([Resource("host-a", "STOPPED"), Resource("host-c", "RUNNING")]));
    Check(!partialBaseline.OperationSucceeded && Changes(partialBaseline).GetArrayLength() == 1, "Partial baseline suppresses apparent additions and omissions");

    var unknown = await Compare(Report([Resource("host-a", "[redacted]")]), Report([Resource("host-a", "RUNNING")]));
    Check(Coverage(unknown) == "Partial" && Changes(unknown).GetArrayLength() == 0 && Drift(unknown).GetProperty("unknownFields").GetInt32() == 1, "Redacted state is unknown, never an observed change");
    var absentState = await Compare(Report([Resource("host-a", "")]), Report([Resource("host-a", "RUNNING")]));
    Check(Coverage(absentState) == "Partial" && Changes(absentState).GetArrayLength() == 0, "Absent state is excluded without a zero/default substitution");
    var unknownAbsence = await Compare(Report([Resource("host-a", ""), Resource("host-b", "")]), Report([Resource("host-a", "")]));
    Check(Coverage(unknownAbsence) == "Partial" && Drift(unknownAbsence).GetProperty("absenceAssessmentAvailable").GetBoolean() && Drift(unknownAbsence).GetProperty("missingResources").GetInt32() == 1, "Unknown state limits field comparison without discarding independently complete enumeration");
    var extras = Rewrite(baseReport, data =>
    {
        data["resources"]![0]!["properties"]!["password"] = "never-emit-this-secret";
        data["resources"]![0]!["properties"]!["tags"] = new JsonObject { ["arbitrary"] = "never-emit-label" };
        data["resources"]![0]!["properties"]!["observedAtUtc"] = "2000-01-01T00:00:00Z";
        data["resources"]![0]!["name"] = "never-emit-display-name";
    });
    var ignored = await Compare(extras, baseReport);
    Check(ignored.OperationSucceeded && Changes(ignored).GetArrayLength() == 0, "Names, observation timestamps and extra metadata do not produce drift");
    Check(!ReportSecurity.Serialize(ignored, false).Contains("never-emit", StringComparison.Ordinal), "Raw baseline metadata is never copied into drift evidence");

    await Invalid(Rewrite(baseReport, data => data["scope"]!["accounts"] = new JsonArray("other-project-123")), baseReport, "Cross-project baseline is rejected");
    await Invalid(Rewrite(baseReport, data => data["scope"]!["region"] = Region), baseReport, "Different region filters cannot be compared");
    await Invalid(Rewrite(baseReport, data => data["scope"]!["resource"] = Id("host-a")), baseReport, "Filtered baseline cannot establish whole-project absence");
    await Invalid(Rewrite(baseReport, data => data["scope"]!["profile"] = "other-profile"), baseReport, "Profile selector mismatch is rejected");
    await Invalid(Rewrite(baseReport, data => data["scope"]!["schemaVersion"] = 2), baseReport, "Unknown scope schema is rejected");
    await Invalid(Rewrite(baseReport, data => data["scope"]!.AsObject().Remove("assetTypes")), baseReport, "Old baselines without explicit resource universe must be regenerated");
    await Invalid(Rewrite(baseReport, data => data["scope"]!["assetTypes"] = new JsonArray(types.Take(8).Select(value => (JsonNode?)JsonValue.Create(value)).ToArray())), baseReport, "Different asset type universe is rejected");
    await Invalid(Rewrite(baseReport, data => data["scope"]!["accounts"] = new JsonArray(Project, Project)), baseReport, "Duplicate scope projects are rejected");
    await Invalid(Rewrite(baseReport, data => data["resources"]![0]!["account"] = "other-project-123"), baseReport, "Resource ownership must match explicit selected projects");
    await Invalid(Rewrite(baseReport, data => data["resources"]![0]!["id"] = "[redacted-1]"), baseReport, "Redacted resource identities fail closed");
    await Invalid(Rewrite(baseReport, data => data["resources"]![0]!["id"] = "//compute.googleapis.com/projects/other-project-123/zones/europe-west1-b/instances/host-a"), baseReport, "Canonical ID must bind the same project");
    await Invalid(Rewrite(baseReport, data => data["resources"]![0]!["id"] = Id("host-a") + "?token=never-emit"), baseReport, "Query-bearing resource identities are rejected");
    await Invalid(Rewrite(baseReport, data => data["resources"]![0]!["provider"] = "aws"), baseReport, "Other-provider resources cannot enter comparison");
    await Invalid(Rewrite(baseReport, data => data["resources"]![0]!["type"] = "compute.googleapis.com/Unknown"), baseReport, "Unknown resource types cannot broaden comparison");
    await Invalid(Rewrite(baseReport, data => data["resources"]!.AsArray().Add(data["resources"]![0]!.DeepClone())), baseReport, "Duplicate resource identities fail closed");
    await Invalid(Rewrite(baseReport, data => data["coverage"]!["enumeratedResources"] = 0), baseReport, "Coverage row count must match retained resources");
    await Invalid(Rewrite(baseReport, data => data["coverage"]!["state"] = "0"), baseReport, "Numeric-string coverage does not default to Complete");
    await Invalid(Rewrite(baseReport, data => data["coverage"]!.AsObject().Remove("state")), baseReport, "Missing coverage never defaults to complete");
    await Invalid(Rewrite(baseReport, data => data["coverage"]!["expectedScopes"] = 2), baseReport, "Coverage scope counts must match provenance");
    await Invalid(Rewrite(baseReport, data => data["operation"] = "services"), baseReport, "Service/bundle snapshots are not inventory baselines");
    await Invalid(baseReport with { Kind = "cloud/aws/inventory" }, baseReport, "Wrong report kind is rejected");
    await Invalid(baseReport with { CollectedAtUtc = DateTimeOffset.UtcNow.AddHours(1) }, baseReport, "Implausible future baseline timestamps are rejected");

    var optionsMismatch = await Compare(baseReport, baseReport, new Dictionary<string, string> { ["region"] = Region });
    Check(Coverage(optionsMismatch) == "Failed" && Changes(optionsMismatch).GetArrayLength() == 0, "Runtime query options must agree with provenance");
    var failedCurrent = await Compare(baseReport, baseReport with { OperationSucceeded = false });
    Check(Coverage(failedCurrent) == "Partial" && !Drift(failedCurrent).GetProperty("absenceAssessmentAvailable").GetBoolean(), "Execution failure overrides a complete-looking coverage string");
    var oldKind = await Compare(baseReport with { Kind = "cloud.gcp.inventory" }, baseReport);
    Check(oldKind.OperationSucceeded, "Both CLI and provider normalized inventory kinds are accepted");
    var empty = await Compare(Report([]), Report([]));
    Check(empty.OperationSucceeded && Changes(empty).GetArrayLength() == 0, "Explicit complete empty inventories remain comparable observations");
    var newlyObserved = await Compare(Report([]), Report([Resource("host-a", "RUNNING")]));
    Check(Drift(newlyObserved).GetProperty("addedResources").GetInt32() == 1, "A valid empty baseline can describe a subsequent observed addition");

    var filtered = Rewrite(Report([Resource("host-a", "RUNNING")]), data => { data["scope"]!["region"] = Region; data["scope"]!["resource"] = Id("host-a"); });
    var filteredResult = await Compare(filtered, filtered, new() { ["region"] = Region, ["resource"] = Id("host-a") });
    Check(filteredResult.OperationSucceeded, "Identical explicit region/resource filters are comparable");
    var relativeFiltered = Rewrite(filtered, data => data["scope"]!["resource"] = Id("host-a")["//compute.googleapis.com/".Length..]);
    var relativeResult = await Compare(relativeFiltered, filtered, new() { ["region"] = " " + Region + " ", ["resource"] = Id("host-a")["//compute.googleapis.com/".Length..] });
    Check(relativeResult.OperationSucceeded, "Equivalent canonical Compute resource aliases and trimmed selectors match the actual query");
    var unsupportedProfile = Rewrite(filtered, data => data["scope"]!["profile"] = "reader-profile");
    await Invalid(unsupportedProfile, unsupportedProfile, "Matching historical profile selectors are rejected because GCP never implemented that selector", new() { ["region"] = Region, ["resource"] = Id("host-a"), ["profile"] = "reader-profile" });
    var misplaced = Rewrite(filtered, data => data["resources"]![0]!["region"] = "us-central1-a");
    await Invalid(misplaced, filtered, "Resource outside selected region is rejected", new() { ["region"] = Region, ["resource"] = Id("host-a") });

    var multi = Rewrite(baseReport, data => data["scope"]!["accounts"] = new JsonArray(Project, "second-project-123"));
    multi = Rewrite(multi, data => { data["coverage"]!["expectedScopes"] = 2; data["coverage"]!["completedScopes"] = 2; });
    var multiReversed = Rewrite(multi, data => data["scope"]!["accounts"] = new JsonArray("second-project-123", Project));
    var multiResult = await Compare(multi, multiReversed, new() { ["projects"] = "second-project-123," + Project });
    Check(multiResult.OperationSucceeded, "Scope ordering does not change the explicit project set");
    var semicolonResult = await Compare(multi, multiReversed, new() { ["projects"] = "second-project-123;" + Project + ";" + Project });
    Check(semicolonResult.OperationSucceeded, "Semicolon-delimited deduplicated scope selectors match GcpProvider parsing");

    var runner = new AssetRunner(Project, Zone);
    var integratedProvider = new GcpProvider(runner);
    var inventoryExport = await integratedProvider.CollectAsync("inventory", new Dictionary<string, string> { ["project"] = Project });
    Check(inventoryExport.OperationSucceeded, "Provider generates a complete normalized inventory for an explicitly scoped asset read");
    await File.WriteAllTextAsync(path, ReportSecurity.Serialize(inventoryExport, false));
    runner.State = "STOPPED";
    var integrated = await integratedProvider.CollectAsync("drift", Options());
    Check(integrated.OperationSucceeded && Coverage(integrated) == "Complete" && Drift(integrated).GetProperty("changedResources").GetInt32() == 1, "Real normalized provider exports roundtrip through the integrated drift operation");
    Check(runner.Calls == 2 && runner.Commands.All(command => command == "asset search-all-resources"), "Integrated baseline comparison only reads the bounded live asset inventory");
    Check(Changes(integrated)[0].GetProperty("fields").EnumerateArray().Select(field => field.GetString()).SequenceEqual(["state"]), "Integrated provider comparison excludes volatile observation timestamps");
    await File.WriteAllTextAsync(path, ReportSecurity.Serialize(inventoryExport));
    var redactedExport = await integratedProvider.CollectAsync("drift", Options());
    Check(Coverage(redactedExport) == "Failed" && Changes(redactedExport).GetArrayLength() == 0, "A real redacted provider export cannot establish full baseline identity");

    var noBaseline = await GcpBaselineComparer.CompareAsync(baseReport, new Dictionary<string, string> { ["project"] = Project });
    Check(Coverage(noBaseline) == "NotConfigured" && !noBaseline.OperationSucceeded, "Missing baseline is explicitly not configured");
    var missing = await GcpBaselineComparer.CompareAsync(baseReport, new Dictionary<string, string> { ["project"] = Project, ["baseline"] = Path.Combine(directory, "not-present-private.json") });
    Check(Coverage(missing) == "Failed" && !ReportSecurity.Serialize(missing, false).Contains("not-present-private", StringComparison.Ordinal), "Unavailable baseline emits no raw file path");
    await File.WriteAllTextAsync(path, "{not-valid-json-private-value}");
    var malformed = await GcpBaselineComparer.CompareAsync(baseReport, Options());
    Check(Coverage(malformed) == "Failed" && !ReportSecurity.Serialize(malformed, false).Contains("private-value", StringComparison.Ordinal), "Malformed JSON fails without raw document/error text");
    await File.WriteAllTextAsync(path, new string(' ', SnapshotIO.MaximumBytes + 1));
    var oversized = await GcpBaselineComparer.CompareAsync(baseReport, Options());
    Check(Coverage(oversized) == "Failed", "Regular baseline input remains bounded to 16 MiB");
    await File.WriteAllTextAsync(path, ReportSecurity.Serialize(baseReport, false).Replace("\"provider\": \"gcp\"", "\"provider\": \"gcp\",\"PROVIDER\":\"aws\"", StringComparison.Ordinal));
    var duplicate = await GcpBaselineComparer.CompareAsync(baseReport, Options());
    Check(Coverage(duplicate) == "Failed", "Ambiguous duplicate fields cannot override evidence provenance");
    using var canceled = new CancellationTokenSource(); canceled.Cancel();
    var propagated = false;
    try { await GcpBaselineComparer.CompareAsync(baseReport, Options(), canceled.Token); } catch (OperationCanceledException) { propagated = true; }
    Check(propagated, "Caller cancellation is propagated");

    Console.WriteLine($"PASS: {count} GCP baseline drift checks.");
}
finally { Directory.Delete(directory, true); }

string Id(string name) => $"//compute.googleapis.com/projects/{Project}/zones/{Zone}/instances/{name}";
CloudResource Resource(string name, string state) => new("gcp", Project, Zone, Id(name), "compute.googleapis.com/Instance", name, new { state, observedAtUtc = DateTimeOffset.UtcNow });
AnalysisReport Report(CloudResource[] resources, bool complete = true) => new("cloud/gcp/inventory", DateTimeOffset.UtcNow, [], new
{
    provider = "gcp", operation = "inventory", resources,
    scope = new { schemaVersion = 1, accounts = new[] { Project }, region = (string?)null, resource = (string?)null, profile = (string?)null, assetTypes = types },
    coverage = new CloudCoverage(complete ? CoverageState.Complete : CoverageState.Partial, DateTimeOffset.UtcNow, resources.Length, 1, complete ? 1 : 0, [])
}) { OperationSucceeded = complete };
AnalysisReport Rewrite(AnalysisReport report, Action<JsonObject> rewrite)
{
    var data = JsonSerializer.SerializeToNode(report.Data, ReportSecurity.JsonOptions)!.AsObject();
    rewrite(data);
    return report with { Data = data };
}
Dictionary<string, string> Options() => new() { ["project"] = Project, ["baseline"] = path };
async Task<AnalysisReport> Compare(AnalysisReport baseline, AnalysisReport current, Dictionary<string, string>? extra = null)
{
    await File.WriteAllTextAsync(path, ReportSecurity.Serialize(baseline, false));
    var options = Options();
    if (extra is not null) foreach (var (key, value) in extra) options[key] = value;
    if (extra?.ContainsKey("projects") == true) options.Remove("project");
    return await GcpBaselineComparer.CompareAsync(current, options);
}
async Task Invalid(AnalysisReport baseline, AnalysisReport current, string message, Dictionary<string, string>? extra = null)
{
    var result = await Compare(baseline, current, extra);
    Check(!result.OperationSucceeded && Coverage(result) == "Failed" && Changes(result).GetArrayLength() == 0, message);
}
JsonElement Data(AnalysisReport report) => JsonSerializer.SerializeToElement(report.Data, ReportSecurity.JsonOptions);
JsonElement Drift(AnalysisReport report) => Data(report).GetProperty("drift");
JsonElement Changes(AnalysisReport report) => Drift(report).GetProperty("changes");
string Coverage(AnalysisReport report) => Data(report).GetProperty("coverage").GetProperty("state").GetString()!;
void Check(bool condition, string message) { if (!condition) throw new Exception(message); count++; }

sealed class AssetRunner(string project, string zone) : ICloudCommandRunner
{
    public int Calls { get; private set; }
    public string State { get; set; } = "RUNNING";
    public List<string> Commands { get; } = [];
    public Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls++;
        var command = string.Join(' ', arguments.Take(2));
        if (tool != "gcloud" || command != "asset search-all-resources") throw new InvalidOperationException("Unexpected provider query.");
        Commands.Add(command);
        return Task.FromResult(JsonSerializer.SerializeToElement(new[] { new { name = $"//compute.googleapis.com/projects/{project}/zones/{zone}/instances/integrated-host", assetType = "compute.googleapis.com/Instance", displayName = "integrated-host", location = zone, state = State, labels = new { secret = "never-emit-provider-label" } } }));
    }
}
