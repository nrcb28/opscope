using System.Text.Json;
using System.Text.RegularExpressions;

namespace Opscope.Cloud;

/// <summary>Compares explicitly scoped, normalized inventory observations; never queries or changes a provider.</summary>
public static class GcpBaselineComparer
{
    private static readonly string[] AssetTypes = ["compute.googleapis.com/Instance", "compute.googleapis.com/Disk", "compute.googleapis.com/Address", "compute.googleapis.com/Network", "compute.googleapis.com/Firewall", "container.googleapis.com/Cluster", "sqladmin.googleapis.com/Instance", "run.googleapis.com/Service", "storage.googleapis.com/Bucket"];
    private sealed record Scope(string[] Accounts, string? Region, string? Resource, string? Profile, string[] Types);
    private sealed record Resource(string Account, string Id, string Region, string Type, string? State)
    {
        public string Key => Account + "|" + Type + "|" + Id;
        public CloudResource Export() => new("gcp", Account, Region, Id, Type, "", new { state = State });
    }
    private sealed record Evidence(Scope Scope, Dictionary<string, Resource> Resources, bool Complete, bool UnknownFields, DateTimeOffset ObservedAtUtc);
    private sealed record Change(string Account, string ResourceId, string Region, string Type, string ChangeType, string[] Fields);

    public static async Task<AnalysisReport> CompareAsync(AnalysisReport current, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        var now = DateTimeOffset.UtcNow;
        var warnings = new List<string>();
        var changes = new List<Change>();
        var findings = new List<Finding>();
        Evidence? live = null;
        Evidence? baseline = null;
        var state = CoverageState.NotConfigured;
        var comparedResources = 0;
        var comparedFields = 0;
        var unknownFields = 0;
        if (!options.TryGetValue("baseline", out var path) || string.IsNullOrWhiteSpace(path))
        {
            warnings.Add("Google Cloud drift requires --baseline with a private normalized inventory JSON export created with --full. No baseline comparison was performed.");
            return Result();
        }
        try
        {
            var baselineJson = await SnapshotIO.ReadTextAsync(path, cancellationToken);
            SnapshotIO.ValidateJson(baselineJson);
            using var document = JsonDocument.Parse(baselineJson, new JsonDocumentOptions { MaxDepth = 48 });
            using var currentDocument = JsonDocument.Parse(JsonSerializer.Serialize(current, ReportSecurity.JsonOptions), new JsonDocumentOptions { MaxDepth = 48 });
            live = ReadEvidence(currentDocument.RootElement);
            baseline = ReadEvidence(document.RootElement);
            if (!SameScope(live.Scope, baseline.Scope) || !MatchesOptions(live.Scope, options))
                throw new InvalidDataException("Scope mismatch.");
            var complete = live.Complete && baseline.Complete && !live.UnknownFields && !baseline.UnknownFields;
            state = complete ? CoverageState.Complete : CoverageState.Partial;
            if (!live.Complete || !baseline.Complete)
                warnings.Add("Current inventory or baseline coverage is incomplete. Added/missing assessments were suppressed; shared observed fields may still be compared.");
            if (live.UnknownFields || baseline.UnknownFields)
                warnings.Add("Some allowlisted fields are absent, invalid or redacted. Unknown fields were excluded, and comparison coverage is partial.");
            foreach (var expected in baseline.Resources.Values.OrderBy(resource => resource.Key, StringComparer.Ordinal))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!live.Resources.TryGetValue(expected.Key, out var actual))
                {
                    if (live.Complete && baseline.Complete) changes.Add(new(expected.Account, expected.Id, expected.Region, expected.Type, "Missing", []));
                    continue;
                }
                comparedResources++;
                var fields = new List<string>();
                if (expected.Region.Length > 0 && actual.Region.Length > 0)
                { comparedFields++; if (expected.Region != actual.Region) fields.Add("region"); }
                else unknownFields++;
                if (expected.State is not null && actual.State is not null)
                { comparedFields++; if (expected.State != actual.State) fields.Add("state"); }
                else unknownFields++;
                if (fields.Count > 0) changes.Add(new(actual.Account, actual.Id, actual.Region, actual.Type, "Changed", fields.ToArray()));
            }
            if (live.Complete && baseline.Complete)
                foreach (var actual in live.Resources.Values.Where(resource => !baseline.Resources.ContainsKey(resource.Key)).OrderBy(resource => resource.Key, StringComparer.Ordinal))
                    changes.Add(new(actual.Account, actual.Id, actual.Region, actual.Type, "Added", []));
            foreach (var change in changes.OrderBy(change => change.Account, StringComparer.Ordinal).ThenBy(change => change.Type, StringComparer.Ordinal).ThenBy(change => change.ResourceId, StringComparer.Ordinal).ThenBy(change => change.ChangeType, StringComparer.Ordinal))
            {
                var description = change.ChangeType switch
                {
                    "Missing" => "Baseline resource was not observed in the current selected inventory",
                    "Added" => "Current resource was not observed in the supplied inventory baseline",
                    _ => "Shared observed inventory fields differ from the baseline"
                };
                findings.Add(new(FindingSeverity.Info, "GCP_BASELINE_" + change.ChangeType.ToUpperInvariant(), description,
                    change.ResourceId + (change.Fields.Length > 0 ? "; fields: " + string.Join(", ", change.Fields) : ""),
                    "Review the observation, selected scopes and Cloud Asset freshness before updating an approved baseline. This does not prove unauthorized change or current compliance."));
            }
            warnings.Add("Drift compares selected Cloud Asset inventory identities, location and state only. Display names, labels, timestamps, raw metadata and unsupported configuration are excluded. No before/after values or baseline file paths are emitted.");
            warnings.Add("Added/missing observations depend on inventory visibility and freshness, even when all selected reads completed. They are not deletion, authorization or compliance claims; no Terraform plan or remediation was run.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or JsonException or ArgumentException or InvalidOperationException or NotSupportedException or OperationCanceledException)
        {
            state = CoverageState.Failed;
            live = null;
            baseline = null;
            changes.Clear();
            findings.Clear();
            warnings.Add("The baseline/current inventory format, scope or resource identities could not be validated. Regenerate matching normalized inventory exports with --full and the same project, region, resource and profile filters. No baseline comparison was performed; file contents, paths and error text are omitted.");
        }
        return Result();

        AnalysisReport Result()
        {
            var ordered = changes.OrderBy(change => change.Account, StringComparer.Ordinal).ThenBy(change => change.Type, StringComparer.Ordinal).ThenBy(change => change.ResourceId, StringComparer.Ordinal).ThenBy(change => change.ChangeType, StringComparer.Ordinal).ToArray();
            return new("cloud.gcp.drift", now, findings, new
            {
                provider = "gcp", operation = "drift",
                resources = live?.Resources.Values.OrderBy(resource => resource.Key, StringComparer.Ordinal).Select(resource => resource.Export()).ToArray() ?? [],
                scope = live is null ? null : new { schemaVersion = 1, accounts = live.Scope.Accounts, region = live.Scope.Region, resource = live.Scope.Resource, profile = live.Scope.Profile, assetTypes = live.Scope.Types },
                coverage = new CloudCoverage(state, now, live?.Resources.Count ?? 0, live?.Scope.Accounts.Length, state == CoverageState.Complete ? live?.Scope.Accounts.Length ?? 0 : 0, warnings.ToArray()),
                drift = new
                {
                    baselineObservedAtUtc = baseline?.ObservedAtUtc, currentObservedAtUtc = live?.ObservedAtUtc,
                    comparedResources, comparedFields, unknownFields,
                    addedResources = ordered.Count(change => change.ChangeType == "Added"), missingResources = ordered.Count(change => change.ChangeType == "Missing"), changedResources = ordered.Count(change => change.ChangeType == "Changed"),
                    absenceAssessmentAvailable = live is not null && baseline is not null && live.Complete && baseline.Complete,
                    changes = ordered, comparedFieldAllowlist = new[] { "region", "state" }
                },
                source = "normalized-inventory-baseline-comparison"
            }, warnings) { OperationSucceeded = state == CoverageState.Complete };
        }
    }

    private static Evidence ReadEvidence(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object || Text(root, "kind") is not ("cloud/gcp/inventory" or "cloud.gcp.inventory")) throw new InvalidDataException("Only normalized GCP inventory is supported.");
        var observed = Property(root, "collectedAtUtc");
        if (observed.ValueKind != JsonValueKind.String || !observed.TryGetDateTimeOffset(out var observedAt) || observedAt > DateTimeOffset.UtcNow.AddMinutes(5)) throw new InvalidDataException("Invalid observation timestamp.");
        var data = Property(root, "data");
        if (Text(data, "provider") != "gcp" || Text(data, "operation") != "inventory") throw new InvalidDataException("Invalid provider operation.");
        var scope = ReadScope(Property(data, "scope"));
        var coverage = Property(data, "coverage");
        var coverageState = Property(coverage, "state");
        var knownState = coverageState.ValueKind == JsonValueKind.String ? coverageState.GetString() : null;
        if (knownState is null || !Enum.TryParse<CoverageState>(knownState, true, out var status) || !Enum.IsDefined(status) || !string.Equals(knownState, status.ToString(), StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Coverage must be explicit.");
        var expected = Integer(coverage, "expectedScopes");
        var completed = Integer(coverage, "completedScopes");
        if (expected != scope.Accounts.Length || completed < 0 || completed > expected) throw new InvalidDataException("Invalid scope coverage.");
        var success = Property(root, "operationSucceeded");
        if (success.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new InvalidDataException("Execution result is required.");
        var complete = status == CoverageState.Complete && success.ValueKind == JsonValueKind.True && completed == expected;
        var resources = Property(data, "resources");
        if (resources.ValueKind != JsonValueKind.Array || resources.GetArrayLength() > 10000 || Integer(coverage, "enumeratedResources") != resources.GetArrayLength()) throw new InvalidDataException("Invalid resources.");
        var result = new Dictionary<string, Resource>(StringComparer.Ordinal);
        var unknown = false;
        foreach (var resource in resources.EnumerateArray())
        {
            var account = Text(resource, "account"); var type = Text(resource, "type"); var id = Text(resource, "id");
            if (Text(resource, "provider") != "gcp" || !scope.Accounts.Contains(account, StringComparer.Ordinal) || !scope.Types.Contains(type, StringComparer.Ordinal) || !ValidId(id, type, account)) throw new InvalidDataException("Unverified resource identity.");
            var region = Text(resource, "region");
            if (region.Length > 64 || region.Length > 0 && !Regex.IsMatch(region, "\\A[A-Za-z0-9-]+\\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100))) throw new InvalidDataException("Invalid resource location.");
            if (scope.Region is not null && region != scope.Region && !region.StartsWith(scope.Region + "-", StringComparison.Ordinal)) throw new InvalidDataException("Resource outside region filter.");
            if (scope.Resource is not null && !string.Equals(scope.Resource, id, StringComparison.Ordinal)) throw new InvalidDataException("Resource outside selected filter.");
            var state = Text(Property(resource, "properties"), "state");
            if (state.Length == 0 || state.Length > 80 || !Regex.IsMatch(state, "\\A[A-Z][A-Z0-9_]*\\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100))) { state = null; unknown = true; }
            if (region.Length == 0) unknown = true;
            var entry = new Resource(account, id, region, type, state);
            if (!result.TryAdd(entry.Key, entry)) throw new InvalidDataException("Ambiguous duplicate resource identity.");
        }
        return new(scope, result, complete, unknown, observedAt);
    }

    private static Scope ReadScope(JsonElement value)
    {
        if (Integer(value, "schemaVersion") != 1) throw new InvalidDataException("Unsupported scope schema.");
        var accounts = Strings(Property(value, "accounts"), 20).Order(StringComparer.Ordinal).ToArray();
        if (accounts.Length == 0 || accounts.Distinct(StringComparer.Ordinal).Count() != accounts.Length || accounts.Any(account => !Regex.IsMatch(account, "\\A[a-z][a-z0-9-]{4,28}[a-z0-9]\\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)))) throw new InvalidDataException("Invalid project scope.");
        var types = Strings(Property(value, "assetTypes"), AssetTypes.Length).Order(StringComparer.Ordinal).ToArray();
        if (!types.SequenceEqual(AssetTypes.Order(StringComparer.Ordinal), StringComparer.Ordinal)) throw new InvalidDataException("Unsupported asset universe.");
        var region = NullableText(value, "region"); var resource = CanonicalResource(NullableText(value, "resource")); var profile = NullableText(value, "profile");
        if (region is not null && !Regex.IsMatch(region, "\\A[a-z]+(?:-[a-z0-9]+)+[0-9]\\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100))) throw new InvalidDataException("Invalid selected region.");
        if (profile is not null) throw new InvalidDataException("GCP profile selectors are unsupported.");
        if (resource is not null && !accounts.Any(account => AssetTypes.Any(type => ValidId(resource, type, account)))) throw new InvalidDataException("Invalid resource scope.");
        return new(accounts, region, resource, profile, types);
    }

    private static bool SameScope(Scope left, Scope right) => left.Accounts.SequenceEqual(right.Accounts, StringComparer.Ordinal) && left.Region == right.Region && left.Resource == right.Resource && left.Profile == right.Profile && left.Types.SequenceEqual(right.Types, StringComparer.Ordinal);
    private static bool MatchesOptions(Scope scope, IReadOnlyDictionary<string, string> options)
    {
        var raw = Option("projects") ?? Option("project") ?? "";
        var projects = raw.Split([',', ';'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        return projects.SequenceEqual(scope.Accounts, StringComparer.Ordinal) && Option("region") == scope.Region && CanonicalResource(Option("resource")) == scope.Resource && Option("profile") == scope.Profile;
        string? Option(string name) => options.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value) ? value.Trim() : null;
    }

    private static string? CanonicalResource(string? resource) => resource is not null && resource.StartsWith("projects/", StringComparison.Ordinal) ? "//compute.googleapis.com/" + resource : resource;

    private static bool ValidId(string id, string type, string account)
    {
        if (id.Length > 1024 || id.Length == 0 || id.Any(char.IsControl)) return false;
        var suffix = type switch
        {
            "compute.googleapis.com/Instance" => "zones/[a-z0-9-]+/instances/[a-z0-9-]+",
            "compute.googleapis.com/Disk" => "(?:zones|regions)/[a-z0-9-]+/disks/[a-z0-9-]+",
            "compute.googleapis.com/Address" => "(?:regions/[a-z0-9-]+|global)/addresses/[a-z0-9-]+",
            "compute.googleapis.com/Network" => "global/networks/[a-z0-9-]+",
            "compute.googleapis.com/Firewall" => "global/firewalls/[a-z0-9-]+",
            "container.googleapis.com/Cluster" => "(?:locations|zones)/[a-z0-9-]+/clusters/[a-z0-9-]+",
            "sqladmin.googleapis.com/Instance" => "instances/[a-z0-9-]+",
            "run.googleapis.com/Service" => "locations/[a-z0-9-]+/services/[a-z0-9-]+",
            "storage.googleapis.com/Bucket" => "",
            _ => null
        };
        if (suffix is null) return false;
        if (type == "storage.googleapis.com/Bucket") return Regex.IsMatch(id, "\\A//storage\\.googleapis\\.com/[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]\\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
        var service = type[..type.IndexOf('/')];
        return Regex.IsMatch(id, "\\A//" + Regex.Escape(service) + "/projects/" + Regex.Escape(account) + "/" + suffix + "\\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    }
    private static string[] Strings(JsonElement array, int max)
    {
        if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() > max) throw new InvalidDataException("Invalid scope list.");
        return array.EnumerateArray().Select(value => value.ValueKind == JsonValueKind.String ? value.GetString()! : throw new InvalidDataException("Invalid scope item.")).ToArray();
    }
    private static JsonElement Property(JsonElement value, string name)
    {
        if (value.ValueKind != JsonValueKind.Object) return default;
        var matches = value.EnumerateObject().Where(property => string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (matches.Length > 1) throw new InvalidDataException("Ambiguous duplicate field.");
        return matches.Length == 1 ? matches[0].Value : default;
    }
    private static string Text(JsonElement value, string name) => Property(value, name) is { ValueKind: JsonValueKind.String } text ? text.GetString()! : "";
    private static string? NullableText(JsonElement value, string name)
    {
        var field = Property(value, name);
        if (field.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined) return null;
        if (field.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(field.GetString())) throw new InvalidDataException("Scope filters must be explicit.");
        return field.GetString();
    }
    private static int Integer(JsonElement value, string name) => Property(value, name) is { ValueKind: JsonValueKind.Number } number && number.TryGetInt32(out var result) ? result : -1;
}
