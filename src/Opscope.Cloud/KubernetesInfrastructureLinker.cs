using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Opscope.Cloud;

/// <summary>Matches explicit node provider references to current, scoped infrastructure inventory.</summary>
/// <remarks>A node reference never establishes a cluster's control-plane, account ownership or application health.</remarks>
public static class KubernetesInfrastructureLinker
{
    private const int MaximumNodes = 1000;
    private const int MaximumResources = 10000;
    private const int MaximumReports = 20;
    private const int MaximumJsonBytes = 8 * 1024 * 1024;
    private const string Limitation = "A verified node reference only matches the node's configured infrastructure reference to an exact observed inventory resource. Cluster/control-plane identity, cluster account ownership and application health remain unverified.";
    private static readonly TimeSpan RegexBudget = TimeSpan.FromMilliseconds(100);

    /// <summary>Produces bounded positive matches only; missing or ineligible evidence does not establish absence.</summary>
    public static KubernetesInfrastructureCorrelation Correlate(AnalysisReport clusterReport, IReadOnlyList<AnalysisReport> infrastructureReports)
    {
        ArgumentNullException.ThrowIfNull(clusterReport);
        ArgumentNullException.ThrowIfNull(infrastructureReports);
        var now = DateTimeOffset.UtcNow;
        using var clusterDocument = Document(clusterReport.Data);
        if (clusterDocument is null) return Unverified(0, false, "Cluster evidence was outside the supported bounded report shape.");
        var cluster = clusterDocument.RootElement;
        var clusterResources = Property(cluster, "resources");
        var nodes = clusterResources.ValueKind == JsonValueKind.Array && clusterResources.GetArrayLength() <= MaximumNodes
            ? clusterResources.EnumerateArray().Where(resource => Text(resource, "provider") == "kubernetes" && Text(resource, "type") == "kubernetes.node").ToArray() : [];
        var includesNodes = Property(Property(cluster, "cluster"), "includesNodes").ValueKind == JsonValueKind.True;
        var fallback = Unverified(nodes.Length, includesNodes);
        var operation = Text(cluster, "operation");
        if (!clusterReport.OperationSucceeded || !Fresh(clusterReport.CollectedAtUtc, now) || Text(cluster, "provider") != "kubernetes" ||
            operation is not ("inventory" or "health") || !Kind(clusterReport.Kind, "kubernetes", operation, clusterSource: true) || !includesNodes ||
            !Complete(Property(cluster, "coverage")) || clusterResources.ValueKind != JsonValueKind.Array || clusterResources.GetArrayLength() > MaximumNodes ||
            nodes.Length == 0 || infrastructureReports.Count is 0 or > MaximumReports)
            return fallback;
        var contexts = Strings(Property(Property(cluster, "scope"), "accounts"), 1);
        if (contexts is not { Length: 1 } || !KubernetesProvider.IsValidContext(contexts[0]) ||
            nodes.Any(node => Text(node, "account") != contexts[0] || Text(node, "region") != "cluster" || !ValidNodeId(Text(node, "id"))) ||
            nodes.Select(node => Text(node, "id")).Distinct(StringComparer.Ordinal).Count() != nodes.Length)
            return Unverified(nodes.Length, true, "Cluster node identities did not agree with the selected context scope.");

        var inventory = new Dictionary<string, ResourceIdentity?>(StringComparer.Ordinal);
        var remaining = MaximumResources;
        var bounded = false;
        foreach (var report in infrastructureReports)
        {
            if (report is null || !report.OperationSucceeded || !Fresh(report.CollectedAtUtc, now)) continue;
            using var document = Document(report.Data);
            if (document is null) continue;
            var data = document.RootElement;
            var provider = Text(data, "provider");
            if (provider is not ("gcp" or "azure") || Text(data, "operation") != "inventory" || !Kind(report.Kind, provider, "inventory")) continue;
            var scope = Property(data, "scope");
            var accounts = Strings(Property(scope, provider == "gcp" ? "accounts" : "subscriptions"), provider == "gcp" ? 20 : 50);
            if (accounts is null || accounts.Length == 0 || accounts.Distinct(provider == "gcp" ? StringComparer.Ordinal : StringComparer.OrdinalIgnoreCase).Count() != accounts.Length) continue;
            if (provider == "gcp" && (!Complete(Property(data, "coverage")) || accounts.Any(account => !ValidProject(account)))) continue;
            if (provider == "azure" && (accounts.Any(account => !Guid.TryParseExact(account, "D", out _)) || IncompleteWarnings(report.Warnings))) continue;
            var coverage = Property(data, "coverage");
            if (provider == "azure" && coverage.ValueKind != JsonValueKind.Undefined && !Complete(coverage)) continue;
            var resources = Property(data, "resources");
            if (resources.ValueKind != JsonValueKind.Array || resources.GetArrayLength() > MaximumResources) continue;
            if (resources.GetArrayLength() > remaining) { bounded = true; break; }
            remaining -= resources.GetArrayLength();
            foreach (var resource in resources.EnumerateArray())
            {
                var identity = InfrastructureResource(resource, provider, accounts);
                if (identity is null) continue;
                // Duplicated canonical identities remain ambiguous, even if their names agree.
                if (!inventory.TryAdd(identity.Key, identity)) inventory[identity.Key] = null;
            }
        }
        var links = new List<KubernetesInfrastructureLink>();
        var references = nodes.Select(node => Reference(Text(Property(node, "properties"), "infrastructureResourceId"))).ToArray();
        var referenceCounts = references.Where(reference => reference is not null).GroupBy(reference => reference!.Key, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.Count(), StringComparer.Ordinal);
        for (var index = 0; index < nodes.Length; index++)
        {
            var node = nodes[index];
            var reference = references[index];
            if (reference is null || referenceCounts[reference.Key] != 1 || !inventory.TryGetValue(reference.Key, out var resource) || resource is null ||
                reference.Provider == "gcp" && reference.Region != resource.Region) continue;
            links.Add(new(Text(node, "id"), resource.Provider, resource.Account, resource.Region, resource.Id, "verified_node_reference"));
        }
        var matched = links.Count;
        var warnings = new List<string> { Limitation };
        if (matched != nodes.Length) warnings.Add("Some observed nodes have no exact eligible inventory match. Missing references, unsupported provider formats, redacted identities, scope mismatches and incomplete reads do not establish resource absence.");
        if (bounded) warnings.Add("The aggregate 10,000-resource correlation budget was reached; remaining inventory reports were not considered.");
        return new(matched == 0 ? "unverified" : matched == nodes.Length ? "verified_node_references" : "partial_node_references",
            matched > 0, false, nodes.Length, matched, nodes.Length - matched, links.OrderBy(link => link.NodeId, StringComparer.Ordinal).ToArray(), warnings);
    }

    /// <summary>Adds correlation evidence without changing cluster identity or collection success.</summary>
    public static AnalysisReport Apply(AnalysisReport clusterReport, IReadOnlyList<AnalysisReport> infrastructureReports)
    {
        var correlation = Correlate(clusterReport, infrastructureReports);
        using var document = Document(clusterReport.Data);
        if (document is null || document.RootElement.ValueKind != JsonValueKind.Object) return clusterReport;
        var data = JsonNode.Parse(document.RootElement.GetRawText())!.AsObject();
        data["infrastructureCorrelation"] = JsonSerializer.SerializeToNode(correlation, ReportSecurity.JsonOptions);
        return clusterReport with { Data = data };
    }

    internal static KubernetesInfrastructureCorrelation Unverified(int nodes, bool requested, string? warning = null) =>
        new("unverified", false, false, nodes, 0, nodes, [], [Limitation, warning ?? (requested ?
            "No exact eligible infrastructure inventory match has been established for the observed nodes." :
            "Cluster-scoped node reads were not requested; infrastructure references remain unverified.")]);

    internal static bool IsSupportedReference(string value) => Reference(value) is not null;

    private static ResourceIdentity? Reference(string value)
    {
        if (value.Length is < 1 or > 2048 || value.Any(char.IsControl) || value.IndexOfAny(['?', '#', '%', '\\']) >= 0) return null;
        var gce = Regex.Match(value, @"\Agce://(?<account>[a-z][a-z0-9-]{4,28}[a-z0-9])/(?<zone>[a-z]+(?:-[a-z0-9]+)+[0-9]-[a-z])/(?<name>[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)\z", RegexOptions.CultureInvariant, RegexBudget);
        if (gce.Success)
        {
            var account = gce.Groups["account"].Value;
            var zone = gce.Groups["zone"].Value;
            var id = $"//compute.googleapis.com/projects/{account}/zones/{zone}/instances/{gce.Groups["name"].Value}";
            return new("gcp", account, zone, id);
        }
        if (!value.StartsWith("azure://", StringComparison.Ordinal)) return null;
        var azure = AzureId(value[8..]);
        return azure is null ? null : new("azure", azure.Value.Account, "", azure.Value.Id);
    }

    private static ResourceIdentity? InfrastructureResource(JsonElement resource, string provider, string[] accounts)
    {
        if (Text(resource, "provider") != provider) return null;
        var id = Text(resource, "id"); var account = Text(resource, "account"); var region = Text(resource, "region");
        if (provider == "gcp")
        {
            if (Text(resource, "type") != "compute.googleapis.com/Instance" || !accounts.Contains(account, StringComparer.Ordinal) || !ValidProject(account)) return null;
            const string prefix = "//compute.googleapis.com/projects/";
            if (!id.StartsWith(prefix, StringComparison.Ordinal)) return null;
            var parts = id[prefix.Length..].Split('/');
            if (parts.Length != 5 || parts[0] != account || parts[1] != "zones" || parts[3] != "instances") return null;
            var reference = Reference($"gce://{account}/{parts[2]}/{parts[4]}");
            return reference is not null && reference.Id == id && region == reference.Region ? reference : null;
        }
        if (!Text(resource, "type").Equals("Microsoft.Compute/virtualMachines", StringComparison.OrdinalIgnoreCase) || !accounts.Contains(account, StringComparer.OrdinalIgnoreCase) ||
            !Guid.TryParseExact(account, "D", out _) || !Regex.IsMatch(region, @"\A[a-z0-9]{1,64}\z", RegexOptions.CultureInvariant, RegexBudget)) return null;
        var azure = AzureId(id);
        return azure is not null && azure.Value.Account.Equals(account, StringComparison.OrdinalIgnoreCase) ? new("azure", account.ToLowerInvariant(), region, azure.Value.Id) : null;
    }

    private static (string Account, string Id)? AzureId(string id)
    {
        if (id.Length > 2048 || id.Any(char.IsControl) || id.IndexOfAny(['?', '#', '%', '\\']) >= 0) return null;
        var match = Regex.Match(id, @"\A/subscriptions/(?<account>[0-9a-fA-F-]{36})/resourceGroups/(?<group>[A-Za-z0-9_.()-]{1,90})/providers/Microsoft\.Compute/virtualMachines/[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexBudget);
        return match.Success && !match.Groups["group"].Value.EndsWith('.') && Guid.TryParseExact(match.Groups["account"].Value, "D", out _) ?
            (match.Groups["account"].Value.ToLowerInvariant(), id.ToLowerInvariant()) : null;
    }

    private static bool ValidProject(string value) => Regex.IsMatch(value, @"\A[a-z][a-z0-9-]{4,28}[a-z0-9]\z", RegexOptions.CultureInvariant, RegexBudget);
    private static bool ValidNodeId(string value) => value.StartsWith("cluster/nodes/", StringComparison.Ordinal) && KubernetesCommandRunner.ValidObjectName(value[14..]);
    private static bool Fresh(DateTimeOffset value, DateTimeOffset now) => value >= now.AddMinutes(-5) && value <= now.AddMinutes(2);
    private static bool Kind(string kind, string provider, string operation, bool clusterSource = false) =>
        kind == $"cloud/{provider}/{operation}" || kind == $"cloud.{provider}.{operation}" || clusterSource && kind == $"cluster/{provider}/{operation}";
    private static bool Complete(JsonElement coverage)
    {
        if (!Text(coverage, "state").Equals("complete", StringComparison.OrdinalIgnoreCase)) return false;
        var expected = Property(coverage, "expectedScopes"); var completed = Property(coverage, "completedScopes");
        return expected.ValueKind == JsonValueKind.Number && completed.ValueKind == JsonValueKind.Number && expected.TryGetInt32(out var count) &&
            completed.TryGetInt32(out var actual) && count is > 0 and <= 50 && actual == count;
    }
    private static bool IncompleteWarnings(IReadOnlyList<string>? warnings) => warnings is { Count: > 128 } || warnings?.Any(warning =>
        warning is null || warning.Length > 2048 || new[] { "incomplete", "truncat", "limit", "continuation", "unavailable", "could not", "unsupported", "inconsistent", "failed" }
            .Any(marker => warning.Contains(marker, StringComparison.OrdinalIgnoreCase))) == true;

    private static string[]? Strings(JsonElement array, int maximum)
    {
        if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() > maximum) return null;
        var result = new List<string>();
        foreach (var value in array.EnumerateArray())
        {
            if (value.ValueKind != JsonValueKind.String || value.GetString() is not { Length: > 0 and <= 2048 } text) return null;
            result.Add(text);
        }
        return result.ToArray();
    }

    private static JsonElement Property(JsonElement value, string key)
    {
        if (value.ValueKind != JsonValueKind.Object) return default;
        var found = default(JsonElement); var count = 0; var fields = 0;
        foreach (var property in value.EnumerateObject())
        {
            if (++fields > 64) return default;
            if (property.Name.Equals(key, StringComparison.OrdinalIgnoreCase)) { found = property.Value; count++; }
        }
        return count == 1 ? found : default;
    }
    private static string Text(JsonElement value, string key) => Property(value, key) is { ValueKind: JsonValueKind.String } text ? text.GetString() ?? "" : "";

    private static JsonDocument? Document(object? value)
    {
        try
        {
            using var stream = new BoundedStream();
            JsonSerializer.Serialize(stream, value, ReportSecurity.JsonOptions);
            return JsonDocument.Parse(stream.ToArray(), new JsonDocumentOptions { MaxDepth = 48 });
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or NotSupportedException or IOException) { return null; }
    }

    private sealed record ResourceIdentity(string Provider, string Account, string Region, string Id)
    {
        public string Key => Provider + "/" + Account + "/" + Id;
    }
    private sealed class BoundedStream : MemoryStream
    {
        public override void Write(byte[] buffer, int offset, int count) { if (Length + count > MaximumJsonBytes) throw new IOException("Correlation report exceeded its byte bound."); base.Write(buffer, offset, count); }
        public override void Write(ReadOnlySpan<byte> buffer) { if (Length + buffer.Length > MaximumJsonBytes) throw new IOException("Correlation report exceeded its byte bound."); base.Write(buffer); }
    }
}

public sealed record KubernetesInfrastructureLink(string NodeId, string Provider, string Account, string Region, string ResourceId, string State);
public sealed record KubernetesInfrastructureCorrelation(string State, bool NodeReferencesVerified, bool ClusterIdentityVerified,
    int ObservedNodes, int MatchedNodes, int UnmatchedNodes, IReadOnlyList<KubernetesInfrastructureLink> Links, IReadOnlyList<string> Warnings);
