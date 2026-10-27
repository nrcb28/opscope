using System.Text.RegularExpressions;

namespace Opscope.Cloud;

/// <summary>Opt-in node reference matching against an explicitly scoped live infrastructure inventory.</summary>
public static class KubernetesInfrastructureCollection
{
    public static IReadOnlyDictionary<string, string>? Prepare(IReadOnlyDictionary<string, string> options)
    {
        if (!options.TryGetValue("infrastructure-provider", out var provider)) return null;
        if (provider is not ("gcp" or "azure")) throw new ArgumentException("--infrastructure-provider accepts gcp or azure only.");
        if (provider == "gcp" && Get("profile") is not null)
            throw new ArgumentException("Google Cloud node matching uses the existing gcloud configuration; --profile cannot select a Google Cloud identity.");
        if (!options.TryGetValue("kubernetes-nodes", out var nodes) || nodes is not ("true" or "1" or "yes"))
            throw new ArgumentException("Infrastructure correlation requires explicit --kubernetes-nodes access.");
        var (singular, plural) = provider == "gcp" ? ("project", "projects") : ("subscription", "subscriptions");
        var scope = Get(provider + "-" + plural) ?? Get(plural) ?? Get(singular);
        var values = scope?.Split([',', ';'], StringSplitOptions.TrimEntries) ?? [];
        if (values.Length is < 1 or > 20 || values.Distinct(provider == "gcp" ? StringComparer.Ordinal : StringComparer.OrdinalIgnoreCase).Count() != values.Length ||
            values.Any(value => provider == "gcp"
                ? !Regex.IsMatch(value, @"\A[a-z][a-z0-9-]{4,28}[a-z0-9]\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100))
                : !Guid.TryParseExact(value, "D", out _)))
            throw new ArgumentException($"Infrastructure correlation requires one to twenty distinct explicit --{singular} or --{plural} scopes.");
        // No credentials, arbitrary endpoints, cluster options or resource filters enter the infrastructure query.
        var prepared = new Dictionary<string, string>(StringComparer.Ordinal) { ["provider"] = provider, [plural] = string.Join(',', values) };
        foreach (var key in new[] { "region" })
            if (Get(key) is { } value) prepared[key] = value;
        return prepared;

        string? Get(string key) => options.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;
    }

    public static Task<AnalysisReport> CollectAsync(ICloudProvider cluster, string operation,
        IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default) =>
        CollectAsync(cluster, operation, options, CloudProviderRegistry.Create, cancellationToken);

    internal static async Task<AnalysisReport> CollectAsync(ICloudProvider cluster, string operation,
        IReadOnlyDictionary<string, string> options, Func<string, ICloudCommandRunner?, ICloudProvider> create,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(cluster);
        if (cluster.Name != "kubernetes") throw new ArgumentException("Node reference collection requires the Kubernetes adapter.");
        var infrastructure = Prepare(options);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(60));
        var report = await cluster.CollectAsync(operation, options, deadline.Token);
        if (infrastructure is null || operation is not ("inventory" or "health") || !report.OperationSucceeded) return report;
        try
        {
            var inventory = await create(infrastructure["provider"], null).CollectAsync("inventory", infrastructure, deadline.Token);
            return KubernetesInfrastructureLinker.Apply(report, [inventory]);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or InvalidOperationException or ArgumentException or System.Text.Json.JsonException or HttpRequestException or OperationCanceledException or System.ComponentModel.Win32Exception)
        {
            return report with { Warnings = (report.Warnings ?? []).Append("The explicitly requested infrastructure inventory was unavailable. Node references remain unverified; provider error text is omitted.").ToArray() };
        }
    }
}
