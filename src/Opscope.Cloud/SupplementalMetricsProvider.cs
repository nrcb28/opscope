namespace Opscope.Cloud;

/// <summary>Adds explicitly scoped metric readers without changing established inventory transports.</summary>
internal sealed class SupplementalMetricsProvider(ICloudProvider provider, ICloudCommandRunner? runner) : ICloudProvider
{
    public string Name => provider.Name;

    public Task<AnalysisReport> CollectAsync(string operation, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default) =>
        string.Equals(operation, "metrics", StringComparison.OrdinalIgnoreCase)
            ? SupplementalCloudMetricsA.Supports(Name)
                ? SupplementalCloudMetricsA.CollectAsync(Name, options, runner, cancellationToken)
                : SupplementalCloudMetricsB.CollectAsync(Name, options, runner, cancellationToken)
            : provider.CollectAsync(operation, options, cancellationToken);
}
