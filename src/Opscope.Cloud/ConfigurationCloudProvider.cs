namespace Opscope.Cloud;

/// <summary>Routes the additional, explicitly scoped configuration reads without changing established inventory or metrics.</summary>
internal sealed class ConfigurationCloudProvider(ICloudProvider provider, ICloudCommandRunner? runner) : ICloudProvider
{
    public string Name => provider.Name;

    public Task<AnalysisReport> CollectAsync(string operation, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default) =>
        (Name, operation.ToLowerInvariant()) switch
        {
            ("cloudflare", "posture") => new CloudflarePostureProvider().CollectAsync("posture", options, cancellationToken),
            ("alibaba", "posture") => new AlibabaSecurityProvider(runner).CollectAsync("posture", options, cancellationToken),
            ("scaleway", "networks") => new ScalewayNetworkProvider().CollectAsync("networks", options, cancellationToken),
            ("ibm", "networks") => new IbmVpcProvider().CollectAsync("networks", options, cancellationToken),
            _ => provider.CollectAsync(operation, options, cancellationToken)
        };
}
