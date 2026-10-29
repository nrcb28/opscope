namespace Opscope.Cloud;

/// <summary>Routes explicitly scoped infrastructure and configuration reads independently of metrics.</summary>
internal sealed class ConfigurationCloudProvider(ICloudProvider provider, ICloudCommandRunner? runner) : ICloudProvider
{
    public string Name => provider.Name;

    public Task<AnalysisReport> CollectAsync(string operation, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default) =>
        (Name, operation.ToLowerInvariant()) switch
        {
            ("digitalocean", "inventory" or "posture") => new DigitalOceanProjectProvider().CollectAsync(operation.ToLowerInvariant(), options, cancellationToken),
            ("cloudflare", "posture") => new CloudflarePostureProvider().CollectAsync("posture", options, cancellationToken),
            ("alibaba", "posture") => new AlibabaSecurityProvider(runner).CollectAsync("posture", options, cancellationToken),
            ("scaleway", "networks") => new ScalewayNetworkProvider().CollectAsync("networks", options, cancellationToken),
            ("ibm", "networks") => new IbmVpcProvider().CollectAsync("networks", options, cancellationToken),
            _ => provider.CollectAsync(operation, options, cancellationToken)
        };
}
