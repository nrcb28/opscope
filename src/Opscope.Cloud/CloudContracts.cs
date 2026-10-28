using System.Text.Json;

namespace Opscope.Cloud;

public interface ICloudCommandRunner
{
    Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken);
}

public interface ICloudProvider
{
    string Name { get; }
    Task<AnalysisReport> CollectAsync(string operation, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default);
}

public sealed record CloudResource(string Provider, string Account, string Region, string Id, string Type, string Name, object? Properties = null);

// EN: Capabilities describe implemented reads, not credentials or guarantees about provider coverage.
// ES: Las capacidades describen lecturas implementadas, no credenciales ni garantías de cobertura.
public enum CloudOperation { Inventory, Health, Posture, Metrics, Cost, Patches, Vm, Instance, Bundle, Drift, Arc, Metadata, Scc, Services, Networks }
[System.Text.Json.Serialization.JsonConverter(typeof(System.Text.Json.Serialization.JsonStringEnumConverter<CoverageState>))]
public enum CoverageState { Complete, Partial, NotConfigured, PermissionDenied, RateLimited, Failed, Unsupported }

public sealed record CloudScope(string Alias, string ProviderId, string DisplayLabel);
public sealed record CloudCapability(CloudOperation Operation, IReadOnlyList<string> ResourceTypes,
    IReadOnlyList<string> RequiredPermissions, bool IsExperimental, TimeSpan? MinimumFreshness = null);
public sealed record CloudAdapterDescriptor(string ProviderId, string DisplayName, string Category, string Version,
    IReadOnlyList<CloudCapability> Capabilities);
public sealed record CloudCoverage(CoverageState State, DateTimeOffset ObservedAtUtc, int EnumeratedResources,
    int? ExpectedScopes, int CompletedScopes, IReadOnlyList<string> Warnings);
public sealed record CloudObservation(string ProviderId, string ScopeAlias, string ResourceType,
    string RedactedResourceId, string State, DateTimeOffset ObservedAtUtc, CloudCoverage Coverage);
