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
