using System.Collections.Concurrent;
using System.Globalization;
using Opscope.Cloud;

namespace Opscope.Api;

/// <summary>Only configured action aliases cross the local HTTP boundary; remote scope identifiers stay in closures.</summary>
internal sealed class CloudWorkspace(IReadOnlyDictionary<string, Func<CancellationToken, Task<AnalysisReport>>>? configured)
{
    private readonly ConcurrentDictionary<string, Observation> observations = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, CachedReport> cache = new(StringComparer.Ordinal);
    private readonly string[] keys = configured?.Keys.Where(IsSafeAction).Order(StringComparer.Ordinal).ToArray() ?? [];

    internal object Catalog() => new
    {
        version = 2,
        providers = CloudProviderRegistry.Descriptors.Select(descriptor => new
        {
            id = descriptor.ProviderId,
            descriptor.DisplayName,
            descriptor.Category,
            descriptor.Version,
            scopes = keys.Select(Parse).Where(action => action.Provider == descriptor.ProviderId)
                .Select(action => action.Scope).Distinct(StringComparer.Ordinal)
                .Select(alias => new { alias, label = alias }).ToArray(),
            operations = descriptor.Capabilities.Select(capability => new
            {
                name = capability.Operation.ToString().ToLowerInvariant(),
                availability = keys.Any(key => Parse(key) is var action && action.Provider == descriptor.ProviderId &&
                    action.Operation == capability.Operation.ToString().ToLowerInvariant()) ? "configured" : "not-configured",
                supported = true,
                readOnly = true,
                capability.IsExperimental,
                capability.ResourceTypes,
                capability.RequiredPermissions,
                minimumFreshnessSeconds = capability.MinimumFreshness?.TotalSeconds,
                limitations = capability.IsExperimental
                    ? new[] { "Experimental read-only adapter. Coverage and permissions are evaluated per query; remote metrics are not sampled at the host interval." }
                    : Array.Empty<string>()
            }).ToArray()
        }).ToArray(),
        actions = keys.Select(key =>
        {
            var action = Parse(key);
            return new { actionKey = key, providerId = action.Provider, scopeAlias = action.Scope, operation = action.Operation, availability = "configured", supported = true, readOnly = true };
        }).ToArray()
    };

    internal object Coverage() => new
    {
        schemaVersion = 1,
        source = "configured-read-only-actions",
        actions = keys.Select(key => observations.TryGetValue(key, out var result)
            ? result : new Observation(key, "not-requested", null, false)).ToArray()
    };

    internal bool IsConfigured(string key) => Array.BinarySearch(keys, key, StringComparer.Ordinal) >= 0;

    internal CachedReport? Cached(string key) => cache.TryGetValue(key, out var cached) && cached.ExpiresAtUtc > DateTimeOffset.UtcNow ? cached : null;

    internal void Cache(string key, string redactedJson, int statusCode)
    {
        // Only final redacted HTTP representations are cached: at most 16 MiB of UTF-8 payloads, plus runtime overhead.
        if (System.Text.Encoding.UTF8.GetByteCount(redactedJson) > 512 * 1024) return;
        if (cache.Count >= 32 && !cache.ContainsKey(key))
        {
            var oldest = cache.OrderBy(pair => pair.Value.ExpiresAtUtc).FirstOrDefault();
            if (oldest.Key is not null) cache.TryRemove(oldest.Key, out _);
        }
        var now = DateTimeOffset.UtcNow;
        var seconds = statusCode != 200 ? 15 : key.EndsWith("/metrics", StringComparison.Ordinal) ? 60 : 30;
        cache[key] = new(redactedJson, statusCode, now, now.AddSeconds(seconds));
    }

    internal void Record(string key, AnalysisReport report)
    {
        var status = !report.OperationSucceeded ? "failed" : report.Warnings is { Count: > 0 } ? "partial" : "succeeded";
        var data = System.Text.Json.JsonSerializer.SerializeToElement(report.Data, ReportSecurity.JsonOptions);
        if (data.ValueKind == System.Text.Json.JsonValueKind.Object && data.TryGetProperty("coverage", out var coverage) &&
            coverage.ValueKind == System.Text.Json.JsonValueKind.Object && coverage.TryGetProperty("state", out var value) && value.ValueKind == System.Text.Json.JsonValueKind.String)
        {
            var declared = value.GetString()!.Replace("_", "", StringComparison.Ordinal).Replace("-", "", StringComparison.Ordinal).ToLowerInvariant();
            status = declared switch
            {
                "complete" => "succeeded", "partial" => "partial", "notconfigured" => "not-configured",
                "permissiondenied" => "permission-denied", "ratelimited" => "rate-limited",
                "unsupported" => "unsupported", "failed" => "failed", "nodata" => "no-data",
                "unavailable" => "unavailable", "timedout" => "timed-out", _ => status
            };
        }
        observations[key] = new Observation(key, status, report.CollectedAtUtc, report.OperationSucceeded);
    }

    internal void RecordFailure(string key, string status) => observations[key] = new Observation(key, status, DateTimeOffset.UtcNow, false);

    internal static string? ProviderId(string scope)
    {
        if (CloudProviderRegistry.IsKnownProvider(scope)) return scope;
        var marker = scope.LastIndexOf("-scope-", StringComparison.Ordinal);
        if (marker < 1 || !int.TryParse(scope.AsSpan(marker + 7), NumberStyles.None, CultureInfo.InvariantCulture, out var index) || index < 1) return null;
        var provider = scope[..marker];
        return CloudProviderRegistry.IsKnownProvider(provider) ? provider : null;
    }

    private static bool IsSafeAction(string key)
    {
        var parts = key.Split('/');
        return parts.Length == 2 && ProviderId(parts[0]) is { } provider && CloudProviderRegistry.SupportsOperation(provider, parts[1]);
    }

    private static (string Provider, string Scope, string Operation) Parse(string key)
    {
        var parts = key.Split('/');
        return (ProviderId(parts[0])!, parts[0], parts[1]);
    }

    private sealed record Observation(string ActionKey, string Status, DateTimeOffset? LastObservedAtUtc, bool OperationSucceeded);
    internal sealed record CachedReport(string Json, int StatusCode, DateTimeOffset CachedAtUtc, DateTimeOffset ExpiresAtUtc);
}
