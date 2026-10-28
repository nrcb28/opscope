using System.Collections.Concurrent;
using System.Globalization;
using Opscope.Cloud;

namespace Opscope.Api;

/// <summary>Only configured aliases cross HTTP; cloud scheduling and memory-only cache are independent of host collection.</summary>
internal sealed class CloudWorkspace : IDisposable
{
    internal const int ProviderQuotaCooldownSeconds = 15;
    private const int MinimumReadIntervalSeconds = 2;
    private readonly ConcurrentDictionary<string, Observation> observations = new(StringComparer.Ordinal);
    private readonly Dictionary<string, CachedReport> cache = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ScopeReadState> scopes;
    private readonly SemaphoreSlim cloudReads = new(1, 1);
    private readonly object gate = new();
    private readonly TimeProvider clock;
    private readonly string[] keys;

    internal CloudWorkspace(IReadOnlyDictionary<string, Func<CancellationToken, Task<AnalysisReport>>>? configured, TimeProvider? clock = null)
    {
        this.clock = clock ?? TimeProvider.System;
        keys = configured?.Keys.Where(IsSafeAction).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).Take(512).ToArray() ?? [];
        scopes = keys.Select(key => Parse(key).Scope).Distinct(StringComparer.Ordinal).ToDictionary(scope => scope, _ => new ScopeReadState(), StringComparer.Ordinal);
    }

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

    internal object Coverage()
    {
        lock (gate)
            return new
            {
                schemaVersion = 1,
                source = "configured-read-only-actions",
                actions = keys.Select(key =>
                {
                    var observation = observations.TryGetValue(key, out var observed) ? observed : new Observation(key, "not-requested", null, false);
                    var metadata = CacheMetadataCore(key);
                    var readiness = ReadinessCore(key);
                    return new
                    {
                        observation.ActionKey, observation.Status, observation.LastObservedAtUtc, observation.OperationSucceeded,
                        cacheState = metadata.State, metadata.CachedAtUtc, metadata.ExpiresAtUtc,
                        cacheAgeSeconds = metadata.AgeSeconds, cacheRemainingSeconds = metadata.RemainingSeconds,
                        readiness.RetryAfterSeconds, readiness.RetryReason,
                        canRequestRead = readiness.Allowed && metadata.State != "fresh"
                    };
                }).ToArray()
            };
    }

    internal bool IsConfigured(string key) => Array.BinarySearch(keys, key, StringComparer.Ordinal) >= 0;

    internal CachedReport? Cached(string key)
    {
        lock (gate) return cache.TryGetValue(key, out var cached) && Remaining(cached.StartedTimestamp, cached.TtlSeconds) > 0 ? cached : null;
    }

    internal CacheMetadata CacheDetails(string key) { lock (gate) return CacheMetadataCore(key); }
    internal CacheMetadata CacheDetails(CachedReport cached) => DescribeCache(cached);
    private CacheMetadata CacheMetadataCore(string key)
    {
        if (!cache.TryGetValue(key, out var cached)) return new("none", null, null, null, 0);
        return DescribeCache(cached);
    }
    private CacheMetadata DescribeCache(CachedReport cached)
    {
        var remaining = Remaining(cached.StartedTimestamp, cached.TtlSeconds);
        var age = Math.Max(0, (int)Math.Min(int.MaxValue, Math.Floor(clock.GetElapsedTime(cached.StartedTimestamp).TotalSeconds)));
        return new(remaining > 0 ? "fresh" : "expired", cached.CachedAtUtc, cached.ExpiresAtUtc, age, remaining);
    }

    internal void Cache(string key, string redactedJson, int statusCode)
    {
        if (!IsConfigured(key)) return;
        if (System.Text.Encoding.UTF8.GetByteCount(redactedJson) > 512 * 1024)
        {
            lock (gate) cache.Remove(key);
            return;
        }
        lock (gate)
        {
            // EN: At most 32 x 512 KiB of redacted UTF-8 payloads; cache hits never renew age or quota.
            // ES: Máximo 32 x 512 KiB redactados; consultar caché nunca renueva antigüedad ni cuota.
            if (cache.Count >= 32 && !cache.ContainsKey(key))
            {
                var oldest = cache.OrderBy(pair => pair.Value.CachedAtUtc).First();
                cache.Remove(oldest.Key);
            }
            var now = clock.GetUtcNow();
            var seconds = statusCode != 200 ? 15 : key.EndsWith("/metrics", StringComparison.Ordinal) ? 60 : 30;
            cache[key] = new(redactedJson, statusCode, now, now.AddSeconds(seconds), clock.GetTimestamp(), seconds);
        }
    }

    internal ReadAdmission TryEnterRead(string key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            var readiness = ReadinessCore(key);
            if (!readiness.Allowed) return readiness;
            if (!cloudReads.Wait(0, cancellationToken)) return new(false, 1, "workspace-busy");
            scopes[Parse(key).Scope].LastStartedTimestamp = clock.GetTimestamp();
            return new(true, 0, null);
        }
    }

    internal ReadAdmission Readiness(string key, bool completingRead = false) { lock (gate) return ReadinessCore(key, completingRead); }
    private ReadAdmission ReadinessCore(string key, bool completingRead = false)
    {
        if (!IsConfigured(key)) return new(false, 0, null);
        var scope = scopes[Parse(key).Scope];
        var quota = scope.QuotaStartedTimestamp is { } started ? Remaining(started, ProviderQuotaCooldownSeconds) : 0;
        if (quota > 0) return new(false, quota, "provider-quota");
        var interval = scope.LastStartedTimestamp is { } previous ? Remaining(previous, MinimumReadIntervalSeconds) : 0;
        if (interval > 0) return new(false, interval, "scope-cooldown");
        return !completingRead && cloudReads.CurrentCount == 0 ? new(false, 1, "workspace-busy") : new(true, 0, null);
    }

    internal void RecordProviderQuota(string key)
    {
        if (!IsConfigured(key)) return;
        lock (gate) scopes[Parse(key).Scope].QuotaStartedTimestamp = clock.GetTimestamp();
    }

    internal void ExitRead() => cloudReads.Release();
    private int Remaining(long started, int durationSeconds) => Math.Clamp((int)Math.Ceiling(durationSeconds - clock.GetElapsedTime(started).TotalSeconds), 0, durationSeconds);

    internal void Record(string key, AnalysisReport report)
    {
        if (!IsConfigured(key)) return;
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

    internal void RecordFailure(string key, string status) { if (IsConfigured(key)) observations[key] = new Observation(key, status, clock.GetUtcNow(), false); }

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

    public void Dispose() => cloudReads.Dispose();
    private sealed class ScopeReadState { internal long? LastStartedTimestamp; internal long? QuotaStartedTimestamp; }
    private sealed record Observation(string ActionKey, string Status, DateTimeOffset? LastObservedAtUtc, bool OperationSucceeded);
    internal sealed record ReadAdmission(bool Allowed, int RetryAfterSeconds, string? RetryReason);
    internal sealed record CacheMetadata(string State, DateTimeOffset? CachedAtUtc, DateTimeOffset? ExpiresAtUtc, int? AgeSeconds, int RemainingSeconds);
    internal sealed record CachedReport(string Json, int StatusCode, DateTimeOffset CachedAtUtc, DateTimeOffset ExpiresAtUtc, long StartedTimestamp, int TtlSeconds);
}
