using System.Collections;
using System.Reflection;
using System.Text.Json;
using Opscope;
using Opscope.Api;

internal static class Program
{
    private static int assertions;

    private static async Task<int> Main()
    {
        try
        {
            TestClosedBoundedKeys();
            TestCacheBudgetsAndLifetimes();
            TestMonotonicExpiry();
            TestCapturedCacheMetadata();
            TestScopeAdmission();
            assertions += await HttpChecks.RunAsync();
            Console.WriteLine($"PASS: {assertions} cloud reliability assertions.");
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error);
            return 1;
        }
    }

    private static void TestClosedBoundedKeys()
    {
        var configured = Enumerable.Range(1, 600).Select(index => $"gcp-scope-{index}/inventory").ToDictionary(key => key, _ => Action());
        configured["unknown-scope-1/inventory"] = Action();
        configured["gcp-scope-0/inventory"] = Action();
        configured["gcp-scope-1/delete"] = Action();
        configured["gcp-scope-1/inventory/extra"] = Action();
        using var workspace = new CloudWorkspace(configured);
        var catalog = JsonSerializer.SerializeToElement(workspace.Catalog());
        var keys = catalog.GetProperty("actions").EnumerateArray().Select(item => item.GetProperty("actionKey").GetString()!).ToArray();
        Equal(512, keys.Length, "configuration is capped at 512 known action keys");
        Check(keys.SequenceEqual(keys.Order(StringComparer.Ordinal)), "configured action keys have deterministic ordering");
        Check(keys.All(workspace.IsConfigured), "every catalog action is admitted by the closed allowlist");
        Check(!workspace.IsConfigured("unknown-scope-1/inventory"), "unknown provider is excluded");
        Check(!workspace.IsConfigured("gcp-scope-0/inventory"), "zero scope alias is excluded");
        Check(!workspace.IsConfigured("gcp-scope-1/delete"), "unsupported action is excluded");
        Check(!workspace.IsConfigured("gcp-scope-1/inventory/extra"), "extra path segment is excluded");
        var before = JsonSerializer.Serialize(workspace.Coverage());
        for (var index = 0; index < 2000; index++)
        {
            var unknown = $"gcp-scope-{10000 + index}/inventory";
            workspace.Cache(unknown, "{}", 200);
            workspace.Record(unknown, Report());
            workspace.RecordFailure(unknown, "failed");
            workspace.RecordProviderQuota(unknown);
            Check(!workspace.TryEnterRead(unknown, CancellationToken.None).Allowed, "unconfigured reads are rejected");
        }
        Equal(before, JsonSerializer.Serialize(workspace.Coverage()), "unknown keys do not change known observations or readiness");
        Equal(0, StoredCount(workspace, "cache"), "unknown keys allocate no cache entries");
        Equal(0, StoredCount(workspace, "observations"), "unknown keys allocate no observations");
        Equal(keys.Select(key => key.Split('/')[0]).Distinct().Count(), StoredCount(workspace, "scopes"), "unknown keys allocate no scope quota state");
    }

    private static void TestCacheBudgetsAndLifetimes()
    {
        var clock = new ManualClock();
        var configured = Enumerable.Range(1, 40).Select(index => $"gcp-scope-{index}/inventory").ToDictionary(key => key, _ => Action());
        configured["gcp-scope-1/metrics"] = Action();
        configured["gcp-scope-1/health"] = Action();
        using var workspace = new CloudWorkspace(configured, clock);
        const string ordinary = "gcp-scope-1/inventory";
        const string metrics = "gcp-scope-1/metrics";
        const string failure = "gcp-scope-1/health";
        workspace.Cache(ordinary, new string('a', 512 * 1024), 200);
        Equal(512 * 1024, workspace.Cached(ordinary)!.Json.Length, "a payload exactly at 512 KiB is retained");
        workspace.Cache(ordinary, new string('a', 512 * 1024 + 1), 200);
        Check(workspace.Cached(ordinary) is null, "oversized replacement removes metadata from the earlier report");
        Equal("none", workspace.CacheDetails(ordinary).State, "uncached replacement cannot inherit previous report cache metadata");
        workspace.Cache(ordinary, "{}", 200);
        workspace.Cache(metrics, new string('\u00e9', 262145), 200);
        Check(workspace.Cached(metrics) is null, "cache byte budget counts UTF-8 bytes rather than characters");
        workspace.Cache(metrics, "{\"metric\":true}", 200);
        workspace.Cache(failure, "{\"error\":true}", 429);
        Equal(30, workspace.CacheDetails(ordinary).RemainingSeconds, "ordinary successful report has a 30 second lifetime");
        Equal(60, workspace.CacheDetails(metrics).RemainingSeconds, "metrics report has a 60 second lifetime");
        Equal(15, workspace.CacheDetails(failure).RemainingSeconds, "error report has a 15 second lifetime");
        clock.Advance(TimeSpan.FromSeconds(14.25));
        Equal(1, workspace.CacheDetails(failure).RemainingSeconds, "remaining lifetime rounds up for retry presentation");
        Equal(14, workspace.CacheDetails(failure).AgeSeconds, "cache age rounds down");
        clock.Advance(TimeSpan.FromSeconds(.75));
        Check(workspace.Cached(failure) is null, "error report expires exactly after 15 seconds");
        Equal("expired", workspace.CacheDetails(failure).State, "expired report metadata remains distinguishable");
        clock.Advance(TimeSpan.FromSeconds(15));
        Check(workspace.Cached(ordinary) is null, "ordinary report expires exactly after 30 seconds");
        Check(workspace.Cached(metrics) is not null, "metrics remain cached after ordinary report expires");
        clock.Advance(TimeSpan.FromSeconds(30));
        Check(workspace.Cached(metrics) is null, "metrics expire exactly after 60 seconds");
        workspace.Cache(metrics, new string('a', 512 * 1024 + 1), 200);
        var uncached = workspace.CacheDetails(metrics);
        Check(uncached.State == "none" && uncached.CachedAtUtc is null && uncached.ExpiresAtUtc is null && uncached.AgeSeconds is null, "oversized replacement of an expired report clears stale cache timings");

        using var bounded = new CloudWorkspace(configured, clock);
        for (var index = 1; index <= 33; index++)
        {
            bounded.Cache($"gcp-scope-{index}/inventory", "{}", 200);
            clock.Advance(TimeSpan.FromMilliseconds(1));
        }
        Equal(32, StoredCount(bounded, "cache"), "cache retains at most 32 reports");
        Check(bounded.Cached("gcp-scope-1/inventory") is null, "oldest cache entry is evicted under capacity pressure");
        Check(bounded.Cached("gcp-scope-33/inventory") is not null, "newest report is retained under capacity pressure");
    }

    private static void TestMonotonicExpiry()
    {
        var clock = new ManualClock();
        using var workspace = new CloudWorkspace(Actions("gcp-scope-1/inventory", "gcp-scope-1/health"), clock);
        const string key = "gcp-scope-1/inventory";
        workspace.Cache(key, "{}", 429);
        workspace.RecordProviderQuota(key);
        var metadata = workspace.CacheDetails(key);
        clock.Advance(TimeSpan.FromSeconds(5));
        clock.JumpUtc(TimeSpan.FromDays(365));
        for (var index = 0; index < 10; index++) Check(workspace.Cached(key) is not null, "cache hit remains available before expiry");
        Equal(5, workspace.CacheDetails(key).AgeSeconds, "wall clock jump does not alter monotonic cache age");
        Equal(10, workspace.CacheDetails(key).RemainingSeconds, "forward UTC jump does not expire cache");
        Equal(metadata.CachedAtUtc, workspace.CacheDetails(key).CachedAtUtc, "hits preserve original cached timestamp");
        Equal(metadata.ExpiresAtUtc, workspace.CacheDetails(key).ExpiresAtUtc, "hits preserve original display expiry");
        Equal(10, workspace.Readiness("gcp-scope-1/health").RetryAfterSeconds, "hits do not renew scope provider quota");
        clock.JumpUtc(TimeSpan.FromDays(-730));
        clock.Advance(TimeSpan.FromSeconds(10));
        Check(workspace.Cached(key) is null, "backward UTC jump does not extend cache lifetime");
        Equal(0, workspace.CacheDetails(key).RemainingSeconds, "expired cache never reports negative remaining time");
        Check(workspace.Readiness("gcp-scope-1/health").Allowed, "provider quota expires after 15 monotonic seconds");
    }

    private static void TestScopeAdmission()
    {
        var clock = new ManualClock();
        using var workspace = new CloudWorkspace(Actions("gcp-scope-1/inventory", "gcp-scope-1/health", "gcp-scope-2/inventory", "aws-scope-1/health"), clock);
        Check(workspace.TryEnterRead("gcp-scope-1/inventory", CancellationToken.None).Allowed, "first configured read starts immediately");
        Equal("workspace-busy", workspace.TryEnterRead("gcp-scope-2/inventory", CancellationToken.None).RetryReason, "second alias cannot start while the workspace has an active cloud read");
        Equal("workspace-busy", workspace.TryEnterRead("aws-scope-1/health", CancellationToken.None).RetryReason, "workspace concurrency limit spans providers");
        Equal("scope-cooldown", workspace.TryEnterRead("gcp-scope-1/health", CancellationToken.None).RetryReason, "two second scope interval spans operations");
        using (var canceled = new CancellationTokenSource())
        {
            canceled.Cancel();
            var threw = false;
            try { workspace.TryEnterRead("gcp-scope-2/inventory", canceled.Token); }
            catch (OperationCanceledException) { threw = true; }
            Check(threw, "canceled admission returns cancellation without waiting for the active cloud read");
        }
        workspace.ExitRead();
        Check(workspace.TryEnterRead("gcp-scope-2/inventory", CancellationToken.None).Allowed, "different alias can start immediately once active read ends");
        workspace.ExitRead();
        clock.Advance(TimeSpan.FromSeconds(1.25));
        Equal(1, workspace.Readiness("gcp-scope-1/health").RetryAfterSeconds, "minimum read interval counts down independently of cached data");
        clock.Advance(TimeSpan.FromSeconds(.75));
        Check(workspace.TryEnterRead("gcp-scope-1/health", CancellationToken.None).Allowed, "same alias can read again exactly after two seconds");
        workspace.ExitRead();
        workspace.RecordProviderQuota("gcp-scope-1/health");
        Equal("provider-quota", workspace.Readiness("gcp-scope-1/inventory").RetryReason, "provider quota applies across operations within the configured alias");
        Equal(15, workspace.Readiness("gcp-scope-1/inventory").RetryAfterSeconds, "provider quota uses fifteen second local fallback");
        Check(workspace.TryEnterRead("gcp-scope-2/inventory", CancellationToken.None).Allowed, "provider quota does not block another alias of the same provider");
        workspace.ExitRead();
        Check(workspace.TryEnterRead("aws-scope-1/health", CancellationToken.None).Allowed, "provider quota does not block another provider");
        workspace.ExitRead();
        clock.Advance(TimeSpan.FromSeconds(14.5));
        Equal(1, workspace.Readiness("gcp-scope-1/inventory").RetryAfterSeconds, "quota retry counts down to one");
        clock.Advance(TimeSpan.FromSeconds(.5));
        Check(workspace.TryEnterRead("gcp-scope-1/inventory", CancellationToken.None).Allowed, "provider quota expires at the precise monotonic boundary");
        workspace.ExitRead();
    }

    private static void TestCapturedCacheMetadata()
    {
        const string key = "gcp-scope-1/inventory";
        var clock = new ManualClock();
        using var workspace = new CloudWorkspace(Actions(key), clock);
        workspace.Cache(key, "{\"observation\":1}", 200);
        var captured = workspace.Cached(key)!;
        clock.Advance(TimeSpan.FromSeconds(30));
        workspace.Cache(key, "{\"observation\":2}", 200);
        var original = workspace.CacheDetails(captured);
        var replacement = workspace.CacheDetails(key);
        Equal(captured.CachedAtUtc, original.CachedAtUtc, "captured response retains the matching cache entry timestamp after replacement");
        Equal(captured.ExpiresAtUtc, original.ExpiresAtUtc, "captured response retains its own expiry after replacement");
        Equal(30, original.AgeSeconds, "captured response age follows its original monotonic timestamp");
        Equal("expired", original.State, "an entry expiring while its response is being prepared remains visibly expired");
        Equal(0, replacement.AgeSeconds, "the replacement has its own independent age");
        Check(original.CachedAtUtc != replacement.CachedAtUtc, "old response metadata is never taken from a newer cache entry");
    }

    private static Dictionary<string, Func<CancellationToken, Task<AnalysisReport>>> Actions(params string[] keys) => keys.ToDictionary(key => key, _ => Action());
    private static Func<CancellationToken, Task<AnalysisReport>> Action() => _ => Task.FromResult(Report());
    private static AnalysisReport Report() => new("cloud/gcp/inventory", DateTimeOffset.UtcNow, [], new { resources = Array.Empty<object>() });
    private static int StoredCount(CloudWorkspace workspace, string field)
    {
        var entries = workspace.GetType().GetField(field, BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(workspace)!;
        return (int)entries.GetType().GetProperty(nameof(ICollection.Count))!.GetValue(entries)!;
    }
    private static void Check(bool condition, string message) { assertions++; if (!condition) throw new InvalidOperationException(message); }
    private static void Equal<T>(T expected, T actual, string message) => Check(EqualityComparer<T>.Default.Equals(expected, actual), $"{message}: expected {expected}, got {actual}");
}

internal sealed class ManualClock : TimeProvider
{
    private long timestamp;
    private DateTimeOffset utc = new(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    public override long GetTimestamp() => Interlocked.Read(ref timestamp);
    public override DateTimeOffset GetUtcNow() => utc;
    public void Advance(TimeSpan elapsed) { Interlocked.Add(ref timestamp, elapsed.Ticks); utc = utc.Add(elapsed); }
    public void JumpUtc(TimeSpan elapsed) => utc = utc.Add(elapsed);
}
