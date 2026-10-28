using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;

namespace Opscope.Api;

/// <summary>Aggregate counters only. This contract must never contain host, user, process or network identities.</summary>
public sealed record HostMetricSample(
    int SchemaVersion,
    long Sequence,
    DateTimeOffset SampledAtUtc,
    long ElapsedMilliseconds,
    double SampleIntervalSeconds,
    double? CpuPercent,
    double? MemoryPercent,
    string Status,
    string Source,
    HostMetricCoverage Coverage,
    bool ClockAdjusted = false);

public sealed record HostMetricCoverage(string Cpu, string Memory);
public sealed record HostMetricsHistory(int SchemaVersion, string Source, DateTimeOffset ServerTimeUtc,
    double SampleIntervalSeconds, int Capacity, long DroppedSamples, IReadOnlyList<HostMetricSample> Points);
public sealed record HostMetricsCapabilities(int SchemaVersion, string Source, double SampleIntervalSeconds,
    int Capacity, IReadOnlyList<string> Metrics, string Persistence, IReadOnlyList<string> SupportedWindows,
    HostMetricCoverage Coverage, string Status);

/// <summary>Cumulative host counters. CPU counters must use the same unit, and include idle in total.</summary>
public sealed record HostMetricsReading(ulong? CpuTotal, ulong? CpuIdle, double? MemoryPercent,
    string? CpuStatus = null, string? MemoryStatus = null);

public interface IHostMetricsReader
{
    HostMetricsReading Read();
}

/// <summary>A fixed-capacity, identity-free session history, independent of persisted evidence snapshots.</summary>
public sealed class HostMetricsBuffer
{
    private readonly object gate = new();
    private readonly Queue<HostMetricSample> points = new();
    private long dropped;
    public int Capacity { get; }

    public HostMetricsBuffer(int capacity = 720)
    {
        if (capacity is < 2 or > 720) throw new ArgumentOutOfRangeException(nameof(capacity));
        Capacity = capacity;
    }

    public bool Append(HostMetricSample sample)
    {
        ArgumentNullException.ThrowIfNull(sample);
        if (sample.SchemaVersion != 1 || sample.Source != "local-lightweight" || sample.Sequence < 1 ||
            sample.ElapsedMilliseconds < 0 || !double.IsFinite(sample.SampleIntervalSeconds) || sample.SampleIntervalSeconds < 1 ||
            !ValidPercent(sample.CpuPercent) || !ValidPercent(sample.MemoryPercent)) return false;
        lock (gate)
        {
            if (points.LastOrDefault() is { } previous)
            {
                if (sample.Sequence <= previous.Sequence || sample.ElapsedMilliseconds <= previous.ElapsedMilliseconds) return false;
                // UTC can move backwards after clock synchronization. Retention and causality use the monotonic clock.
                if (sample.SampledAtUtc <= previous.SampledAtUtc) sample = sample with { ClockAdjusted = true };
            }
            if (points.Count == Capacity) { points.Dequeue(); dropped++; }
            points.Enqueue(sample);
            return true;
        }
    }

    public HostMetricsHistory History(TimeSpan window, double sampleIntervalSeconds = 5, int limit = 720, long afterSequence = 0,
        DateTimeOffset? now = null)
    {
        if (window < TimeSpan.FromMinutes(1) || window > TimeSpan.FromHours(1)) throw new ArgumentOutOfRangeException(nameof(window));
        if (limit is < 1 or > 720 || afterSequence < 0) throw new ArgumentOutOfRangeException(nameof(limit));
        var instant = now ?? DateTimeOffset.UtcNow;
        lock (gate)
        {
            var earliestElapsed = (points.LastOrDefault()?.ElapsedMilliseconds ?? 0) - window.TotalMilliseconds;
            return new(1, "local-lightweight", instant, sampleIntervalSeconds, Capacity, dropped,
                points.Where(point => point.ElapsedMilliseconds >= earliestElapsed && point.Sequence > afterSequence).TakeLast(limit).ToArray());
        }
    }

    public HostMetricSample? Latest { get { lock (gate) return points.LastOrDefault(); } }
    private static bool ValidPercent(double? value) => value is null || (double.IsFinite(value.Value) && value >= 0 && value <= 100);
}

/// <summary>One lightweight timer per server, with no process, service or evidence enumeration.</summary>
public sealed class HostMetricsSampler : IAsyncDisposable
{
    private readonly IHostMetricsReader reader;
    private readonly TimeSpan interval;
    private readonly Stopwatch clock = Stopwatch.StartNew();
    private readonly CancellationTokenSource shutdown = new();
    private readonly object gate = new();
    private Task? loop;
    private HostMetricsReading? previous;
    private long sequence;
    private bool disposed;
    public HostMetricsBuffer Buffer { get; }
    public HostMetricSample? Latest => Buffer.Latest;
    public HostMetricsCapabilities Capabilities => new(1, "local-lightweight", interval.TotalSeconds,
        Buffer.Capacity, ["cpuPercent", "memoryPercent"], "session-memory-only", ["5m", "15m", "30m", "1h"],
        Latest?.Coverage ?? new("unavailable", "unavailable"), Latest?.Status ?? "initializing");

    public HostMetricsSampler(TimeSpan? interval = null, int capacity = 720, IHostMetricsReader? reader = null)
    {
        this.interval = interval ?? TimeSpan.FromSeconds(5);
        if (this.interval < TimeSpan.FromSeconds(5) || this.interval > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(interval), "Lightweight sampling is bounded to 5–60 seconds.");
        this.reader = reader ?? new SystemHostMetricsReader();
        Buffer = new(capacity);
    }

    public void Start()
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (loop is not null) return;
            SampleLocked();
            loop = RunAsync(shutdown.Token);
        }
    }

    public HostMetricsHistory History(TimeSpan window, int limit = 720, long afterSequence = 0) =>
        Buffer.History(window, interval.TotalSeconds, limit, afterSequence);

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(interval);
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken))
                lock (gate) SampleLocked();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
    }

    private void SampleLocked()
    {
        HostMetricsReading current;
        try { current = reader.Read(); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException or FormatException or OverflowException)
        { current = new(null, null, null); }
        var cpu = CpuDelta(previous, current);
        var memory = current.MemoryPercent is { } value && double.IsFinite(value) && value is >= 0 and <= 100 ? value : (double?)null;
        var cpuCoverage = current.CpuTotal is null || current.CpuIdle is null ? current.CpuStatus ?? "unavailable" : previous?.CpuTotal is null ? "warmingUp" : cpu is null ? "unavailable" : "observed";
        var memoryCoverage = memory is null ? current.MemoryStatus ?? "unavailable" : current.MemoryStatus == "estimated" ? "estimated" : "observed";
        Buffer.Append(new(1, ++sequence, DateTimeOffset.UtcNow, clock.ElapsedMilliseconds,
            interval.TotalSeconds, cpu, memory, cpu is not null && memory is not null ? "observed" : "partial",
            "local-lightweight", new(cpuCoverage, memoryCoverage)));
        previous = current;
    }

    public static double? CpuDelta(HostMetricsReading? previous, HostMetricsReading current)
    {
        if (previous?.CpuTotal is not { } oldTotal || previous.CpuIdle is not { } oldIdle ||
            current.CpuTotal is not { } total || current.CpuIdle is not { } idle || total <= oldTotal || idle < oldIdle) return null;
        var totalDelta = total - oldTotal;
        var idleDelta = idle - oldIdle;
        return idleDelta > totalDelta ? null : Math.Round(100d * (totalDelta - idleDelta) / totalDelta, 2);
    }

    public async ValueTask DisposeAsync()
    {
        Task? running;
        lock (gate)
        {
            if (disposed) return;
            disposed = true;
            shutdown.Cancel();
            running = loop;
        }
        if (running is not null) await running;
        shutdown.Dispose();
    }
}

/// <summary>Reads operating-system aggregate counters; unsupported platforms report missing values.</summary>
public sealed class SystemHostMetricsReader : IHostMetricsReader
{
    public HostMetricsReading Read()
    {
        if (OperatingSystem.IsLinux())
        {
            ulong? total = null, idle = null;
            double? memory = null;
            try
            {
                var line = File.ReadLines("/proc/stat").FirstOrDefault();
                if (line?.StartsWith("cpu ", StringComparison.Ordinal) == true)
                {
                    var counters = line.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1).Take(8)
                        .Select(value => ulong.Parse(value, CultureInfo.InvariantCulture)).ToArray();
                    if (counters.Length >= 4) { total = counters.Aggregate(0UL, (sum, value) => checked(sum + value)); idle = counters[3] + (counters.Length > 4 ? counters[4] : 0); }
                }
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or FormatException or OverflowException) { }
            try
            {
                var memoryValues = File.ReadLines("/proc/meminfo").Where(line => line.StartsWith("MemTotal:", StringComparison.Ordinal) || line.StartsWith("MemAvailable:", StringComparison.Ordinal))
                    .Select(line => line.Split([' ', ':'], StringSplitOptions.RemoveEmptyEntries)).ToDictionary(parts => parts[0], parts => double.Parse(parts[1], CultureInfo.InvariantCulture));
                if (memoryValues.TryGetValue("MemTotal", out var bytes) && bytes > 0 && memoryValues.TryGetValue("MemAvailable", out var available) && available >= 0 && available <= bytes)
                    memory = Math.Round(100d * (bytes - available) / bytes, 2);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or FormatException or OverflowException) { }
            return new(total, idle, memory);
        }
        if (OperatingSystem.IsWindows())
        {
            ulong? total = null, idle = null;
            double? memory = null;
            if (GetSystemTimes(out var idleCounter, out var kernelCounter, out var userCounter))
            { total = kernelCounter.Value + userCounter.Value; idle = idleCounter.Value; }
            var status = new MemoryStatus { Length = (uint)Marshal.SizeOf<MemoryStatus>() };
            if (GlobalMemoryStatusEx(ref status) && status.TotalPhysical > 0 && status.AvailablePhysical <= status.TotalPhysical)
                memory = Math.Round(100d * (status.TotalPhysical - status.AvailablePhysical) / status.TotalPhysical, 2);
            return new(total, idle, memory);
        }
        if (OperatingSystem.IsMacOS()) return new DarwinHostMetricsReader().Read();
        return new(null, null, null, "notSupported", "notSupported");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint Low;
        public uint High;
        public readonly ulong Value => ((ulong)High << 32) | Low;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatus
    {
        public uint Length;
        public uint Load;
        public ulong TotalPhysical;
        public ulong AvailablePhysical;
        public ulong TotalPageFile;
        public ulong AvailablePageFile;
        public ulong TotalVirtual;
        public ulong AvailableVirtual;
        public ulong AvailableExtendedVirtual;
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemTimes(out FileTime idle, out FileTime kernel, out FileTime user);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatus memoryStatus);
}
