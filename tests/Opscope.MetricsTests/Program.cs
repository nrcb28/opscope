using System.Text.Json;
using Opscope.Api;

var assertions = 0;
var time = new DateTimeOffset(2026, 10, 25, 12, 0, 0, TimeSpan.Zero);
HostMetricSample Sample(long sequence, long? elapsed = null, DateTimeOffset? utc = null, double? cpu = 50) =>
    new(1, sequence, utc ?? time.AddSeconds(sequence * 5), elapsed ?? sequence * 5000, 5, cpu, 60, "observed", "local-lightweight", new("observed", "observed"));
void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); assertions++; }
void Reject(Action action, string message) { try { action(); throw new Exception(message); } catch (ArgumentOutOfRangeException) { assertions++; } }

Check(HostMetricsSampler.CpuDelta(new(100, 20, null), new(200, 50, null)) == 70, "CPU is calculated from host-wide cumulative counter deltas");
Check(HostMetricsSampler.CpuDelta(null, new(200, 50, null)) is null, "Initial CPU sample stays unknown until a second observation");
Check(HostMetricsSampler.CpuDelta(new(200, 50, null), new(100, 20, null)) is null, "CPU counter reset is unknown, not a utilization spike");
Check(HostMetricsSampler.CpuDelta(new(100, 20, null), new(100, 20, null)) is null, "CPU zero elapsed counters remain unknown");
Check(HostMetricsSampler.CpuDelta(new(100, 20, null), new(200, 121, null)) is null, "Invalid idle delta never becomes negative utilization");
Check(HostMetricsSampler.CpuDelta(new(100, 20, null), new(200, 120, null)) == 0, "Actual idle observation preserves zero utilization");
var buffer = new HostMetricsBuffer();
for (var sequence = 1; sequence <= 800; sequence++) Check(buffer.Append(Sample(sequence)), "Monotonic observation accepted");
var history = buffer.History(TimeSpan.FromHours(1), now: time.AddSeconds(4000));
Check(history.Points.Count == 720 && history.Points[0].Sequence == 81 && history.Points[^1].Sequence == 800, "Session memory remains bounded at 720 actual observations");
Check(history.DroppedSamples == 80, "Buffer retention is explicitly counted");
Check(!buffer.Append(Sample(800)), "Duplicate sequence is rejected");
Check(!buffer.Append(Sample(799)), "Out-of-order sequence is rejected");
Check(!buffer.Append(Sample(801, elapsed: 3)), "Monotonic elapsed regression is rejected");
Check(!buffer.Append(Sample(801, cpu: double.NaN)), "Non-finite CPU is rejected");
Check(!buffer.Append(Sample(801, cpu: -1)), "Negative CPU is rejected");
Check(!buffer.Append(Sample(801, cpu: 101)), "CPU over 100 is rejected");
Check(buffer.Append(Sample(801, cpu: null)), "Missing CPU is retained as a gap");
Check(buffer.Latest!.CpuPercent is null, "Missing CPU remains null, never zero");
Check(buffer.Append(Sample(802, utc: time.AddDays(-1))), "UTC clock correction does not discard a causally newer observation");
Check(buffer.Latest!.ClockAdjusted, "UTC clock correction is visible to graph renderers");
Check(buffer.History(TimeSpan.FromMinutes(5), now: time.AddDays(-1)).Points.Count == 61, "Window retention follows monotonic time after UTC clock correction");
Check(buffer.History(TimeSpan.FromHours(1), limit: 2, afterSequence: 800).Points.Select(point => point.Sequence).SequenceEqual([801L, 802L]), "Resynchronization returns bounded observations after a known sequence");
Reject(() => buffer.History(TimeSpan.Zero), "Unbounded short windows must fail");
Reject(() => buffer.History(TimeSpan.FromHours(2)), "Overlong windows must fail");
Reject(() => buffer.History(TimeSpan.FromHours(1), limit: 721), "Overlarge query limits must fail");
Reject(() => buffer.History(TimeSpan.FromHours(1), afterSequence: -1), "Negative cursors must fail");
Reject(() => new HostMetricsBuffer(721), "Overlarge buffers must fail");
Reject(() => new HostMetricsSampler(TimeSpan.FromSeconds(1)), "Unbenchmarked high-frequency sampling must fail");
var reader = new FixedReader();
await using (var sampler = new HostMetricsSampler(reader: reader))
{
    sampler.Start(); sampler.Start();
    Check(reader.Reads == 1, "Starting multiple consumers cannot create duplicate sampling loops");
    Check(sampler.Latest is { CpuPercent: null, MemoryPercent: 42 } && sampler.Latest.Coverage.Cpu == "warmingUp", "First timer reading has explicit partial coverage");
    Check(sampler.Capabilities.Persistence == "session-memory-only", "Fast metrics never claim SQLite persistence");
    var json = JsonSerializer.Serialize(sampler.History(TimeSpan.FromHours(1)), new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
    foreach (var forbidden in new[] { "hostname", "username", "processes", "interfaces", "addresses", "paths", "token" })
        Check(!json.Contains(forbidden, StringComparison.OrdinalIgnoreCase), "Metric DTO excludes identity-bearing property " + forbidden);
}
var system = new SystemHostMetricsReader().Read();
Check(system.MemoryPercent is null || system.MemoryPercent is >= 0 and <= 100, "Actual platform memory counter remains bounded or unavailable");
Console.WriteLine($"PASS: {assertions} lightweight metrics, retention, ordering, and privacy assertions.");

sealed class FixedReader : IHostMetricsReader
{
    public int Reads { get; private set; }
    public HostMetricsReading Read() { Reads++; return new(100, 20, 42); }
}
