using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using Opscope.Api;

var assertions = 0;
void Check(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
    assertions++;
}
HostMetricsReading Read(Fixture fixture) => new DarwinHostMetricsReader(fixture).Read();
void Released(Fixture fixture) => Check(fixture.Acquires == 1 && fixture.Releases == 1 && fixture.ReleasedPort == fixture.Host,
    "Every acquired host send right is released exactly once");
void CpuAvailable(HostMetricsReading reading) => Check(reading.CpuTotal == 100 && reading.CpuIdle == 40 && reading.CpuStatus is null,
    "Independent valid CPU counters remain available");
void MemoryAvailable(HostMetricsReading reading) => Check(reading.MemoryPercent == 70 && reading.MemoryStatus == "estimated",
    "Independent memory estimate remains available with explicit estimated coverage");
void CpuMissing(HostMetricsReading reading) => Check(reading.CpuTotal is null && reading.CpuIdle is null && reading.CpuStatus == "unavailable",
    "Invalid CPU reads remain unknown, without fabricated counters");
void MemoryMissing(HostMetricsReading reading) => Check(reading.MemoryPercent is null && reading.MemoryStatus == "unavailable",
    "Invalid memory reads remain unknown, without fabricated utilization");

// Apple host_info.h / vm_statistics.h ABI: HOST_CPU_LOAD_INFO_COUNT=4;
// HOST_VM_INFO64_REV0_COUNT=offsetof(decompressions)/sizeof(integer_t)=96/4.
Check(Marshal.SizeOf<DarwinCpuLoad>() == 16 && DarwinHostMetricsReader.CpuCount == 4, "CPU ABI contains four 32-bit counters");
Check(Marshal.OffsetOf<DarwinCpuLoad>(nameof(DarwinCpuLoad.User)).ToInt32() == 0 &&
      Marshal.OffsetOf<DarwinCpuLoad>(nameof(DarwinCpuLoad.System)).ToInt32() == 4 &&
      Marshal.OffsetOf<DarwinCpuLoad>(nameof(DarwinCpuLoad.Idle)).ToInt32() == 8 &&
      Marshal.OffsetOf<DarwinCpuLoad>(nameof(DarwinCpuLoad.Nice)).ToInt32() == 12, "CPU counter order matches CPU_STATE_* indexes");
Check(Marshal.SizeOf<DarwinVmInfo64>() == 96 && DarwinHostMetricsReader.VmCount == 24, "VM buffer matches the stable 96-byte revision-zero prefix");
Check(Marshal.OffsetOf<DarwinVmInfo64>(nameof(DarwinVmInfo64.Free)).ToInt32() == 0 &&
      Marshal.OffsetOf<DarwinVmInfo64>(nameof(DarwinVmInfo64.Inactive)).ToInt32() == 8, "VM page counts retain their native offsets");
var imports = typeof(DarwinMetricsNative).GetMethods(BindingFlags.Static | BindingFlags.NonPublic)
    .Select(method => (Method: method, Import: method.GetCustomAttribute<DllImportAttribute>()))
    .Where(pair => pair.Import is not null).ToArray();
Check(imports.Length == 7 && imports.All(pair => pair.Import!.Value == "/usr/lib/libSystem.B.dylib" && pair.Import.ExactSpelling),
    "Darwin imports use exact libSystem exports");
Check(imports.Any(pair => pair.Import!.EntryPoint == "task_self_trap") && !imports.Any(pair => pair.Import!.EntryPoint == "mach_task_self"),
    "Host-right deallocation uses an exported task-self trap, not a C macro");
Check(imports.Single(pair => pair.Import!.EntryPoint == "host_page_size").Method.GetParameters()[1].ParameterType == typeof(nuint).MakeByRefType(),
    "host_page_size writes a native-width vm_size_t");
var sysctl = imports.Single(pair => pair.Import!.EntryPoint == "sysctlbyname").Method.GetParameters();
Check(sysctl[1].ParameterType == typeof(ulong).MakeByRefType() && sysctl[2].ParameterType == typeof(nuint).MakeByRefType(),
    "hw.memsize uses a 64-bit value and native-width size_t");

var valid = new Fixture();
var baseline = Read(valid);
CpuAvailable(baseline);
MemoryAvailable(baseline);
Check(valid.CpuRequested == 4 && valid.VmRequested == 24 && valid.MemoryRequested == 8, "Every native call receives its exact ABI buffer count");
Check(valid.Calls.SequenceEqual(["acquire", "cpu", "memory", "page", "vm", "release"]), "A sample performs only bounded aggregate host reads and releases its port");
Released(valid);

// Deliberately populate the native speculative_count field at byte 92. Apple includes
// those pages in free_count already, so adding it again would incorrectly yield 20%.
var vmBytes = new byte[96];
BitConverter.GetBytes(100u).CopyTo(vmBytes, 0);
BitConverter.GetBytes(200u).CopyTo(vmBytes, 8);
BitConverter.GetBytes(500u).CopyTo(vmBytes, 92);
var pinned = GCHandle.Alloc(vmBytes, GCHandleType.Pinned);
try
{
    var speculative = new Fixture { Vm = Marshal.PtrToStructure<DarwinVmInfo64>(pinned.AddrOfPinnedObject()) };
    MemoryAvailable(Read(speculative));
    Released(speculative);
}
finally { pinned.Free(); }

foreach (var count in new[] { 0u, 3u, 5u, uint.MaxValue })
{
    var fixture = new Fixture { CpuReturned = count };
    var reading = Read(fixture);
    CpuMissing(reading); MemoryAvailable(reading); Released(fixture);
}
foreach (var count in new[] { 0u, 23u, 25u, uint.MaxValue })
{
    var fixture = new Fixture { VmReturned = count };
    var reading = Read(fixture);
    CpuAvailable(reading); MemoryMissing(reading); Released(fixture);
}
foreach (var length in new nuint[] { 0, 4, 7, 9, 16 })
{
    var fixture = new Fixture { MemoryReturned = length };
    var reading = Read(fixture);
    CpuAvailable(reading); MemoryMissing(reading); Released(fixture);
    Check(!fixture.Calls.Contains("page") && !fixture.Calls.Contains("vm"), "Invalid physical-memory lengths stop dependent native reads");
}
foreach (var stage in new[] { "cpu", "memory", "page", "vm" })
{
    var fixture = new Fixture { FailedStage = stage };
    var reading = Read(fixture);
    if (stage == "cpu") { CpuMissing(reading); MemoryAvailable(reading); }
    else { CpuAvailable(reading); MemoryMissing(reading); }
    Released(fixture);
}
foreach (var page in new nuint[] { 0, 3, 4095, 6144 })
{
    var fixture = new Fixture { PageSize = page };
    var reading = Read(fixture);
    CpuAvailable(reading); MemoryMissing(reading); Released(fixture);
    Check(!fixture.Calls.Contains("vm"), "Zero and non-power-of-two page sizes stop VM reads");
}
foreach (var physical in new[] { 0UL, 1UL, 300UL * 4096 - 1 })
{
    var fixture = new Fixture { PhysicalBytes = physical };
    var reading = Read(fixture);
    CpuAvailable(reading); MemoryMissing(reading); Released(fixture);
}
foreach (var (pages, expected) in new[] { (0u, 100d), (1000u, 0d) })
{
    var fixture = new Fixture { Vm = new() { Free = pages, Inactive = 0 } };
    var reading = Read(fixture);
    Check(reading.MemoryPercent == expected && reading.MemoryStatus == "estimated", "Genuine 0% and 100% memory estimates are retained");
    Released(fixture);
}
var wideCpu = new Fixture { Cpu = new() { User = uint.MaxValue, System = uint.MaxValue, Idle = uint.MaxValue, Nice = uint.MaxValue } };
var wideReading = Read(wideCpu);
Check(wideReading.CpuTotal == 4UL * uint.MaxValue && wideReading.CpuIdle == uint.MaxValue, "CPU summation widens before adding native uint counters");
Released(wideCpu);
var wideVm = new Fixture { PhysicalBytes = 2UL * uint.MaxValue * 4096, Vm = new() { Free = uint.MaxValue, Inactive = uint.MaxValue } };
var wideMemory = Read(wideVm);
Check(wideMemory.MemoryPercent == 0 && wideMemory.MemoryStatus == "estimated", "Page-count addition widens before adding native uint counters");
Released(wideVm);
if (nuint.Size == 8)
{
    var overflow = new Fixture { PhysicalBytes = ulong.MaxValue, PageSize = unchecked((nuint)(1UL << 63)), Vm = new() { Free = 3 } };
    var reading = Read(overflow);
    CpuAvailable(reading); MemoryMissing(reading); Released(overflow);
}

foreach (var stage in new[] { "acquire", "cpu", "memory", "page", "vm", "release" })
{
    var fixture = new Fixture { ThrowStage = stage, Error = new InvalidOperationException("private native failure") };
    var reading = Read(fixture);
    if (stage == "acquire") { CpuMissing(reading); MemoryMissing(reading); Check(fixture.Releases == 0, "A failed acquisition does not release a nonexistent right"); }
    else
    {
        if (stage == "cpu") { CpuMissing(reading); MemoryAvailable(reading); }
        else if (stage == "release") { CpuAvailable(reading); MemoryAvailable(reading); }
        else { CpuAvailable(reading); MemoryMissing(reading); }
        Released(fixture);
    }
    Check(!JsonSerializer.Serialize(reading).Contains("private native failure", StringComparison.Ordinal), "Native exception details never enter a reading");
}
foreach (var error in new Exception[] { new DllNotFoundException(), new EntryPointNotFoundException(), new BadImageFormatException(),
    new ExternalException(), new IOException(), new UnauthorizedAccessException(), new ArgumentException(), new OverflowException() })
{
    var fixture = new Fixture { ThrowStage = "cpu", Error = error };
    var reading = Read(fixture);
    CpuMissing(reading); MemoryAvailable(reading); Released(fixture);
}
var noHost = new Fixture { Host = 0 };
var unavailable = Read(noHost);
CpuMissing(unavailable); MemoryMissing(unavailable);
Check(noHost.Calls.SequenceEqual(["acquire"]) && noHost.Releases == 0, "A null host right stops reads and is never deallocated");
var failedRelease = new Fixture { FailedStage = "release" };
CpuAvailable(Read(failedRelease)); Released(failedRelease);

Check(HostMetricsSampler.CpuDelta(null, baseline) is null, "Darwin CPU warms up without inventing a first percentage");
Check(HostMetricsSampler.CpuDelta(baseline, baseline) is null, "Unchanged CPU counters remain unknown");
Check(HostMetricsSampler.CpuDelta(baseline, new(90, 30, 70)) is null, "A total-counter reset remains unknown");
Check(HostMetricsSampler.CpuDelta(baseline, new(200, 30, 70)) is null, "An idle-counter reset remains unknown");
Check(HostMetricsSampler.CpuDelta(baseline, new(200, 141, 70)) is null, "An impossible idle delta remains unknown");
Check(HostMetricsSampler.CpuDelta(baseline, new(200, 140, 70)) == 0, "A measured fully idle interval preserves true zero CPU");
Check(HostMetricsSampler.CpuDelta(baseline, new(200, 40, 70)) == 100, "A measured fully busy interval preserves 100% CPU");
Check(HostMetricsSampler.CpuDelta(baseline, new(200, 65, 70)) == 75, "Darwin CPU percentage comes from cumulative counter deltas");

await using (var sampler = new HostMetricsSampler(reader: new DarwinHostMetricsReader(new Fixture())))
{
    sampler.Start();
    Check(sampler.Latest is { CpuPercent: null, MemoryPercent: 70, Status: "partial" } &&
        sampler.Latest.Coverage == new HostMetricCoverage("warmingUp", "estimated"), "Sampler preserves estimated memory while Darwin CPU warms up");
    Check(sampler.Capabilities.Coverage.Memory == "estimated", "Capabilities preserve the memory estimate qualification");
    var json = JsonSerializer.Serialize(sampler.History(TimeSpan.FromHours(1)));
    foreach (var forbidden in new[] { "hostname", "username", "processes", "interfaces", "addresses", "path", "token", "port" })
        Check(!json.Contains(forbidden, StringComparison.OrdinalIgnoreCase), "Darwin history excludes identity-bearing field " + forbidden);
}

if (OperatingSystem.IsMacOS())
{
    var native = new DarwinMetricsNative();
    var host = native.AcquireHost();
    Check(host != 0, "Real macOS returns a host send right");
    if (host != 0) Check(native.ReleaseHost(host) == 0, "Real macOS deallocates its host send right successfully");
    var system = new SystemHostMetricsReader();
    var first = system.Read();
    var second = first;
    for (var attempt = 0; attempt < 12; attempt++)
    {
        await Task.Delay(250);
        second = system.Read();
        if (HostMetricsSampler.CpuDelta(first, second) is not null) break;
    }
    foreach (var reading in new[] { first, second })
    {
        Check(reading.CpuTotal is > 0 && reading.CpuIdle is not null && reading.CpuIdle <= reading.CpuTotal,
            "Real macOS exposes valid aggregate CPU counters");
        Check(reading.MemoryPercent is >= 0 and <= 100 && reading.MemoryStatus == "estimated", "Real macOS exposes bounded estimated memory");
        var properties = JsonSerializer.SerializeToElement(reading).EnumerateObject().Select(property => property.Name).ToArray();
        Check(properties.SequenceEqual(["CpuTotal", "CpuIdle", "MemoryPercent", "CpuStatus", "MemoryStatus"]), "Real macOS output contains only aggregate metric values and coverage");
    }
    Check(HostMetricsSampler.CpuDelta(first, second) is >= 0 and <= 100, "Two real macOS observations produce a known bounded CPU delta");
    Console.WriteLine("PASS: real macOS native counters and host-right release exercised.");
}
else Console.WriteLine("SKIP: real macOS native checks require macOS; fixture checks ran on this platform.");
Console.WriteLine($"PASS: {assertions} Darwin ABI, aggregate metrics, failure isolation, lifecycle, estimate coverage, and privacy assertions.");

sealed class Fixture : IDarwinMetricsNative
{
    public uint Host = 42;
    public DarwinCpuLoad Cpu = new() { User = 20, System = 30, Idle = 40, Nice = 10 };
    public DarwinVmInfo64 Vm = new() { Free = 100, Inactive = 200 };
    public ulong PhysicalBytes = 1000UL * 4096;
    public nuint PageSize = 4096;
    public uint CpuReturned = 4, VmReturned = 24;
    public nuint MemoryReturned = 8;
    public string? FailedStage, ThrowStage;
    public Exception Error = new InvalidOperationException();
    public List<string> Calls { get; } = [];
    public int Acquires, Releases;
    public uint ReleasedPort, CpuRequested, VmRequested;
    public nuint MemoryRequested;
    private int Call(string stage)
    {
        Calls.Add(stage);
        if (ThrowStage == stage) throw Error;
        return FailedStage == stage ? 5 : 0;
    }
    private void HostMatches(uint host)
    {
        if (host == 0 || host != Host) throw new Exception("Reader used a host right it did not acquire");
    }
    public uint AcquireHost() { Acquires++; Call("acquire"); return Host; }
    public int ReadCpu(uint host, out DarwinCpuLoad cpu, ref uint count)
    { HostMatches(host); CpuRequested = count; cpu = Cpu; count = CpuReturned; return Call("cpu"); }
    public int ReadVm(uint host, out DarwinVmInfo64 vm, ref uint count)
    { HostMatches(host); VmRequested = count; vm = Vm; count = VmReturned; return Call("vm"); }
    public int ReadPageSize(uint host, out nuint pageSize)
    { HostMatches(host); pageSize = PageSize; return Call("page"); }
    public int ReadMemorySize(out ulong bytes, ref nuint length)
    { MemoryRequested = length; bytes = PhysicalBytes; length = MemoryReturned; return Call("memory"); }
    public int ReleaseHost(uint host)
    { HostMatches(host); Releases++; ReleasedPort = host; return Call("release"); }
}
