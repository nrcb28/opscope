using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

[assembly: InternalsVisibleTo("Opscope.DarwinMetricsTests")]

namespace Opscope.Api;

/// <summary>Bounded Darwin host counters; no process enumeration, shell commands or identities.</summary>
internal sealed class DarwinHostMetricsReader(IDarwinMetricsNative? native = null) : IHostMetricsReader
{
    private readonly IDarwinMetricsNative native = native ?? new DarwinMetricsNative();
    internal const uint CpuCount = 4;
    // EN: Request the stable VM64 revision-zero prefix, rather than a newer OS-specific tail.
    // ES: Se solicita el prefijo estable de revisión cero, sin depender de campos de sistemas posteriores.
    internal const uint VmCount = 24;

    public HostMetricsReading Read()
    {
        ulong? total = null, idle = null;
        double? memory = null;
        uint host = 0;
        try
        {
            host = native.AcquireHost();
            if (host == 0) return Unavailable();
            try
            {
                var count = CpuCount;
                if (native.ReadCpu(host, out var cpu, ref count) == 0 && count == CpuCount)
                {
                    total = checked((ulong)cpu.User + cpu.System + cpu.Idle + cpu.Nice);
                    idle = cpu.Idle;
                }
            }
            catch (Exception error) when (NativeFailure(error)) { }
            try
            {
                nuint length = sizeof(ulong);
                var count = VmCount;
                if (native.ReadMemorySize(out var physical, ref length) == 0 && length == sizeof(ulong) && physical > 0 &&
                    native.ReadPageSize(host, out var pageSize) == 0 && pageSize > 0 && (pageSize & (pageSize - 1)) == 0 &&
                    native.ReadVm(host, out var vm, ref count) == 0 && count == VmCount)
                {
                    // Speculative pages are already included in free_count (Apple vm_statistics.h).
                    // Las páginas especulativas ya se incluyen en free_count; no se suman otra vez.
                    var reclaimable = checked(((ulong)vm.Free + vm.Inactive) * (ulong)pageSize);
                    if (reclaimable <= physical)
                        memory = Math.Round(100d * (physical - reclaimable) / physical, 2);
                }
            }
            catch (Exception error) when (NativeFailure(error)) { }
        }
        catch (Exception error) when (NativeFailure(error)) { }
        finally
        {
            // mach_host_self returns a send right; release it even when another counter fails.
            // Se libera el derecho de envío incluso si falla alguna lectura del host.
            if (host != 0)
                try { native.ReleaseHost(host); }
                catch (Exception error) when (NativeFailure(error)) { }
        }
        return new(total, idle, memory, total is null ? "unavailable" : null, memory is null ? "unavailable" : "estimated");
    }

    private static HostMetricsReading Unavailable() => new(null, null, null, "unavailable", "unavailable");
    private static bool NativeFailure(Exception error) => error is DllNotFoundException or EntryPointNotFoundException or
        BadImageFormatException or ExternalException or IOException or UnauthorizedAccessException or InvalidOperationException or
        ArgumentException or OverflowException;
}

internal interface IDarwinMetricsNative
{
    uint AcquireHost();
    int ReadCpu(uint host, out DarwinCpuLoad cpu, ref uint count);
    int ReadVm(uint host, out DarwinVmInfo64 vm, ref uint count);
    int ReadPageSize(uint host, out nuint pageSize);
    int ReadMemorySize(out ulong bytes, ref nuint length);
    int ReleaseHost(uint host);
}

[StructLayout(LayoutKind.Sequential)]
internal struct DarwinCpuLoad
{
    public uint User;
    public uint System;
    public uint Idle;
    public uint Nice;
}

// HOST_VM_INFO64_REV0_COUNT is offsetof(decompressions)/sizeof(integer_t): 96/4.
// Only the two page counts used by this estimate are exposed from the native prefix.
[StructLayout(LayoutKind.Explicit, Size = 96)]
internal struct DarwinVmInfo64
{
    [FieldOffset(0)] public uint Free;
    [FieldOffset(8)] public uint Inactive;
}

internal sealed class DarwinMetricsNative : IDarwinMetricsNative
{
    private const string Library = "/usr/lib/libSystem.B.dylib";
    public uint AcquireHost() => MachHostSelf();
    public int ReadCpu(uint host, out DarwinCpuLoad cpu, ref uint count) => HostCpuStatistics(host, 3, out cpu, ref count);
    public int ReadVm(uint host, out DarwinVmInfo64 vm, ref uint count) => HostVmStatistics64(host, 4, out vm, ref count);
    public int ReadPageSize(uint host, out nuint pageSize) => HostPageSize(host, out pageSize);
    public int ReadMemorySize(out ulong bytes, ref nuint length) => SysctlByName("hw.memsize", out bytes, ref length, IntPtr.Zero, 0);
    public int ReleaseHost(uint host) => MachPortDeallocate(TaskSelfTrap(), host);

    [DllImport(Library, EntryPoint = "mach_host_self", ExactSpelling = true)]
    private static extern uint MachHostSelf();
    // mach_task_self() is a C macro over a data symbol; use the exported trap instead.
    [DllImport(Library, EntryPoint = "task_self_trap", ExactSpelling = true)]
    private static extern uint TaskSelfTrap();
    [DllImport(Library, EntryPoint = "mach_port_deallocate", ExactSpelling = true)]
    private static extern int MachPortDeallocate(uint task, uint name);
    [DllImport(Library, EntryPoint = "host_statistics", ExactSpelling = true)]
    private static extern int HostCpuStatistics(uint host, int flavor, out DarwinCpuLoad info, ref uint count);
    [DllImport(Library, EntryPoint = "host_statistics64", ExactSpelling = true)]
    private static extern int HostVmStatistics64(uint host, int flavor, out DarwinVmInfo64 info, ref uint count);
    [DllImport(Library, EntryPoint = "host_page_size", ExactSpelling = true)]
    private static extern int HostPageSize(uint host, out nuint size);
    [DllImport(Library, EntryPoint = "sysctlbyname", ExactSpelling = true)]
    private static extern int SysctlByName([MarshalAs(UnmanagedType.LPUTF8Str)] string name, out ulong oldValue, ref nuint length, IntPtr newValue, nuint newLength);
}
