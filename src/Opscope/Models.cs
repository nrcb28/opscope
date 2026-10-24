namespace Opscope;

public enum FindingSeverity
{
    Info,
    Warning,
    Critical
}

public sealed record Finding(
    FindingSeverity Severity,
    string Code,
    string Title,
    string Detail,
    string Recommendation);

public sealed record HostInfo(
    string Hostname,
    string OsDescription,
    string Platform,
    string Architecture,
    string Runtime,
    string Kernel,
    DateTimeOffset BootTimeUtc,
    TimeSpan Uptime,
    bool IsElevated,
    int ProcessorCount,
    string CurrentUser);

public sealed record MemoryInfo(
    ulong TotalBytes,
    ulong AvailableBytes,
    ulong UsedBytes,
    double UsedPercent,
    string Source);

public sealed record DiskInfo(
    string Name,
    string Root,
    string FileSystem,
    long TotalBytes,
    long AvailableBytes,
    double UsedPercent,
    bool IsReady);

public sealed record NetworkAdapter(
    string Name,
    string Description,
    string Type,
    string Status,
    IReadOnlyList<string> Addresses,
    long SpeedBitsPerSecond);

public sealed record ProcessInfo(
    int Id,
    string Name,
    string User,
    long WorkingSetBytes,
    double WorkingSetMb,
    TimeSpan CpuTime,
    string? CommandLine,
    bool AccessLimited);

public sealed record ListenerInfo(
    string Protocol,
    string LocalAddress,
    string Process,
    string Source);

public sealed record ServiceInfo(
    string Name,
    string State,
    string? Description,
    string Source);

public sealed record FirewallProfile(
    string Name,
    string State,
    string Source);

public sealed record SecurityPosture(
    IReadOnlyList<FirewallProfile> Firewalls,
    bool FirewallStatusKnown,
    bool HasActiveFirewall,
    int ExposedListeners);

public sealed record ToolInfo(
    string Name,
    string Purpose,
    string Role,
    bool Available,
    string? Path,
    string Security,
    string? Version);

public sealed record ToolingPosture(
    IReadOnlyList<ToolInfo> Tools);

public sealed record CommandResult(
    int ExitCode,
    string StandardOutput,
    string StandardError,
    bool TimedOut,
    bool OutputTruncated = false);

public sealed record Snapshot(
    DateTimeOffset CollectedAtUtc,
    HostInfo Host,
    double CpuUsedPercent,
    MemoryInfo Memory,
    IReadOnlyList<DiskInfo> Disks,
    IReadOnlyList<NetworkAdapter> Network,
    IReadOnlyList<ProcessInfo> Processes,
    IReadOnlyList<ListenerInfo> Listeners,
    IReadOnlyList<ServiceInfo> Services,
    SecurityPosture Security,
    ToolingPosture? Tooling,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<string> CollectionWarnings,
    TimeSpan CollectionDuration);

public sealed record MetricDelta(
    string Name,
    double Baseline,
    double Current,
    double Delta,
    string Unit);

public sealed record EntityDelta(
    string Category,
    string Identity,
    string Change,
    string Details);

public sealed record DiffReport(
    string BaselineHost,
    string CurrentHost,
    DateTimeOffset BaselineCollectedAtUtc,
    DateTimeOffset CurrentCollectedAtUtc,
    bool Significant,
    IReadOnlyList<MetricDelta> Metrics,
    IReadOnlyList<EntityDelta> Changes);

public sealed record CollectorOptions(
    bool IncludeProcesses = true,
    bool IncludeNetwork = true,
    bool IncludeServices = true,
    int TopProcesses = 20,
    TimeSpan CommandTimeout = default)
{
    public TimeSpan EffectiveCommandTimeout => CommandTimeout == default ? TimeSpan.FromSeconds(3) : CommandTimeout;
}

