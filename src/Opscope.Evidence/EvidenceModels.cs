namespace Opscope.Evidence;

public sealed record EvidenceRecord(string Group, string Source, string Status, string Summary,
    DateTimeOffset? TimestampUtc = null, IReadOnlyDictionary<string, string>? Metadata = null);

public sealed record CheckCoverage(string Code, string Platform, string State, string Evidence, string? Reference = null);

public sealed record EvidenceData(IReadOnlyList<EvidenceRecord> Records, IReadOnlyList<CheckCoverage> Coverage);

public sealed record TimelineEvent(DateTimeOffset TimestampUtc, string Kind, string Source, string Description);

public sealed record TimelineData(IReadOnlyList<TimelineEvent> Events);

public sealed record IocIndicator(string Type, string Value, string? Label = null);

public sealed record IocMatch(IocIndicator Indicator, string Source, string Evidence);

public sealed record IocData(int IndicatorCount, int ObservableCount, IReadOnlyList<IocMatch> Matches);

public sealed record FleetHost(string Host, int SnapshotCount, double CpuUsedPercent, double MemoryUsedPercent,
    double? MaximumDiskUsedPercent, int Findings, int FailedServices);

public sealed record FleetData(IReadOnlyList<FleetHost> Hosts, double MedianCpuUsedPercent,
    double MedianMemoryUsedPercent, double? MedianMaximumDiskUsedPercent);

public sealed record TriageStep(int Number, string Title, string Evidence, string Guidance);

public sealed record TriageData(string Scenario, IReadOnlyList<TriageStep> Steps);

public sealed record RuntimeEnvironment(bool ContainerDetected, bool DockerDetected, bool PodmanDetected,
    bool KubernetesDetected, IReadOnlyList<string> Signals, IReadOnlyDictionary<string, string> Inventory);
