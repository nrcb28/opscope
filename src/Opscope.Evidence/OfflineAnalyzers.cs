using System.Globalization;
using System.Text;

namespace Opscope.Evidence;

public static class TimelineBuilder
{
    public static AnalysisReport Build(Snapshot snapshot, Snapshot? baseline = null, IReadOnlyList<EvidenceRecord>? records = null)
    {
        var events = new List<TimelineEvent>();
        var warnings = new List<string>(snapshot.CollectionWarnings);
        if (snapshot.Host.BootTimeUtc <= snapshot.CollectedAtUtc)
            events.Add(new TimelineEvent(snapshot.Host.BootTimeUtc, "boot", "snapshot", "Host boot time reported by the snapshot; this may be derived from uptime."));
        else warnings.Add("Boot time is later than snapshot time and was excluded.");
        events.Add(new TimelineEvent(snapshot.CollectedAtUtc, "snapshot", "snapshot", EvidenceCollector.Safe(snapshot,
            $"Observed CPU={snapshot.CpuUsedPercent:F1}%, memory={snapshot.Memory.UsedPercent:F1}%, findings={snapshot.Findings.Count}, services={snapshot.Services.Count}.")));
        foreach (var service in snapshot.Services.Where(service => service.State.Contains("fail", StringComparison.OrdinalIgnoreCase)).Take(500))
            events.Add(new TimelineEvent(snapshot.CollectedAtUtc, "service-observation", "snapshot", EvidenceCollector.Safe(snapshot, $"{service.Name}: {service.State}; observation time, not failure onset.")));
        if (baseline is not null)
        {
            if (baseline.CollectedAtUtc > snapshot.CollectedAtUtc) throw new ArgumentException("Timeline baseline must not be later than current snapshot.", nameof(baseline));
            if (!baseline.Host.Hostname.StartsWith("[redacted", StringComparison.Ordinal) && !snapshot.Host.Hostname.StartsWith("[redacted", StringComparison.Ordinal) && !baseline.Host.Hostname.Equals(snapshot.Host.Hostname, StringComparison.OrdinalIgnoreCase)) warnings.Add("Baseline and current snapshot identify different hosts; drift is a cross-host comparison.");
            events.Add(new TimelineEvent(baseline.CollectedAtUtc, "baseline", "snapshot", "Baseline snapshot collected."));
            var diff = Reporter.RedactForOutput(DiffEngine.Compare(baseline, snapshot));
            warnings.AddRange(diff.Warnings ?? []);
            foreach (var change in diff.Changes.Take(1000))
                events.Add(new TimelineEvent(snapshot.CollectedAtUtc, "drift", "snapshot-diff", EvidenceCollector.Safe(snapshot,
                    $"{change.Category}: {change.Identity}: {change.Change}: {change.Details}. Observed between baseline and current snapshots; exact change time unknown.")));
        }
        foreach (var record in (records ?? []).Where(record => record.Group == "logs" && record.TimestampUtc.HasValue).Take(2000))
            events.Add(new TimelineEvent(record.TimestampUtc!.Value, "log", record.Source, EvidenceCollector.Safe(snapshot, record.Summary)));
        if ((records ?? []).Any(record => record.Group == "logs" && !record.TimestampUtc.HasValue)) warnings.Add("Log records without a parseable timestamp were not placed on the timeline.");
        warnings.Add("Timestamps use UTC ISO 8601. Snapshot differences are assigned observation time, not an invented exact change time.");
        return new AnalysisReport("timeline", snapshot.CollectedAtUtc, [], new TimelineData(events
            .OrderBy(entry => entry.TimestampUtc).ThenBy(entry => entry.Kind, StringComparer.Ordinal).ThenBy(entry => entry.Source, StringComparer.Ordinal)
            .ThenBy(entry => entry.Description, StringComparer.Ordinal).Take(5000).ToArray()), warnings);
    }

    public static string ToCsv(AnalysisReport report)
    {
        if (report.Data is not TimelineData data) throw new ArgumentException("A timeline report is required.", nameof(report));
        var csv = new StringBuilder("timestampUtc,kind,source,description\r\n");
        foreach (var entry in data.Events)
            csv.Append(Csv(entry.TimestampUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture))).Append(',')
                .Append(Csv(entry.Kind)).Append(',').Append(Csv(entry.Source)).Append(',').Append(Csv(entry.Description)).Append("\r\n");
        return csv.ToString();
    }

    private static string Csv(string value)
    {
        // Spreadsheet consumers must not interpret evidence as a formula.
        if (value.TrimStart().StartsWith('=') || value.TrimStart().StartsWith('+') || value.TrimStart().StartsWith('-') || value.TrimStart().StartsWith('@')) value = "'" + value;
        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }
}

public static class FleetAnalyzer
{
    public static AnalysisReport Compare(IReadOnlyList<Snapshot> snapshots)
    {
        ArgumentNullException.ThrowIfNull(snapshots);
        if (snapshots.Count < 2 || snapshots.Count > 256) throw new ArgumentException("Fleet comparison requires 2–256 saved snapshots.", nameof(snapshots));
        var warnings = new List<string>();
        var hosts = snapshots.GroupBy(snapshot => snapshot.Host.Hostname, StringComparer.OrdinalIgnoreCase).Select(group =>
        {
            var latest = group.OrderByDescending(snapshot => snapshot.CollectedAtUtc).First();
            return new FleetHost(latest.Host.Hostname, group.Count(), latest.CpuUsedPercent, latest.Memory.UsedPercent,
                latest.Disks.Where(disk => disk.IsReady).Select(disk => (double?)disk.UsedPercent).DefaultIfEmpty().Max(),
                latest.Findings.Count, latest.Services.Count(service => service.State.Contains("fail", StringComparison.OrdinalIgnoreCase)));
        }).OrderBy(host => host.Host, StringComparer.Ordinal).ToArray();
        if (hosts.Length < 2) throw new ArgumentException("Fleet comparison requires at least two distinct host identities.", nameof(snapshots));
        if (snapshots.Select(snapshot => snapshot.Host.Platform).Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1)
            warnings.Add("Fleet spans multiple operating systems; service and process names are not treated as equivalent compliance baselines.");
        if (snapshots.Max(snapshot => snapshot.CollectedAtUtc) - snapshots.Min(snapshot => snapshot.CollectedAtUtc) > TimeSpan.FromHours(24))
            warnings.Add("Snapshots span more than 24 hours; time differences may explain apparent outliers.");
        if (hosts.Any(host => host.SnapshotCount > 1)) warnings.Add("Multiple snapshots for one host use the latest observation for outlier comparisons.");
        var cpuMedian = Median(hosts.Select(host => host.CpuUsedPercent));
        var memoryMedian = Median(hosts.Select(host => host.MemoryUsedPercent));
        var diskValues = hosts.Where(host => host.MaximumDiskUsedPercent.HasValue).Select(host => host.MaximumDiskUsedPercent!.Value).ToArray();
        var diskMedian = diskValues.Length > 0 ? Median(diskValues) : (double?)null;
        var findings = new List<Finding>();
        foreach (var host in hosts)
        {
            CompareMetric(host, "CPU", host.CpuUsedPercent, cpuMedian, findings);
            CompareMetric(host, "MEMORY", host.MemoryUsedPercent, memoryMedian, findings);
            if (host.MaximumDiskUsedPercent.HasValue && diskMedian.HasValue) CompareMetric(host, "DISK", host.MaximumDiskUsedPercent.Value, diskMedian.Value, findings);
            if (host.FailedServices > 0 && hosts.Any(peer => peer.FailedServices == 0))
                findings.Add(new Finding(FindingSeverity.Warning, "FLEET_FAILED_SERVICES", "Host has failed services unlike a peer",
                    Reporter.RedactEvidenceText($"Host {host.Host}: {host.FailedServices} failed services; compare only equivalent host roles.", host.Host),
                    "Review service purpose, baseline and collection completeness before treating differences as an incident."));
        }
        warnings.Add("Outlier rule: utilization at least 85% and at least 20 percentage points above the fleet median. Findings are observational and do not imply comparable host roles.");
        return new AnalysisReport("fleet", snapshots.Max(snapshot => snapshot.CollectedAtUtc), findings,
            new FleetData(hosts, cpuMedian, memoryMedian, diskMedian), warnings);
    }

    private static void CompareMetric(FleetHost host, string metric, double value, double median, List<Finding> findings)
    {
        if (!double.IsFinite(value) || !double.IsFinite(median)) throw new InvalidDataException("Fleet utilization must contain finite numbers.");
        if (value >= 85 && value - median >= 20)
            findings.Add(new Finding(value >= 95 ? FindingSeverity.Critical : FindingSeverity.Warning, $"FLEET_{metric}_OUTLIER", $"{metric} utilization outlier",
                Reporter.RedactEvidenceText(FormattableString.Invariant($"Host {host.Host}: {value:F1}%, fleet median {median:F1}%, delta {value - median:F1} percentage points."), host.Host),
                "Compare the host's role, baseline and timestamp with peers; no remediation was executed."));
    }

    private static double Median(IEnumerable<double> values)
    {
        var sorted = values.Order().ToArray();
        if (sorted.Length == 0) return 0;
        if (sorted.Any(value => !double.IsFinite(value) || value is < 0 or > 100)) throw new InvalidDataException("Fleet utilization must be finite and between 0 and 100.");
        return sorted.Length % 2 == 0 ? (sorted[sorted.Length / 2 - 1] + sorted[sorted.Length / 2]) / 2 : sorted[sorted.Length / 2];
    }
}

public static class TriageAdvisor
{
    public static AnalysisReport Analyze(Snapshot snapshot, string scenario)
    {
        var steps = new List<TriageStep>();
        var findings = new List<Finding>();
        scenario = scenario.Trim().ToLowerInvariant();
        switch (scenario)
        {
            case "high-cpu":
                steps.Add(new TriageStep(1, "Confirm host CPU pressure", FormattableString.Invariant($"CPU={snapshot.CpuUsedPercent:F1}%; processors={snapshot.Host.ProcessorCount}; observed={snapshot.CollectedAtUtc:O}."), "Compare repeated snapshots to distinguish sustained load from a short spike."));
                steps.Add(new TriageStep(2, "Review process evidence", string.Join("; ", snapshot.Processes.OrderByDescending(process => process.CpuTime).Take(5).Select(process => $"PID {process.Id} {process.Name}: cumulative CPU {process.CpuTime}")), "Process CPU times are cumulative, not instantaneous percentages; inspect workload ownership and compare a later snapshot."));
                steps.Add(new TriageStep(3, "Correlate memory and failures", FormattableString.Invariant($"Memory={snapshot.Memory.UsedPercent:F1}%; failed services={snapshot.Services.Count(service => service.State.Contains("fail", StringComparison.OrdinalIgnoreCase))}."), "Review recent errors and baseline changes; collect a redacted support bundle for handoff."));
                if (snapshot.CpuUsedPercent >= 85) findings.Add(new Finding(FindingSeverity.Warning, "TRIAGE_CPU_PRESSURE", "High CPU observed", FormattableString.Invariant($"Host CPU={snapshot.CpuUsedPercent:F1}%."), "Follow the observational high-cpu triage steps; no process was stopped."));
                break;
            case "disk-full":
                steps.Add(new TriageStep(1, "Locate affected filesystems", string.Join("; ", snapshot.Disks.Where(disk => disk.IsReady).OrderByDescending(disk => disk.UsedPercent).Take(10).Select(disk => FormattableString.Invariant($"{disk.Root}: {disk.UsedPercent:F1}% used, {disk.AvailableBytes} bytes available"))), "Confirm the affected mount and its normal capacity before inspecting application growth."));
                steps.Add(new TriageStep(2, "Correlate errors and service state", $"Snapshot findings={snapshot.Findings.Count}; collection warnings={snapshot.CollectionWarnings.Count}.", "Review error logs, recent deployments, retention policies and the baseline. Do not delete evidence during triage."));
                steps.Add(new TriageStep(3, "Prepare handoff", "This workflow did not scan file contents, delete files or rotate logs.", "Generate a redacted bundle and ask the service owner to plan capacity or cleanup under their change procedure."));
                foreach (var disk in snapshot.Disks.Where(disk => disk.IsReady && disk.UsedPercent >= 85)) findings.Add(new Finding(disk.UsedPercent >= 95 ? FindingSeverity.Critical : FindingSeverity.Warning,
                    "TRIAGE_DISK_PRESSURE", "Filesystem capacity pressure", EvidenceCollector.Safe(snapshot, FormattableString.Invariant($"{disk.Root}: {disk.UsedPercent:F1}% used.")), "Review the disk-full guidance and preserve incident evidence."));
                break;
            case "port-exposed":
                var listeners = snapshot.Listeners.Where(listener => EvidenceCollector.TryGetEndpoint(listener.LocalAddress, out var address, out _) && !EvidenceCollector.IsLoopback(address)).ToArray();
                steps.Add(new TriageStep(1, "Identify non-loopback listeners", string.Join("; ", listeners.Take(20).Select(listener => $"{listener.Protocol} {listener.LocalAddress} {listener.Process}")), "A listening socket does not establish Internet reachability. Confirm intended clients and process ownership."));
                steps.Add(new TriageStep(2, "Check filtering evidence", $"Firewall status known={snapshot.Security.FirewallStatusKnown}; protection verified={snapshot.Security.ProtectionVerified}.", "Review host firewall, cloud security groups/NSGs, NAT and routing in the correct account and network context."));
                steps.Add(new TriageStep(3, "Compare intended exposure", "Use allowed-port policies, baseline drift and cloud posture if configured.", "Preserve a redacted bundle and route any access change through the operator; this workflow does not modify firewall rules."));
                findings.AddRange(EvidenceCollector.EvaluateSnapshotSecurity(snapshot).Findings);
                break;
            default: throw new ArgumentException("Supported scenarios: high-cpu, disk-full, port-exposed.", nameof(scenario));
        }
        return new AnalysisReport("triage", snapshot.CollectedAtUtc, findings,
            new TriageData(scenario, steps.Select(step => step with { Evidence = EvidenceCollector.Safe(snapshot, step.Evidence) }).ToArray()),
            ["Guidance only: no service, process, file, firewall or resource was changed. Evidence is limited to the supplied snapshot."]);
    }
}
