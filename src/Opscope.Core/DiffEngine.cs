namespace Opscope;

public static class DiffEngine
{
    public static DiffReport Compare(Snapshot baseline, Snapshot current)
    {
        // Compare normalized evidence instead of raw JSON so ordering and formatting do not create false changes.
        // Comparamos evidencia normalizada, no JSON bruto, para evitar falsos cambios por orden o formato.
        var warnings = new List<string>();
        var redactedHost = baseline.Host.Hostname.StartsWith("[redacted", StringComparison.Ordinal) || current.Host.Hostname.StartsWith("[redacted", StringComparison.Ordinal);
        var redactedServices = baseline.Services.Concat(current.Services).Any(s => s.Name.StartsWith("[redacted", StringComparison.Ordinal));
        var redactedListeners = baseline.Listeners.Concat(current.Listeners).Any(l => l.LocalAddress.StartsWith("[redacted", StringComparison.Ordinal));
        if (redactedHost) warnings.Add("Host identity is redacted; host identity changes were not assessed.");
        if (redactedServices) warnings.Add("Service identities are redacted; only service state counts were compared.");
        if (redactedListeners) warnings.Add("Listener endpoints are redacted; only listener protocol counts were compared.");
        if (baseline.Disks.Concat(current.Disks).Any(d => d.Root.StartsWith("[redacted", StringComparison.Ordinal)))
            warnings.Add("Disk identities are redacted; per-volume drift may be unavailable.");
        var metrics = new List<MetricDelta>
        {
            Delta("cpuUsedPercent", baseline.CpuUsedPercent, current.CpuUsedPercent, "%"),
            Delta("memoryUsedPercent", baseline.Memory.UsedPercent, current.Memory.UsedPercent, "%"),
            Delta("listenerCount", baseline.Listeners.Count, current.Listeners.Count, "count"),
            Delta("serviceCount", baseline.Services.Count, current.Services.Count, "count"),
            Delta("processCount", baseline.Processes.Count, current.Processes.Count, "count")
        };

        foreach (var currentDisk in current.Disks.Where(disk => disk.IsReady))
        {
            var baselineDisk = baseline.Disks.FirstOrDefault(disk => disk.Root.Equals(currentDisk.Root, StringComparison.OrdinalIgnoreCase));
            if (baselineDisk is not null)
                metrics.Add(Delta($"diskUsedPercent:{currentDisk.Root}", baselineDisk.UsedPercent, currentDisk.UsedPercent, "%"));
        }

        var changes = new List<EntityDelta>();
        if (!redactedHost && !baseline.Host.Hostname.Equals(current.Host.Hostname, StringComparison.OrdinalIgnoreCase))
            changes.Add(new("host", current.Host.Hostname, "changed", $"Baseline host was {baseline.Host.Hostname}."));

        if (redactedListeners)
            AddCountChanges(changes, "listener", baseline.Listeners.Select(l => l.Protocol), current.Listeners.Select(l => l.Protocol));
        else AddSetChanges(changes, "listener", baseline.Listeners.Select(Key), current.Listeners.Select(Key), "Listening socket set changed.");
        if (redactedServices)
            AddCountChanges(changes, "service", baseline.Services.Select(s => s.State), current.Services.Select(s => s.State));
        else AddServiceChanges(changes, baseline.Services, current.Services);
        AddProcessChanges(changes, baseline.Processes, current.Processes);
        AddSecurityChange(changes, "firewall.active", baseline.Security.HasActiveFirewall, current.Security.HasActiveFirewall);
        AddSecurityChange(changes, "firewall.verified", baseline.Security.ProtectionVerified, current.Security.ProtectionVerified);
        AddSecurityChange(changes, "firewall.known", baseline.Security.FirewallStatusKnown, current.Security.FirewallStatusKnown);
        if (baseline.CollectionWarnings.Count != current.CollectionWarnings.Count)
            changes.Add(new("coverage", "collectionWarnings", "changed", $"Collection warning count changed from {baseline.CollectionWarnings.Count} to {current.CollectionWarnings.Count}."));
        foreach (var tool in current.Tooling?.Tools ?? Array.Empty<ToolInfo>())
        {
            var old = baseline.Tooling?.Tools.FirstOrDefault(t => t.Name.Equals(tool.Name, StringComparison.OrdinalIgnoreCase));
            if (old is not null && (old.Security != tool.Security || old.Available != tool.Available))
                changes.Add(new("security", tool.Name, "changed", "Tool availability or trust changed."));
        }


        // Thresholds highlight operationally meaningful drift while ignoring normal sampling noise.
        // Los umbrales resaltan cambios operativos relevantes e ignoran el ruido normal de las muestras.
        var significant = changes.Count > 0 || metrics.Any(metric =>
            (metric.Name.Contains("cpu", StringComparison.OrdinalIgnoreCase) && Math.Abs(metric.Delta) >= 20) ||
            (metric.Name.Contains("memory", StringComparison.OrdinalIgnoreCase) && Math.Abs(metric.Delta) >= 15) ||
            (metric.Name.Contains("disk", StringComparison.OrdinalIgnoreCase) && Math.Abs(metric.Delta) >= 10));

        return new DiffReport(baseline.Host.Hostname, current.Host.Hostname, baseline.CollectedAtUtc, current.CollectedAtUtc, significant, metrics, changes, warnings);
    }

    private static void AddCountChanges(List<EntityDelta> changes, string category, IEnumerable<string> baseline, IEnumerable<string> current)
    {
        var before = baseline.GroupBy(v => v, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);
        var after = current.GroupBy(v => v, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);
        foreach (var key in before.Keys.Union(after.Keys, StringComparer.OrdinalIgnoreCase))
        {
            before.TryGetValue(key, out var oldCount);
            after.TryGetValue(key, out var newCount);
            if (oldCount != newCount) changes.Add(new(category, key, "changed", $"Observed count changed from {oldCount} to {newCount}; identities were redacted."));
        }
    }

    private static void AddSecurityChange(List<EntityDelta> changes, string name, bool before, bool after)
    {
        if (before != after) changes.Add(new("security", name, "changed", $"State changed from {before} to {after}."));
    }

    private static MetricDelta Delta(string name, double baseline, double current, string unit) =>
        new(name, Math.Round(baseline, 2), Math.Round(current, 2), Math.Round(current - baseline, 2), unit);

    private static string Key(ListenerInfo listener) => $"{listener.Protocol}|{listener.LocalAddress}";

    private static void AddSetChanges(List<EntityDelta> changes, string category, IEnumerable<string> baseline, IEnumerable<string> current, string detail)
    {
        var before = baseline.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var after = current.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var added in after.Except(before, StringComparer.OrdinalIgnoreCase).OrderBy(value => value))
            changes.Add(new(category, added, "added", detail));
        foreach (var removed in before.Except(after, StringComparer.OrdinalIgnoreCase).OrderBy(value => value))
            changes.Add(new(category, removed, "removed", detail));
    }

    private static void AddServiceChanges(List<EntityDelta> changes, IReadOnlyList<ServiceInfo> baseline, IReadOnlyList<ServiceInfo> current)
    {
        var before = baseline.ToDictionary(service => service.Name, StringComparer.OrdinalIgnoreCase);
        var after = current.ToDictionary(service => service.Name, StringComparer.OrdinalIgnoreCase);
        foreach (var service in after.Values)
        {
            if (!before.TryGetValue(service.Name, out var old))
                changes.Add(new("service", service.Name, "added", $"State is {service.State}."));
            else if (!old.State.Equals(service.State, StringComparison.OrdinalIgnoreCase))
                changes.Add(new("service", service.Name, "changed", $"State changed from {old.State} to {service.State}."));
        }
        foreach (var service in before.Values.Where(service => !after.ContainsKey(service.Name)))
            changes.Add(new("service", service.Name, "removed", $"Baseline state was {service.State}."));
    }

    private static void AddProcessChanges(List<EntityDelta> changes, IReadOnlyList<ProcessInfo> baseline, IReadOnlyList<ProcessInfo> current)
    {
        var before = baseline.GroupBy(process => process.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(group => group.Key, group => group.Count(), StringComparer.OrdinalIgnoreCase);
        var after = current.GroupBy(process => process.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(group => group.Key, group => group.Count(), StringComparer.OrdinalIgnoreCase);
        foreach (var name in after.Keys.Union(before.Keys, StringComparer.OrdinalIgnoreCase).OrderBy(name => name, StringComparer.OrdinalIgnoreCase))
        {
            before.TryGetValue(name, out var oldCount);
            after.TryGetValue(name, out var newCount);
            if (oldCount != newCount)
                changes.Add(new("process", name, "changed", $"Process count changed from {oldCount} to {newCount}."));
        }
    }
}

