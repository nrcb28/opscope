using System.IO.Compression;
using System.Text;
using System.Text.Json;

namespace Opscope;

internal static class Reporter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public static string ToJson(Snapshot snapshot, bool redact = false)
    {
        return JsonSerializer.Serialize(redact ? Redact(snapshot) : snapshot, JsonOptions);
    }

    public static string ToJson(DiffReport report) => JsonSerializer.Serialize(report, JsonOptions);

    public static Snapshot ParseSnapshot(string json)
    {
        return JsonSerializer.Deserialize<Snapshot>(json, JsonOptions)
            ?? throw new InvalidDataException("Snapshot JSON was empty or invalid.");
    }

    public static string ToDoctorJson(Snapshot snapshot)
    {
        var result = new
        {
            status = snapshot.Findings.Count == 0 && snapshot.CollectionWarnings.Count == 0
                ? "ok"
                : HighestSeverity(snapshot.Findings).ToString().ToLowerInvariant(),
            collectedAtUtc = snapshot.CollectedAtUtc,
            host = snapshot.Host.Hostname,
            findings = snapshot.Findings,
            collectionWarnings = snapshot.CollectionWarnings
        };
        return JsonSerializer.Serialize(result, JsonOptions);
    }

    public static async Task WriteJsonAsync(string path, Snapshot snapshot, bool redact, CancellationToken cancellationToken)
    {
        EnsureParent(path);
        await File.WriteAllTextAsync(path, ToJson(snapshot, redact), Encoding.UTF8, cancellationToken);
    }

    public static async Task<string> WriteBundleAsync(string path, Snapshot snapshot, CancellationToken cancellationToken)
    {
        EnsureParent(path);
        await using var file = File.Create(path);
        using var archive = new ZipArchive(file, ZipArchiveMode.Create);
        await WriteEntryAsync(archive, "snapshot.json", ToJson(snapshot, redact: true), cancellationToken);
        await WriteEntryAsync(archive, "findings.json", JsonSerializer.Serialize(snapshot.Findings, JsonOptions), cancellationToken);
        await WriteEntryAsync(archive, "README.txt", BuildBundleReadme(snapshot), cancellationToken);
        await WriteEntryAsync(archive, "manifest.json", JsonSerializer.Serialize(new
        {
            format = "opscope-support-bundle/v1",
            generatedAtUtc = DateTimeOffset.UtcNow,
            redacted = true,
            files = new[] { "snapshot.json", "findings.json", "README.txt", "manifest.json" }
        }, JsonOptions), cancellationToken);
        return Path.GetFullPath(path);
    }

    public static void PrintSnapshot(Snapshot snapshot, bool includeDetails = true)
    {
        Console.WriteLine($"opscope snapshot  {snapshot.CollectedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($"Host       {snapshot.Host.Hostname} ({snapshot.Host.Platform}, {snapshot.Host.Architecture})");
        Console.WriteLine($"OS         {snapshot.Host.OsDescription}");
        Console.WriteLine($"Runtime    {snapshot.Host.Runtime} | kernel {snapshot.Host.Kernel}");
        Console.WriteLine($"Uptime     {FormatDuration(snapshot.Host.Uptime)} | boot {snapshot.Host.BootTimeUtc:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($"Privilege  {(snapshot.Host.IsElevated ? "elevated" : "standard")} | CPUs {snapshot.Host.ProcessorCount}");
        Console.WriteLine();
        Console.WriteLine($"Health     {HealthLabel(snapshot)}");
        Console.WriteLine($"CPU        {snapshot.CpuUsedPercent,6:F1}%");
        Console.WriteLine($"Memory     {snapshot.Memory.UsedPercent,6:F1}%  ({FormatBytes(snapshot.Memory.UsedBytes)} / {FormatBytes(snapshot.Memory.TotalBytes)})");
        Console.WriteLine($"Network    {snapshot.Network.Count(a => a.Status.Equals("Up", StringComparison.OrdinalIgnoreCase))} active adapters | {snapshot.Listeners.Count} listeners");
        Console.WriteLine($"Processes  {snapshot.Processes.Count} top processes by working set | Services {snapshot.Services.Count}");
        var firewall = snapshot.Security is null ? "unknown" : snapshot.Security.FirewallStatusKnown ? (snapshot.Security.HasActiveFirewall ? "active" : "inactive") : "unknown";
        Console.WriteLine($"Security   firewall {firewall} | wildcard listeners {snapshot.Security?.ExposedListeners ?? 0}");

        if (!includeDetails) return;
        Console.WriteLine();
        if (snapshot.Disks.Count > 0)
        {
            Console.WriteLine("Disks");
            foreach (var disk in snapshot.Disks)
            {
                Console.WriteLine($"  {disk.Root,-18} {disk.UsedPercent,6:F1}% used  {FormatBytes(disk.AvailableBytes),12} free  {disk.FileSystem}");
            }
        }

        if (snapshot.Processes.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("Top processes by memory");
            Console.WriteLine("  PID      MEMORY    CPU TIME  NAME");
            foreach (var process in snapshot.Processes.Take(10))
                Console.WriteLine($"  {process.Id,-8} {process.WorkingSetMb,7:F1} MB  {FormatDuration(process.CpuTime),-9} {Trim(process.Name, 50)}");
        }

        PrintFindings(snapshot.Findings, snapshot.CollectionWarnings);
        Console.WriteLine();
        Console.WriteLine($"Collected in {snapshot.CollectionDuration.TotalMilliseconds:F0} ms");
    }

    public static void PrintDiff(DiffReport report)
    {
        Console.WriteLine($"opscope diff | {report.BaselineHost} -> {report.CurrentHost}");
        Console.WriteLine($"Baseline   {report.BaselineCollectedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($"Current    {report.CurrentCollectedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($"Status     {(report.Significant ? "CHANGED" : "NO SIGNIFICANT CHANGE")}");
        Console.WriteLine();
        Console.WriteLine("Metrics");
        foreach (var metric in report.Metrics)
            Console.WriteLine($"  {metric.Name,-32} {metric.Baseline,8:F2} -> {metric.Current,8:F2}  ({metric.Delta:+0.00;-0.00;0.00} {metric.Unit})");
        Console.WriteLine();
        Console.WriteLine("Changes");
        if (report.Changes.Count == 0) Console.WriteLine("  none");
        foreach (var change in report.Changes.Take(100))
            Console.WriteLine($"  [{change.Change.ToUpperInvariant(),-7}] {change.Category,-9} {Trim(change.Identity, 44)} — {change.Details}");
        if (report.Changes.Count > 100) Console.WriteLine($"  ... {report.Changes.Count - 100} more changes");
    }

    public static void PrintFindings(IReadOnlyList<Finding> findings, IReadOnlyList<string> warnings)
    {
        if (findings.Count == 0 && warnings.Count == 0)
        {
            Console.WriteLine();
            Console.WriteLine("Findings   none");
            return;
        }

        Console.WriteLine();
        Console.WriteLine("Findings");
        foreach (var finding in findings)
            Console.WriteLine($"  [{finding.Severity.ToString().ToUpperInvariant(),-8}] {finding.Code}: {finding.Title} — {finding.Detail}");
        foreach (var warning in warnings)
            Console.WriteLine($"  [COLLECT ] {warning}");
    }

    public static void PrintDashboard(Snapshot snapshot)
    {
        Console.WriteLine($"opscope watch | {snapshot.Host.Hostname} | {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
        Console.WriteLine(new string('─', 76));
        Console.WriteLine($"CPU {snapshot.CpuUsedPercent,6:F1}%   MEM {snapshot.Memory.UsedPercent,6:F1}%   " +
                          $"DISKS {snapshot.Disks.Count(d => d.IsReady && d.UsedPercent >= 85),2} hot   " +
                          $"FINDINGS {snapshot.Findings.Count,2}   " +
                          $"LISTENERS {snapshot.Listeners.Count,2}");
        Console.WriteLine();
        foreach (var finding in snapshot.Findings.Take(8))
            Console.WriteLine($"{finding.Severity.ToString().ToUpperInvariant(),-8} {finding.Code,-22} {Trim(finding.Title, 42)}");
        if (snapshot.Findings.Count == 0) Console.WriteLine("OK       no actionable findings");
        Console.WriteLine();
        Console.WriteLine("Top memory consumers");
        foreach (var process in snapshot.Processes.Take(5))
            Console.WriteLine($"{process.Id,6} {process.WorkingSetMb,8:F1} MB  {Trim(process.Name, 42)}");
        Console.WriteLine();
        Console.WriteLine("Ctrl+C to stop");
    }

    public static int ExitCode(Snapshot snapshot) => snapshot.Findings.Any(f => f.Severity is FindingSeverity.Warning or FindingSeverity.Critical) ? 1 : 0;

    private static FindingSeverity HighestSeverity(IReadOnlyList<Finding> findings) =>
        findings.Any(f => f.Severity == FindingSeverity.Critical) ? FindingSeverity.Critical :
        findings.Any(f => f.Severity == FindingSeverity.Warning) ? FindingSeverity.Warning : FindingSeverity.Info;

    private static string HealthLabel(Snapshot snapshot) => HighestSeverity(snapshot.Findings) switch
    {
        FindingSeverity.Critical => "CRITICAL",
        FindingSeverity.Warning => "DEGRADED",
        _ => "OK"
    };

    private static string BuildBundleReadme(Snapshot snapshot) =>
        "opscope support bundle\n\n" +
        "Format: opscope-support-bundle/v1\n" +
        $"Generated: {DateTimeOffset.UtcNow:O}\n" +
        "Host: redacted\n" +
        $"Collection duration: {snapshot.CollectionDuration.TotalMilliseconds:F0} ms\n\n" +
        "The bundle is redacted for handoff. It contains a host snapshot, findings, and\n" +
        "collection metadata. Command lines and user/host identifiers may still contain\n" +
        "operationally sensitive data from platform-specific tools; handle it accordingly.\n\n" +
        "The collector is read-only and does not modify services, processes, firewall\n" +
        "rules, files or network configuration.\n";

    private static Snapshot Redact(Snapshot snapshot)
    {
        var host = snapshot.Host with { Hostname = "[redacted-host]", CurrentUser = "[redacted-user]" };
        var processes = snapshot.Processes.Select(process => process with
        {
            User = "[redacted-user]",
            CommandLine = process.CommandLine is null ? null : RedactText(process.CommandLine)
        }).ToArray();
        return snapshot with { Host = host, Processes = processes };
    }

    private static string RedactText(string value)
    {
        var replacements = new[] { Environment.UserName, Environment.MachineName };
        foreach (var replacement in replacements.Where(text => !string.IsNullOrWhiteSpace(text)))
            value = value.Replace(replacement, "[redacted]", StringComparison.OrdinalIgnoreCase);
        return value;
    }

    private static async Task WriteEntryAsync(ZipArchive archive, string name, string content, CancellationToken cancellationToken)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.Fastest);
        await using var stream = entry.Open();
        await using var writer = new StreamWriter(stream, new UTF8Encoding(false));
        await writer.WriteAsync(content.AsMemory(), cancellationToken);
    }

    private static void EnsureParent(string path)
    {
        var full = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(full);
        if (!string.IsNullOrWhiteSpace(parent)) Directory.CreateDirectory(parent);
    }

    private static string FormatBytes(ulong bytes) => bytes switch
    {
        >= 1_000_000_000 => $"{bytes / 1_000_000_000d:F1} GB",
        >= 1_000_000 => $"{bytes / 1_000_000d:F1} MB",
        _ => $"{bytes / 1_000d:F1} KB"
    };

    private static string FormatBytes(long bytes) => FormatBytes(bytes < 0 ? 0UL : (ulong)bytes);

    private static string FormatDuration(TimeSpan value) => value.TotalDays >= 1 ? $"{value.TotalDays:F1}d" : value.TotalHours >= 1 ? $"{value.TotalHours:F1}h" : value.TotalMinutes >= 1 ? $"{value.TotalMinutes:F0}m" : $"{value.TotalSeconds:F1}s";

    private static string Trim(string? value, int length) => string.IsNullOrWhiteSpace(value) ? "-" : value.Length <= length ? value : value[..(length - 1)] + "…";
}


