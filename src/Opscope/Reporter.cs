using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Opscope;

internal static class Reporter
{
    private static readonly string[] BundleFiles = ["snapshot.json", "findings.json", "README.txt", "manifest.json"];
    private static readonly IReadOnlyList<string> RedactedAddresses = ["[redacted-addresses]"];
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        // Bound nested input/output depth so malformed baselines cannot trigger unbounded parsing work.
        // Limitamos la profundidad para que una línea base malformada no provoque trabajo ilimitado.
        MaxDepth = 64,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public static string ToJson(Snapshot snapshot, bool redact = false)
    {
        return JsonSerializer.Serialize(redact ? Redact(snapshot) : snapshot, JsonOptions);
    }

    public static Snapshot RedactForOutput(Snapshot snapshot) => Redact(snapshot);

    public static DiffReport RedactForOutput(DiffReport report) => report with
    {
        BaselineHost = RedactText(report.BaselineHost),
        CurrentHost = RedactText(report.CurrentHost),
        Metrics = report.Metrics.Select(metric => metric with { Name = RedactText(metric.Name) }).ToArray(),
        Changes = report.Changes.Select(change => change with
        {
            Identity = RedactText(change.Identity),
            Details = RedactText(change.Details)
        }).ToArray()
    };

    public static ToolingPosture RedactForOutput(ToolingPosture tooling) =>
        tooling with { Tools = tooling.Tools.Select(tool => tool with { Path = null }).ToArray() };

    public static string SafeDisplay(string? value) => new((value ?? string.Empty).Select(character => char.IsControl(character) ? ' ' : character).ToArray());

    public static string ToJson(DiffReport report) => JsonSerializer.Serialize(report, JsonOptions);

    public static string ToJson(ToolingPosture tooling, bool redact = false) =>
        JsonSerializer.Serialize(redact ? RedactForOutput(tooling) : tooling, JsonOptions);

    public static Snapshot ParseSnapshot(string json)
    {
        var snapshot = JsonSerializer.Deserialize<Snapshot>(json, JsonOptions)
            ?? throw new InvalidDataException("Snapshot JSON was empty or invalid.");
        ValidateSnapshot(snapshot);
        return snapshot;
    }

    public static string ToDoctorJson(Snapshot snapshot, bool redact = false)
    {
        var view = redact ? Redact(snapshot) : snapshot;
        var result = new
        {
            status = view.Findings.Count == 0 && view.CollectionWarnings.Count == 0
                ? "ok"
                : HighestSeverity(view.Findings).ToString().ToLowerInvariant(),
            collectedAtUtc = view.CollectedAtUtc,
            host = view.Host.Hostname,
            findings = view.Findings,
            collectionWarnings = view.CollectionWarnings
        };
        return JsonSerializer.Serialize(result, JsonOptions);
    }

    public static async Task WriteJsonAsync(string path, Snapshot snapshot, bool redact, CancellationToken cancellationToken)
    {
        await WriteTextAtomicallyAsync(path, ToJson(snapshot, redact), cancellationToken);
    }

    public static async Task WriteTextAtomicallyAsync(string path, string content, CancellationToken cancellationToken)
    {
        // Write beside the destination and rename only after completion, preventing partial evidence files.
        // Escribimos junto al destino y renombramos al terminar para evitar archivos de evidencia incompletos.
        EnsureParent(path);
        var fullPath = Path.GetFullPath(path);
        var temporaryPath = $"{fullPath}.{Guid.NewGuid():N}.tmp";
        try
        {
            await using (var stream = CommandRunner.CreatePrivateFile(temporaryPath))
            await using (var writer = new StreamWriter(stream, new UTF8Encoding(false), 8192, leaveOpen: false))
            {
                await writer.WriteAsync(content.AsMemory(), cancellationToken);
            }
            File.Move(temporaryPath, fullPath, overwrite: true);
        }
        finally
        {
            try
            {
                if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
            }
            catch
            {
                // Cleanup is best effort; the primary write result is already known.
            }
        }
    }

    public static async Task<string> WriteBundleAsync(string path, Snapshot snapshot, CancellationToken cancellationToken)
    {
        // Bundles are always redacted before archiving because they are intended for incident handoff.
        // Los bundles siempre se redactan antes de archivarse porque se comparten durante incidentes.
        EnsureParent(path);
        var fullPath = Path.GetFullPath(path);
        var temporaryPath = $"{fullPath}.{Guid.NewGuid():N}.tmp";
        var redactedSnapshot = Redact(snapshot);
        try
        {
            await using (var file = CommandRunner.CreatePrivateFile(temporaryPath))
            using (var archive = new ZipArchive(file, ZipArchiveMode.Create))
            {
                await WriteEntryAsync(archive, "snapshot.json", ToJson(redactedSnapshot), cancellationToken);
                await WriteEntryAsync(archive, "findings.json", JsonSerializer.Serialize(redactedSnapshot.Findings, JsonOptions), cancellationToken);
                await WriteEntryAsync(archive, "README.txt", BuildBundleReadme(snapshot), cancellationToken);
                await WriteEntryAsync(archive, "manifest.json", JsonSerializer.Serialize(new
                {
                    format = "opscope-support-bundle/v1",
                    generatedAtUtc = DateTimeOffset.UtcNow,
                    redacted = true,
                    files = BundleFiles
                }, JsonOptions), cancellationToken);
            }
            File.Move(temporaryPath, fullPath, overwrite: true);
            return fullPath;
        }
        finally
        {
            try
            {
                if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
            }
            catch
            {
                // Cleanup is best effort.
            }
        }
    }

    public static void PrintSnapshot(Snapshot snapshot, bool includeDetails = true)
    {
        Console.WriteLine($"opscope snapshot  {snapshot.CollectedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($"Host       {Clean(snapshot.Host.Hostname)} ({Clean(snapshot.Host.Platform)}, {Clean(snapshot.Host.Architecture)})");
        Console.WriteLine($"OS         {Clean(snapshot.Host.OsDescription)}");
        Console.WriteLine($"Runtime    {Clean(snapshot.Host.Runtime)} | kernel {Clean(snapshot.Host.Kernel)}");
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
        var toolingSummary = snapshot.Tooling is null ? "unknown" : $"{snapshot.Tooling.Tools.Count(tool => tool.Available)}/{snapshot.Tooling.Tools.Count} available";
        Console.WriteLine($"Tooling    {toolingSummary}");

        if (!includeDetails) return;
        Console.WriteLine();
        if (snapshot.Disks.Count > 0)
        {
            Console.WriteLine("Disks");
            foreach (var disk in snapshot.Disks)
            {
                Console.WriteLine($"  {Clean(disk.Root),-18} {disk.UsedPercent,6:F1}% used  {FormatBytes(disk.AvailableBytes),12} free  {Clean(disk.FileSystem)}");
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
        Console.WriteLine($"opscope diff | {Clean(report.BaselineHost)} -> {Clean(report.CurrentHost)}");
        Console.WriteLine($"Baseline   {report.BaselineCollectedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($"Current    {report.CurrentCollectedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($"Status     {(report.Significant ? "CHANGED" : "NO SIGNIFICANT CHANGE")}");
        Console.WriteLine();
        Console.WriteLine("Metrics");
        foreach (var metric in report.Metrics)
            Console.WriteLine($"  {Clean(metric.Name),-32} {metric.Baseline,8:F2} -> {metric.Current,8:F2}  ({metric.Delta:+0.00;-0.00;0.00} {Clean(metric.Unit)})");
        Console.WriteLine();
        Console.WriteLine("Changes");
        if (report.Changes.Count == 0) Console.WriteLine("  none");
        foreach (var change in report.Changes.Take(100))
            Console.WriteLine($"  [{Clean(change.Change).ToUpperInvariant(),-7}] {Clean(change.Category),-9} {Trim(change.Identity, 44)} — {Clean(change.Details)}");
        if (report.Changes.Count > 100) Console.WriteLine($"  ... {report.Changes.Count - 100} more changes");
    }

    public static void PrintTools(ToolingPosture tooling)
    {
        Console.WriteLine("opscope tools | trusted executable and coverage inventory");
        Console.WriteLine();
        Console.WriteLine("  NAME             ROLE        STATUS          SECURITY          PATH");
        foreach (var tool in tooling.Tools)
        {
            var status = tool.Available ? "available" : "missing";
            var path = tool.Path is null ? "-" : SafeDisplay(tool.Path);
            Console.WriteLine($"  {SafeDisplay(tool.Name),-16} {SafeDisplay(tool.Role),-11} {status,-15} {SafeDisplay(tool.Security),-17} {path}");
        }
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
            Console.WriteLine($"  [{finding.Severity.ToString().ToUpperInvariant(),-8}] {Clean(finding.Code)}: {Clean(finding.Title)} — {Clean(finding.Detail)}");
        foreach (var warning in warnings)
            Console.WriteLine($"  [COLLECT ] {Clean(warning)}");
    }

    public static void PrintDashboard(Snapshot snapshot)
    {
        Console.WriteLine($"opscope watch | {Clean(snapshot.Host.Hostname)} | {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
        Console.WriteLine(new string('─', 76));
        Console.WriteLine($"CPU {snapshot.CpuUsedPercent,6:F1}%   MEM {snapshot.Memory.UsedPercent,6:F1}%   " +
                          $"DISKS {snapshot.Disks.Count(d => d.IsReady && d.UsedPercent >= 85),2} hot   " +
                          $"FINDINGS {snapshot.Findings.Count,2}   " +
                          $"LISTENERS {snapshot.Listeners.Count,2}");
        Console.WriteLine();
        foreach (var finding in snapshot.Findings.Take(8))
            Console.WriteLine($"{finding.Severity.ToString().ToUpperInvariant(),-8} {Clean(finding.Code),-22} {Trim(finding.Title, 42)}");
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
        "collection metadata. Command lines are omitted; user, host, network and path\n" +
        "identifiers are redacted where possible. Handle the bundle as sensitive evidence.\n\n" +
        "The collector is read-only and does not modify services, processes, firewall\n" +
        "rules, files or network configuration.\n";

    private static Snapshot Redact(Snapshot snapshot)
    {
        var host = snapshot.Host with
        {
            Hostname = "[redacted-host]",
            OsDescription = RedactText(snapshot.Host.OsDescription),
            Runtime = RedactText(snapshot.Host.Runtime),
            Kernel = RedactText(snapshot.Host.Kernel),
            CurrentUser = "[redacted-user]"
        };
        var disks = snapshot.Disks.Select(disk => disk with { Name = "[redacted-disk]", Root = "[redacted-root]" }).ToArray();
        var network = snapshot.Network.Select(adapter => adapter with
        {
            Name = "[redacted-adapter]",
            Description = "[redacted-adapter]",
            Addresses = RedactedAddresses
        }).ToArray();
        var processes = snapshot.Processes.Select(process => process with
        {
            User = "[redacted-user]",
            CommandLine = null
        }).ToArray();
        var listeners = snapshot.Listeners.Select(listener => listener with
        {
            LocalAddress = "[redacted-address]",
            Process = RedactText(listener.Process)
        }).ToArray();
        var services = snapshot.Services.Select(service => service with
        {
            Name = "[redacted-service]",
            Description = null
        }).ToArray();
        var findings = snapshot.Findings.Select(finding => finding with
        {
            Title = RedactText(finding.Title),
            Detail = RedactText(finding.Detail),
            Recommendation = RedactText(finding.Recommendation)
        }).ToArray();
        var tooling = snapshot.Tooling is null ? null : snapshot.Tooling with
        {
            Tools = snapshot.Tooling.Tools.Select(tool => tool with { Path = null }).ToArray()
        };
        return snapshot with
        {
            Host = host,
            Disks = disks,
            Network = network,
            Processes = processes,
            Listeners = listeners,
            Services = services,
            Tooling = tooling,
            Findings = findings,
            CollectionWarnings = Array.Empty<string>()
        };
    }

    private static string RedactText(string value)
    {
        foreach (var replacement in new[] { Environment.UserName, Environment.MachineName }.Where(text => !string.IsNullOrWhiteSpace(text)))
            value = value.Replace(replacement, "[redacted]", StringComparison.OrdinalIgnoreCase);
        value = Regex.Replace(value, @"(?i)([A-Z]:\\Users\\)[^\\\s]+", "$1[redacted]");
        value = Regex.Replace(value, @"(?i)(?<![\w])/(?:home|srv|opt|var|etc|tmp|mnt|run|root|usr)/[^\s,;]+", "[redacted-path]");
        value = Regex.Replace(value, @"(?i)(?<![\w])(?:[A-Z]:\\|\\\\)[^\s,;]+", "[redacted-path]");
        value = Regex.Replace(value, @"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key)\s*[=:]\s*[^\s,;]+", "$1=[redacted-secret]");
        value = Regex.Replace(value, @"(?<![\w])(?:\[?[0-9A-Fa-f:.%]+\]?)(?![\w])", match =>
        {
            var token = match.Value.Trim('[', ']');
            return IPAddress.TryParse(token.Split('%')[0], out _) ? "[redacted-address]" : match.Value;
        });
        return value;
    }

    private static void ValidateSnapshot(Snapshot snapshot)
    {
        if (snapshot.Host is null || snapshot.Memory is null || snapshot.Security is null ||
            snapshot.Disks is null || snapshot.Network is null || snapshot.Processes is null ||
            snapshot.Listeners is null || snapshot.Services is null || snapshot.Findings is null ||
            snapshot.CollectionWarnings is null || snapshot.Tooling is { Tools: null })
            throw new InvalidDataException("Snapshot is missing required collections or metadata.");

        EnsureCount("disks", snapshot.Disks.Count, 1024);
        EnsureCount("network adapters", snapshot.Network.Count, 4096);
        EnsureCount("processes", snapshot.Processes.Count, 1000);
        EnsureCount("listeners", snapshot.Listeners.Count, 10000);
        EnsureCount("services", snapshot.Services.Count, 10000);
        EnsureCount("findings", snapshot.Findings.Count, 1000);
        EnsureCount("collection warnings", snapshot.CollectionWarnings.Count, 1000);
        if (snapshot.Tooling is not null) EnsureCount("tools", snapshot.Tooling.Tools.Count, 64);

        if (snapshot.Disks.Any(disk => disk is null) ||
            snapshot.Network.Any(adapter => adapter is null) ||
            snapshot.Processes.Any(process => process is null) ||
            snapshot.Listeners.Any(listener => listener is null) ||
            snapshot.Services.Any(service => service is null) ||
            snapshot.Findings.Any(finding => finding is null) ||
            snapshot.CollectionWarnings.Any(warning => warning is null))
            throw new InvalidDataException("Snapshot contains null collection entries.");
    }

    private static void EnsureCount(string name, int count, int maximum)
    {
        if (count > maximum) throw new InvalidDataException($"Snapshot contains too many {name}; maximum is {maximum}.");
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

    private static string Clean(string? value) => SafeDisplay(value);

    private static string Trim(string? value, int length)
    {
        var clean = Clean(value);
        return string.IsNullOrWhiteSpace(clean) ? "-" : clean.Length <= length ? clean : clean[..(length - 1)] + "…";
    }
}

