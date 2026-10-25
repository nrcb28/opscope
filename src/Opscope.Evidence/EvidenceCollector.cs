using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32;

namespace Opscope.Evidence;

/// <summary>Bounded optional evidence collection. Commands and file locations are fixed, never supplied by packs.</summary>
public static partial class EvidenceCollector
{
    private const int MaximumRecords = 2048;
    private static readonly string[] DefaultGroups = ["logs", "packages", "users", "tasks", "certificates", "security", "environment"];
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(5);

    public static async Task<AnalysisReport> CollectAsync(Snapshot snapshot, IReadOnlyList<string> groups,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(groups);
        var selected = groups.Count == 0 || groups.Contains("all", StringComparer.OrdinalIgnoreCase)
            ? DefaultGroups : groups.Select(NormalizeGroup).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        foreach (var group in selected)
            if (!DefaultGroups.Contains(group, StringComparer.OrdinalIgnoreCase))
                throw new ArgumentException($"Unknown evidence group '{group}'. Supported: {string.Join(", ", DefaultGroups)}.", nameof(groups));

        var records = new List<EvidenceRecord>();
        var coverage = new List<CheckCoverage>();
        var warnings = new List<string>();
        var findings = new List<Finding>();
        var platform = OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsMacOS() ? "macos" : OperatingSystem.IsLinux() ? "linux" : "other";
        if (!string.Equals(platform, snapshot.Host.Platform, StringComparison.OrdinalIgnoreCase))
            return new AnalysisReport("evidence", DateTimeOffset.UtcNow, [], new EvidenceData([], []),
                ["Local evidence collection requires a snapshot from the current operating system; use offline analyzers for saved snapshots."]);

        foreach (var group in selected)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                switch (group)
                {
                    case "logs": await CollectLogsAsync(snapshot, records, warnings, cancellationToken); break;
                    case "packages": await CollectPackagesAsync(snapshot, records, warnings, cancellationToken); break;
                    case "users": await CollectUsersAsync(snapshot, records, warnings, cancellationToken); break;
                    case "tasks": await CollectTasksAsync(snapshot, records, warnings, cancellationToken); break;
                    case "certificates": CollectCertificates(snapshot, records, findings, warnings); break;
                    case "security": await CollectSecurityAsync(snapshot, records, coverage, findings, warnings, cancellationToken); break;
                    case "environment":
                        var environment = await PlatformInspector.CollectAsync(snapshot, cancellationToken);
                        records.Add(new EvidenceRecord("environment", "local-runtime", "collected", JsonSerializer.Serialize(environment.Data)));
                        warnings.AddRange(environment.Warnings ?? []);
                        break;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or InvalidOperationException)
            {
                warnings.Add(Safe(snapshot, $"{group}: {ex.Message}"));
                records.Add(new EvidenceRecord(group, "collector", "unavailable", "Collection incomplete; see warnings."));
            }
        }
        if (records.Count > MaximumRecords) warnings.Add($"Evidence limited to {MaximumRecords} records.");
        return new AnalysisReport("evidence", DateTimeOffset.UtcNow, findings,
            new EvidenceData(records.Take(MaximumRecords).ToArray(), coverage), warnings.Distinct().ToArray());
    }

    private static string NormalizeGroup(string group) => group.Trim().ToLowerInvariant() switch
    {
        "scheduledtasks" or "scheduled-tasks" or "cron" => "tasks",
        "certs" => "certificates",
        "accounts" => "users",
        var value => value
    };

    private static async Task CollectLogsAsync(Snapshot snapshot, List<EvidenceRecord> records, List<string> warnings, CancellationToken ct)
    {
        if (OperatingSystem.IsLinux())
        {
            var result = await RunAsync(snapshot, "journalctl", ["--no-pager", "--output=json", "--since=-24h", "--priority=err", "--lines=200"], warnings, ct);
            if (result.ExitCode != 0) { Unavailable(records, "logs", "journalctl"); return; }
            foreach (var line in Lines(result.StandardOutput, 200))
            {
                try
                {
                    using var document = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 16 });
                    var root = document.RootElement;
                    var message = root.TryGetProperty("MESSAGE", out var item) ? item.ToString() : "No textual message";
                    DateTimeOffset? timestamp = null;
                    if (root.TryGetProperty("__REALTIME_TIMESTAMP", out var time) && long.TryParse(time.ToString(), CultureInfo.InvariantCulture, out var microseconds))
                    {
                        try { timestamp = DateTimeOffset.FromUnixTimeMilliseconds(microseconds / 1000); }
                        catch (ArgumentOutOfRangeException) { warnings.Add("journalctl event timestamp outside supported range."); }
                    }
                    records.Add(new EvidenceRecord("logs", "journalctl", "collected", Safe(snapshot, message), timestamp));
                }
                catch (JsonException) { warnings.Add("Skipped malformed journalctl JSON record."); }
            }
            if (!records.Any(record => record.Group == "logs")) records.Add(new EvidenceRecord("logs", "journalctl", "collected", "No error entries returned within the last 24 hours; journal access may be restricted."));
        }
        else if (OperatingSystem.IsWindows())
        {
            foreach (var log in new[] { "System", "Application" })
            {
                var result = await RunAsync(snapshot, "wevtutil.exe", ["qe", log, "/q:*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= 86400000]]]", "/c:100", "/f:xml", "/rd:true"], warnings, ct);
                if (result.ExitCode != 0) { Unavailable(records, "logs", $"EventLog:{log}"); continue; }
                try
                {
                    using var reader = XmlReader.Create(new StringReader("<Events>" + result.StandardOutput + "</Events>"), new XmlReaderSettings
                    { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 1024 * 1024 });
                    var document = XDocument.Load(reader);
                    foreach (var entry in document.Descendants().Where(item => item.Name.LocalName == "Event").Take(100))
                    {
                        var time = entry.Descendants().FirstOrDefault(item => item.Name.LocalName == "TimeCreated")?.Attribute("SystemTime")?.Value;
                        var timestamp = DateTimeOffset.TryParse(time, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed) ? parsed : (DateTimeOffset?)null;
                        var message = string.Join(" | ", entry.Descendants().Where(item => item.Name.LocalName is "Data" or "EventID").Select(item => item.Value));
                        records.Add(new EvidenceRecord("logs", $"EventLog:{log}", "collected", Safe(snapshot, message), timestamp));
                    }
                }
                catch (XmlException) { warnings.Add($"Could not parse Event Log XML for {log}."); }
            }
        }
        else if (OperatingSystem.IsMacOS())
        {
            // The unified log may contain private data. The fixed invocation uses its existing privacy defaults.
            var result = await RunAsync(snapshot, "log", ["show", "--last", "1h", "--style", "ndjson", "--predicate", "messageType == error", "--info"], warnings, ct);
            if (result.ExitCode != 0) { Unavailable(records, "logs", "macOS-unified-log"); return; }
            foreach (var line in Lines(result.StandardOutput, 200))
            {
                try
                {
                    using var document = JsonDocument.Parse(line);
                    var root = document.RootElement;
                    var message = root.TryGetProperty("eventMessage", out var item) ? item.ToString() : "No textual message";
                    var timestamp = root.TryGetProperty("timestamp", out var time) && DateTimeOffset.TryParse(time.ToString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed) ? parsed : (DateTimeOffset?)null;
                    records.Add(new EvidenceRecord("logs", "macOS-unified-log", "collected", Safe(snapshot, message), timestamp));
                }
                catch (JsonException) { warnings.Add("Skipped malformed macOS log record."); }
            }
        }
        else Unavailable(records, "logs", "unsupported-platform");
    }

    private static async Task CollectPackagesAsync(Snapshot snapshot, List<EvidenceRecord> records, List<string> warnings, CancellationToken ct)
    {
        if (OperatingSystem.IsWindows())
        {
            CollectWindowsPackages(snapshot, records, warnings);
            return;
        }
        var tool = OperatingSystem.IsMacOS() ? "pkgutil" : "dpkg-query";
        string[] arguments = OperatingSystem.IsMacOS() ? ["--pkgs"] : ["--show", "--showformat=${binary:Package}\t${Version}\n"];
        var result = await RunAsync(snapshot, tool, arguments, warnings, ct, warnOnFailure: OperatingSystem.IsMacOS());
        if (result.ExitCode != 0 && OperatingSystem.IsLinux())
        {
            tool = "rpm";
            result = await RunAsync(snapshot, tool, ["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], warnings, ct);
        }
        if (result.ExitCode == 0) AddLines(snapshot, records, "packages", tool, result.StandardOutput, 1500);
        else Unavailable(records, "packages", tool);
    }

    private static void CollectWindowsPackages(Snapshot snapshot, List<EvidenceRecord> records, List<string> warnings)
    {
        if (!OperatingSystem.IsWindows()) return;
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var uninstall = hive.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", writable: false);
                if (uninstall is null) continue;
                foreach (var name in uninstall.GetSubKeyNames().Take(1000))
                {
                    using var entry = uninstall.OpenSubKey(name, writable: false);
                    if (entry?.GetValue("DisplayName") is string displayName)
                        records.Add(new EvidenceRecord("packages", $"registry:{view}", "collected", Safe(snapshot, $"{displayName}\t{entry.GetValue("DisplayVersion")}")));
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
            { warnings.Add(Safe(snapshot, $"Package registry {view}: {ex.Message}")); }
        }
        warnings.Add("Windows package inventory covers machine uninstall registry entries; portable apps, per-user apps and some Store packages may be absent.");
    }

    private static async Task CollectUsersAsync(Snapshot snapshot, List<EvidenceRecord> records, List<string> warnings, CancellationToken ct)
    {
        if (OperatingSystem.IsWindows())
        {
            var users = await RunAsync(snapshot, "net.exe", ["user"], warnings, ct);
            if (users.ExitCode == 0) AddAccountLines(snapshot, records, "net-user", users.StandardOutput, 200); else Unavailable(records, "users", "net-user");
            var administrators = "Administrators";
            try
            {
                var account = new System.Security.Principal.SecurityIdentifier("S-1-5-32-544").Translate(typeof(System.Security.Principal.NTAccount)).Value;
                administrators = account[(account.LastIndexOf('\\') + 1)..];
            }
            catch (System.Security.Principal.IdentityNotMappedException) { warnings.Add("Could not resolve localized Administrators group name."); }
            var admins = await RunAsync(snapshot, "net.exe", ["localgroup", administrators], warnings, ct);
            if (admins.ExitCode == 0) AddAccountLines(snapshot, records, "local-administrators", admins.StandardOutput, 200); else Unavailable(records, "users", "local-administrators");
        }
        else if (OperatingSystem.IsLinux())
        {
            // /etc/passwd has account metadata, not password hashes. Never open /etc/shadow.
            var accounts = (ReadFixedFile("/etc/passwd", warnings) ?? string.Empty).Split('\n')
                .Select(line => line.Split(':')).Where(fields => fields.Length >= 7).Take(500).ToArray();
            var accountNames = accounts.Select(fields => fields[0]).Where(name => name.Length > 0).ToArray();
            foreach (var fields in accounts)
                records.Add(new EvidenceRecord("users", "local-account-metadata", "collected", $"Local account UID={fields[2]}, GID={fields[3]}; no password value read.", Metadata:
                    new Dictionary<string, string> { ["user"] = fields[0], ["home"] = fields[5], ["loginShell"] = fields[6] }));
            foreach (var line in ReadFixedFile("/etc/group", warnings)?.Split('\n') ?? [])
            {
                var fields = line.Split(':');
                if (fields.Length >= 4 && fields[0] is "sudo" or "wheel" or "admin")
                    records.Add(new EvidenceRecord("users", "privileged-groups", "collected", $"Privileged group: {fields[0]}.", Metadata: new Dictionary<string, string> { ["user"] = fields[3] }));
            }
            var firstSudoers = records.Count;
            AddFixedFile(snapshot, records, warnings, "users", "/etc/sudoers", 100);
            AddDirectoryFiles(snapshot, records, warnings, "users", "/etc/sudoers.d", 16, 40);
            for (var index = firstSudoers; index < records.Count; index++)
                records[index] = records[index] with { Summary = Reporter.RedactEvidenceText(records[index].Summary, accountNames) };
        }
        else if (OperatingSystem.IsMacOS())
        {
            foreach (var args in new[] { new[] { ".", "-list", "/Users", "UniqueID" }, new[] { ".", "-read", "/Groups/admin", "GroupMembership" } })
            {
                var result = await RunAsync(snapshot, "dscl", args, warnings, ct);
                if (result.ExitCode == 0) AddAccountLines(snapshot, records, "dscl", result.StandardOutput, 500); else Unavailable(records, "users", "dscl");
            }
        }
        else Unavailable(records, "users", "unsupported-platform");
    }

    private static async Task CollectTasksAsync(Snapshot snapshot, List<EvidenceRecord> records, List<string> warnings, CancellationToken ct)
    {
        if (OperatingSystem.IsWindows())
        {
            var result = await RunAsync(snapshot, "schtasks.exe", ["/Query", "/FO", "CSV", "/V"], warnings, ct);
            if (result.ExitCode == 0) AddLines(snapshot, records, "tasks", "TaskScheduler", result.StandardOutput, 500); else Unavailable(records, "tasks", "TaskScheduler");
            return;
        }
        var cron = await RunAsync(snapshot, "crontab", ["-l"], warnings, ct);
        if (cron.ExitCode == 0) AddLines(snapshot, records, "tasks", "current-user-crontab", cron.StandardOutput, 200); else Unavailable(records, "tasks", "current-user-crontab");
        AddFixedFile(snapshot, records, warnings, "tasks", "/etc/crontab", 200);
        if (OperatingSystem.IsLinux())
        {
            AddDirectoryFiles(snapshot, records, warnings, "tasks", "/etc/cron.d", 32, 100);
            var timers = await RunAsync(snapshot, "systemctl", ["list-timers", "--all", "--no-pager", "--no-legend"], warnings, ct);
            if (timers.ExitCode == 0) AddLines(snapshot, records, "tasks", "systemd-timers", timers.StandardOutput, 200); else Unavailable(records, "tasks", "systemd-timers");
        }
        else if (OperatingSystem.IsMacOS())
        {
            var agents = await RunAsync(snapshot, "launchctl", ["list"], warnings, ct);
            if (agents.ExitCode == 0) AddLines(snapshot, records, "tasks", "launchctl", agents.StandardOutput, 300); else Unavailable(records, "tasks", "launchctl");
        }
        warnings.Add("Task collection covers readable system schedules and the current user's crontab; other users' private schedules may be unavailable.");
    }

    private static void CollectCertificates(Snapshot snapshot, List<EvidenceRecord> records, List<Finding> findings, List<string> warnings)
    {
        foreach (var location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
        {
            try
            {
                using var store = new X509Store(StoreName.My, location);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                foreach (var certificate in store.Certificates.Cast<X509Certificate2>().Take(500))
                {
                    using (certificate)
                    {
                        var expires = new DateTimeOffset(certificate.NotAfter.ToUniversalTime());
                        var days = (expires - DateTimeOffset.UtcNow).TotalDays;
                        records.Add(new EvidenceRecord("certificates", $"X509Store:{location}:My", "collected",
                            Safe(snapshot, $"Subject={certificate.Subject}; SHA1-thumbprint={certificate.Thumbprint}; expires={expires:O}; daysRemaining={Math.Floor(days)}"), expires));
                        if (days <= 30)
                            findings.Add(new Finding(days <= 0 ? FindingSeverity.Critical : FindingSeverity.Warning, "CERTIFICATE_EXPIRY",
                                days <= 0 ? "Certificate expired" : "Certificate expires within 30 days",
                                Safe(snapshot, $"{certificate.Subject}; expires {expires:O}; store {location}:My"),
                                "Review the certificate owner and renewal procedure; no certificate was changed."));
                    }
                }
            }
            catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or PlatformNotSupportedException or UnauthorizedAccessException)
            { warnings.Add(Safe(snapshot, $"Certificate store {location}:My unavailable: {ex.Message}")); }
        }
        warnings.Add("Certificate coverage is limited to readable .NET personal certificate stores; application-specific PEM files and remote TLS endpoints are not scanned.");
    }

    private static async Task<CommandResult> RunAsync(Snapshot snapshot, string tool, string[] arguments, List<string> warnings,
        CancellationToken ct, bool warnOnFailure = true)
    {
        var result = await CommandRunner.RunAsync(tool, arguments, CommandTimeout, ct);
        if (result.OutputTruncated) warnings.Add($"{tool}: output truncated by the bounded command runner.");
        if (result.TimedOut) warnings.Add($"{tool}: collection timed out after {CommandTimeout.TotalSeconds} seconds.");
        else if (warnOnFailure && result.ExitCode != 0 && !(tool == "dnf" && result.ExitCode == 100))
            warnings.Add(Safe(snapshot, $"{tool}: unavailable or permission denied (exit {result.ExitCode}); {result.StandardError}"));
        return result;
    }

    internal static string Safe(Snapshot snapshot, string value) =>
        Reporter.RedactEvidenceText(value.Length <= 4096 ? value : value[..4096] + " [truncated]", snapshot.Host.Hostname, snapshot.Host.CurrentUser);

    private static IEnumerable<string> Lines(string text, int limit) => text.Split('\n').Select(line => line.TrimEnd('\r')).Where(line => !string.IsNullOrWhiteSpace(line)).Take(limit);

    private static void AddLines(Snapshot snapshot, List<EvidenceRecord> records, string group, string source, string output, int limit)
    {
        foreach (var line in Lines(output, limit)) records.Add(new EvidenceRecord(group, source, "collected", Safe(snapshot, line)));
        if (string.IsNullOrWhiteSpace(output)) records.Add(new EvidenceRecord(group, source, "collected", "No entries returned."));
    }

    private static void AddAccountLines(Snapshot snapshot, List<EvidenceRecord> records, string source, string output, int limit)
    {
        foreach (var line in Lines(output, limit))
            records.Add(new EvidenceRecord("users", source, "collected", "Account or membership metadata; identity is carried in a protected user field.",
                Metadata: new Dictionary<string, string> { ["user"] = Safe(snapshot, line) }));
    }

    private static void Unavailable(List<EvidenceRecord> records, string group, string source) =>
        records.Add(new EvidenceRecord(group, source, "not_evaluated", "Tool, data, or permissions unavailable; this is not a passing result."));

    private static void AddFixedFile(Snapshot snapshot, List<EvidenceRecord> records, List<string> warnings, string group, string path, int limit)
    {
        var text = ReadFixedFile(path, warnings);
        if (text is not null) AddLines(snapshot, records, group, Safe(snapshot, path), text, limit); else Unavailable(records, group, Safe(snapshot, path));
    }

    private static void AddDirectoryFiles(Snapshot snapshot, List<EvidenceRecord> records, List<string> warnings, string group, string directory, int fileLimit, int lineLimit)
    {
        if (!Directory.Exists(directory)) return;
        try
        {
            if (new DirectoryInfo(directory).LinkTarget is not null) { warnings.Add($"{directory}: symbolic-link directory skipped."); return; }
            foreach (var path in Directory.EnumerateFiles(directory).Order(StringComparer.Ordinal).Take(fileLimit))
                AddFixedFile(snapshot, records, warnings, group, path, lineLimit);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { warnings.Add(Safe(snapshot, $"{directory}: {ex.Message}")); }
    }

    internal static string? ReadFixedFile(string path, List<string> warnings)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var info = new FileInfo(path);
            if (info.LinkTarget is not null) { warnings.Add($"{path}: symbolic-link file skipped."); return null; }
            // The shared reader rejects FIFOs/devices before opening them for normal reads and has a byte/time budget.
            var text = SnapshotIO.ReadTextAsync(path).GetAwaiter().GetResult();
            if (text.Length > 64 * 1024) warnings.Add($"{path}: bounded file read truncated.");
            return text[..Math.Min(text.Length, 64 * 1024)];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or OperationCanceledException or ArgumentException)
        { warnings.Add($"{path}: {ex.Message}"); return null; }
    }
}
