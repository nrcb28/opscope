using System.Globalization;
using System.Text;
using System.Text.Json;
using YamlDotNet.Core;
using YamlDotNet.Core.Events;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Opscope;

internal static class BoundedYaml
{
    internal static T Read<T>(string path)
    {
        var info = new FileInfo(path);
        if (info.Length > 128 * 1024) throw new InvalidDataException("YAML exceeds 128 KiB.");
        string source;
        try
        {
            // The shared reader opens only regular files and bounds time/bytes before parsing.
            // Run outside a caller synchronization context because Load is a synchronous API.
            source = Task.Run(() => SnapshotIO.ReadTextAsync(path)).GetAwaiter().GetResult();
        }
        catch (DecoderFallbackException exception) { throw new InvalidDataException("YAML must use valid UTF-8.", exception); }
        return Parse<T>(source);
    }
    internal static T Parse<T>(string source)
    {
        ArgumentNullException.ThrowIfNull(source);
        try
        {
            if (new UTF8Encoding(false, true).GetByteCount(source) > 128 * 1024) throw new InvalidDataException("YAML exceeds 128 KiB.");
        }
        catch (EncoderFallbackException exception) { throw new InvalidDataException("YAML must contain valid Unicode.", exception); }
        source = source.TrimStart('\uFEFF');
        try
        {
            var parser = new Parser(new StringReader(source));
            var depth = 0; var count = 0; var documents = 0;
            while (parser.MoveNext())
            {
                if (++count > 10000) throw new InvalidDataException("YAML contains too many nodes.");
                if (parser.Current is DocumentStart && ++documents > 1) throw new InvalidDataException("Only one YAML document is allowed.");
                if (parser.Current is AnchorAlias) throw new InvalidDataException("YAML aliases are not allowed.");
                if (parser.Current is NodeEvent node && (!node.Anchor.IsEmpty || !node.Tag.IsEmpty)) throw new InvalidDataException("YAML tags and anchors are not allowed.");
                if (parser.Current is MappingStart or SequenceStart && ++depth > 16) throw new InvalidDataException("YAML nesting exceeds 16 levels.");
                if (parser.Current is MappingEnd or SequenceEnd) depth--;
                if (parser.Current is Scalar scalar && scalar.Value.Length > 8192) throw new InvalidDataException("YAML scalar exceeds 8192 characters.");
            }
            return new DeserializerBuilder().WithNamingConvention(CamelCaseNamingConvention.Instance).WithDuplicateKeyChecking().Build().Deserialize<T>(source)
                ?? throw new InvalidDataException("YAML document is empty.");
        }
        catch (YamlException exception) { throw new InvalidDataException($"Invalid YAML: {exception.Message}", exception); }
    }
}

public sealed class PolicyThresholds
{
    public double CpuWarningPercent { get; set; } = 85;
    public double CpuCriticalPercent { get; set; } = 95;
    public double MemoryWarningPercent { get; set; } = 85;
    public double MemoryCriticalPercent { get; set; } = 95;
    public double DiskWarningPercent { get; set; } = 85;
    public double DiskCriticalPercent { get; set; } = 95;
}

public sealed class DeclarativeRule
{
    public string Id { get; set; } = "";
    public string Metric { get; set; } = "";
    public string Operator { get; set; } = ">=";
    public double Value { get; set; }
    public string Severity { get; set; } = "warning";
    public string Title { get; set; } = "Declarative policy rule matched";
    public string Recommendation { get; set; } = "Review the collected evidence.";
}

public sealed class PolicyDocument
{
    public int Version { get; set; } = 1;
    public PolicyThresholds Thresholds { get; set; } = new();
    public List<int>? AllowedPorts { get; set; }
    public List<string> RequiredServices { get; set; } = [];
    public List<DeclarativeRule> Rules { get; set; } = [];
}

public sealed class PolicyEngine
{
    private static readonly HashSet<string> Metrics = new(StringComparer.Ordinal) { "cpu.usedPercent", "memory.usedPercent", "disk.maxUsedPercent", "security.exposedListeners", "network.listenerCount", "services.runningCount", "firewall.active", "cloud.resourceCount", "cloud.warningCount", "cloud.criticalCount" };
    private readonly PolicyDocument document;
    public PolicyEngine(PolicyDocument document) { this.document = document ?? throw new ArgumentNullException(nameof(document)); }
    public static PolicyEngine Load(string path) => FromDocument(BoundedYaml.Read<PolicyDocument>(path));
    public static PolicyEngine Parse(string yaml) => FromDocument(BoundedYaml.Parse<PolicyDocument>(yaml));
    private static PolicyEngine FromDocument(PolicyDocument document)
    {
        var result = new PolicyEngine(document);
        var errors = result.Validate();
        if (errors.Count > 0) throw new InvalidDataException(string.Join("; ", errors));
        return result;
    }
    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (document.Version != 1) errors.Add("Policy version must be 1.");
        if (document.Thresholds is null || document.RequiredServices is null || document.Rules is null) { errors.Add("Policy collections cannot be null."); return errors; }
        var t = document.Thresholds;
        foreach (var (name, warning, critical) in new[] { ("cpu", t.CpuWarningPercent, t.CpuCriticalPercent), ("memory", t.MemoryWarningPercent, t.MemoryCriticalPercent), ("disk", t.DiskWarningPercent, t.DiskCriticalPercent) })
            if (!double.IsFinite(warning) || !double.IsFinite(critical) || warning < 0 || warning > critical || critical > 100) errors.Add($"{name} thresholds must satisfy 0 <= warning <= critical <= 100.");
        if (document.AllowedPorts is { Count: > 1024 } || document.AllowedPorts?.Any(p => p is < 1 or > 65535) == true) errors.Add("Allowed ports must contain at most 1024 ports between 1 and 65535.");
        if (document.RequiredServices.Count > 256 || document.RequiredServices.Any(s => string.IsNullOrWhiteSpace(s) || s.Length > 128 || s.Any(char.IsControl))) errors.Add("Required services must contain at most 256 nonempty names of at most 128 characters.");
        if (document.Rules.Count > 256) errors.Add("At most 256 rules are allowed.");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var rule in document.Rules)
        {
            if (rule is null) { errors.Add("Null rules are not allowed."); continue; }
            if (string.IsNullOrWhiteSpace(rule.Id) || rule.Id.Length > 128 || !ids.Add(rule.Id) || rule.Id.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '-' and not '_' and not '.')) errors.Add("Rule IDs must be unique safe identifiers of at most 128 characters.");
            if (!Metrics.Contains(rule.Metric)) errors.Add($"Unsupported metric in rule {rule.Id}.");
            if (rule.Operator is not (">" or ">=" or "<" or "<=" or "==" or "!=")) errors.Add($"Unsupported operator in rule {rule.Id}.");
            if (!double.IsFinite(rule.Value)) errors.Add($"Rule {rule.Id} requires a finite numeric value.");
            if (!TrySeverity(rule.Severity, out _)) errors.Add($"Invalid severity in rule {rule.Id}.");
            if (rule.Title is null || rule.Title.Length > 512 || rule.Recommendation is null || rule.Recommendation.Length > 2048) errors.Add($"Rule {rule.Id} text is too long or null.");
        }
        return errors;
    }
    public AnalysisReport Evaluate(Snapshot snapshot)
    {
        var errors = Validate();
        if (errors.Count > 0) throw new InvalidDataException(string.Join("; ", errors));
        var findings = new List<Finding>(); var warnings = new List<string>(snapshot.CollectionWarnings); var t = document.Thresholds;
        Check("CPU", snapshot.CpuUsedPercent, t.CpuWarningPercent, t.CpuCriticalPercent);
        Check("MEMORY", snapshot.Memory.UsedPercent, t.MemoryWarningPercent, t.MemoryCriticalPercent);
        foreach (var disk in snapshot.Disks.Where(d => d.IsReady)) Check("DISK", disk.UsedPercent, t.DiskWarningPercent, t.DiskCriticalPercent);
        if (document.AllowedPorts is not null)
            foreach (var listener in snapshot.Listeners)
                if (TryPort(listener.LocalAddress, out var port) && !document.AllowedPorts.Contains(port)) findings.Add(new(FindingSeverity.Warning, "POLICY_PORT", "Listener outside allowed ports", $"A {listener.Protocol} listener uses port {port}.", "Review the listener and restrict exposure or update the approved policy."));
        foreach (var name in document.RequiredServices)
            if (!snapshot.Services.Any(s => s.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && IsRunning(s.State))) findings.Add(new(FindingSeverity.Critical, "POLICY_SERVICE", "Required service is not running", $"Required service {name} was not observed running.", "Confirm collection coverage and investigate the required service."));
        foreach (var rule in document.Rules)
        {
            if (rule.Metric.StartsWith("cloud.", StringComparison.Ordinal)) { warnings.Add($"Rule {rule.Id} requires a cloud report and was not evaluated against the local snapshot."); continue; }
            var observed = Metric(snapshot, rule.Metric);
            if (Compare(observed, rule.Operator, rule.Value)) { TrySeverity(rule.Severity, out var severity); findings.Add(new(severity, $"RULE_{rule.Id}", rule.Title, $"{rule.Metric} is {observed.ToString("G", CultureInfo.InvariantCulture)}; condition {rule.Operator} {rule.Value.ToString("G", CultureInfo.InvariantCulture)}.", rule.Recommendation)); }
        }
        return new AnalysisReport("policy", snapshot.CollectedAtUtc, findings, new { version = document.Version, rulesEvaluated = document.Rules.Count(rule => !rule.Metric.StartsWith("cloud.", StringComparison.Ordinal)), allowedPortsConfigured = document.AllowedPorts is not null }, warnings);
        void Check(string code, double value, double warning, double critical)
        {
            if (value >= warning) findings.Add(new(value >= critical ? FindingSeverity.Critical : FindingSeverity.Warning, $"POLICY_{code}", $"{code} policy threshold exceeded", $"Observed {value:F1}% (warning {warning:F1}%, critical {critical:F1}%).", "Investigate resource utilization and restore capacity."));
        }
    }
    public AnalysisReport Evaluate(AnalysisReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var errors = Validate();
        if (errors.Count > 0) throw new InvalidDataException(string.Join("; ", errors));
        var findings = new List<Finding>();
        var warnings = new List<string>(report.Warnings ?? []);
        var (resourceCountKnown, resourceCount) = CloudResourceCount(report.Data);
        if (!document.Rules.Any(rule => rule.Metric.StartsWith("cloud.", StringComparison.Ordinal)))
            warnings.Add("The policy contains no cloud rules. Local resource thresholds, ports and required services were not evaluated against this cloud report.");
        var evaluated = 0;
        foreach (var rule in document.Rules)
        {
            if (!rule.Metric.StartsWith("cloud.", StringComparison.Ordinal)) { warnings.Add($"Rule {rule.Id} requires a local snapshot and was not evaluated against the cloud report."); continue; }
            if (rule.Metric == "cloud.resourceCount" && !resourceCountKnown) { warnings.Add($"Rule {rule.Id} was not evaluated: normalized cloud resource evidence was unavailable, redacted, invalid or exceeded bounds."); continue; }
            var observed = rule.Metric switch
            {
                "cloud.resourceCount" => resourceCount,
                "cloud.warningCount" => report.Findings.Count(finding => finding.Severity == FindingSeverity.Warning),
                "cloud.criticalCount" => report.Findings.Count(finding => finding.Severity == FindingSeverity.Critical),
                _ => throw new InvalidDataException("Unsupported cloud metric.")
            };
            evaluated++;
            if (Compare(observed, rule.Operator, rule.Value))
            {
                TrySeverity(rule.Severity, out var severity);
                findings.Add(new(severity, $"RULE_{rule.Id}", rule.Title, $"{rule.Metric} is {observed.ToString(CultureInfo.InvariantCulture)}; condition {rule.Operator} {rule.Value.ToString("G", CultureInfo.InvariantCulture)}.", rule.Recommendation));
            }
        }
        return new("policy/cloud", report.CollectedAtUtc, findings, new { version = document.Version, rulesEvaluated = evaluated, resourceCountKnown, resourceCount = resourceCountKnown ? (int?)resourceCount : null }, warnings.Distinct(StringComparer.Ordinal).ToArray());
    }
    private static (bool Known, int Count) CloudResourceCount(object? data)
    {
        if (data is null) return (false, 0);
        try
        {
            var root = JsonSerializer.SerializeToElement(data, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, MaxDepth = 32 });
            var identities = new HashSet<string>(StringComparer.Ordinal);
            var known = false; var invalid = false; var visited = 0;
            Visit(root, 0);
            return (known && !invalid, identities.Count);
            void Visit(JsonElement node, int depth)
            {
                if (++visited > 100000 || depth > 24) { invalid = true; return; }
                if (node.ValueKind == JsonValueKind.Object)
                {
                    var provider = Text(node, "provider");
                    foreach (var property in node.EnumerateObject())
                    {
                        if (property.Name.Equals("resources", StringComparison.OrdinalIgnoreCase) && property.Value.ValueKind == JsonValueKind.Array)
                        {
                            if (property.Value.GetArrayLength() > 10000) { invalid = true; break; }
                            var normalized = property.Value.GetArrayLength() == 0 ? provider is "azure" or "aws" : property.Value.EnumerateArray().All(IsResource);
                            if (normalized)
                            {
                                known = true;
                                foreach (var resource in property.Value.EnumerateArray())
                                {
                                    var fields = new[] { Text(resource, "provider"), Text(resource, "account"), Text(resource, "region"), Text(resource, "type"), Text(resource, "id") };
                                    if (fields.Any(value => value.StartsWith("[redacted", StringComparison.Ordinal))) invalid = true;
                                    identities.Add(string.Join('\u001f', fields));
                                    if (identities.Count > 10000) { invalid = true; break; }
                                }
                                continue;
                            }
                        }
                        Visit(property.Value, depth + 1);
                        if (invalid) break;
                    }
                }
                else if (node.ValueKind == JsonValueKind.Array)
                    foreach (var item in node.EnumerateArray()) { Visit(item, depth + 1); if (invalid) break; }
            }
            static bool IsResource(JsonElement node) => node.ValueKind == JsonValueKind.Object && Text(node, "provider") is "azure" or "aws" && new[] { "account", "region", "id", "type" }.All(key => Text(node, key).Length > 0);
            static string Text(JsonElement node, string key)
            {
                if (node.ValueKind != JsonValueKind.Object) return string.Empty;
                foreach (var property in node.EnumerateObject()) if (property.Name.Equals(key, StringComparison.OrdinalIgnoreCase) && property.Value.ValueKind == JsonValueKind.String) return property.Value.GetString() ?? string.Empty;
                return string.Empty;
            }
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException or InvalidOperationException) { return (false, 0); }
    }
    public static bool MeetsFailureThreshold(IEnumerable<Finding> findings, string threshold)
    {
        if (threshold.Equals("none", StringComparison.OrdinalIgnoreCase)) return false;
        if (!TrySeverity(threshold, out var severity)) throw new ArgumentException("Failure threshold must be info, warning, critical, or none.", nameof(threshold));
        return findings.Any(f => f.Severity >= severity);
    }
    private static bool TrySeverity(string value, out FindingSeverity severity)
    {
        severity = FindingSeverity.Info;
        return value is not null && (value.Equals("info", StringComparison.OrdinalIgnoreCase) || value.Equals("warning", StringComparison.OrdinalIgnoreCase) || value.Equals("critical", StringComparison.OrdinalIgnoreCase)) && Enum.TryParse(value, true, out severity);
    }
    private static bool IsRunning(string state)
    {
        var finalState = state.Split('/', StringSplitOptions.TrimEntries).LastOrDefault() ?? string.Empty;
        return finalState.Equals("running", StringComparison.OrdinalIgnoreCase) || finalState.Equals("active", StringComparison.OrdinalIgnoreCase);
    }
    private static bool TryPort(string address, out int port) => int.TryParse(address[(address.LastIndexOf(':') + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is >= 1 and <= 65535;
    private static bool Compare(double left, string op, double right) => op switch { ">" => left > right, ">=" => left >= right, "<" => left < right, "<=" => left <= right, "==" => left == right, "!=" => left != right, _ => false };
    private static double Metric(Snapshot s, string name) => name switch { "cpu.usedPercent" => s.CpuUsedPercent, "memory.usedPercent" => s.Memory.UsedPercent, "disk.maxUsedPercent" => s.Disks.Where(d => d.IsReady).Select(d => d.UsedPercent).DefaultIfEmpty(0).Max(), "security.exposedListeners" => s.Security.ExposedListeners, "network.listenerCount" => s.Listeners.Count, "services.runningCount" => s.Services.Count(s => IsRunning(s.State)), "firewall.active" => s.Security.HasActiveFirewall ? 1 : 0, _ => throw new InvalidDataException("Unsupported metric.") };
}

public sealed class PackDocument
{
    public int Version { get; set; } = 1;
    public string Name { get; set; } = "";
    public string? Extends { get; set; }
    public List<string> Collectors { get; set; } = [];
}

public sealed record CollectionPack(string Name, IReadOnlyList<string> Collectors)
{
    private static readonly HashSet<string> Allowed = new(StringComparer.Ordinal) { "host", "cpu", "memory", "disks", "network", "processes", "services", "security", "tools", "logs", "packages", "accounts", "scheduled-tasks", "certificates" };
    public IReadOnlyList<string> EvidenceGroups => Collectors.Where(c => c is "logs" or "packages" or "accounts" or "scheduled-tasks" or "certificates" or "security").ToArray();
    public CollectorOptions ToCollectorOptions() => new(IncludeProcesses: Collectors.Contains("processes"), IncludeNetwork: Collectors.Contains("network"), IncludeServices: Collectors.Contains("services"));
    public static CollectionPack Load(string path)
    {
        var root = Path.GetDirectoryName(Path.GetFullPath(path))!;
        return LoadInner(Path.GetFullPath(path), root, new HashSet<string>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal), 0);
    }
    private static CollectionPack LoadInner(string path, string root, HashSet<string> visited, int depth)
    {
        if (depth > 8 || !visited.Add(path)) throw new InvalidDataException("Pack inheritance contains a cycle or exceeds 8 levels.");
        var info = new FileInfo(path);
        if (info.LinkTarget is not null) throw new InvalidDataException("Pack symbolic links are not allowed.");
        var doc = BoundedYaml.Read<PackDocument>(path);
        if (doc.Version != 1 || string.IsNullOrWhiteSpace(doc.Name) || doc.Name.Length > 128 || doc.Name.Any(char.IsControl)) throw new InvalidDataException("Pack requires version 1 and a bounded name.");
        if (doc.Collectors is null || doc.Collectors.Count > Allowed.Count || doc.Collectors.Any(c => !Allowed.Contains(c))) throw new InvalidDataException("Pack collectors must be allowlisted groups; commands and file paths are unsupported.");
        var groups = new HashSet<string>(StringComparer.Ordinal);
        if (doc.Extends is not null)
        {
            if (Path.IsPathRooted(doc.Extends) || doc.Extends.Split('/', '\\').Any(part => part is ".." or ".") || doc.Extends.Length > 256) throw new InvalidDataException("Pack inheritance must use a safe relative path below the pack directory.");
            var parent = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(path)!, doc.Extends));
            var relative = Path.GetRelativePath(root, parent);
            if (relative.StartsWith("..", StringComparison.Ordinal) || Path.IsPathRooted(relative)) throw new InvalidDataException("Pack inheritance escapes its directory.");
            var cursor = Path.GetDirectoryName(parent);
            while (cursor is not null && !cursor.Equals(root, StringComparison.Ordinal)) { if (new DirectoryInfo(cursor).LinkTarget is not null) throw new InvalidDataException("Pack inheritance cannot traverse symbolic links."); cursor = Path.GetDirectoryName(cursor); }
            groups.UnionWith(LoadInner(parent, root, visited, depth + 1).Collectors);
        }
        groups.UnionWith(doc.Collectors);
        return new(doc.Name, groups.Order(StringComparer.Ordinal).ToArray());
    }
}
