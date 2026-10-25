using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Opscope.Evidence;

public sealed record IocImport(IReadOnlyList<IocIndicator> Indicators, IReadOnlyList<string> Warnings);

public static class IocAnalyzer
{
    private const int MaximumIndicators = 10000;
    private const int MaximumMatches = 2000;
    private static readonly Regex SimpleStixPattern = new(@"^\[\s*(ipv4-addr:value|ipv6-addr:value|domain-name:value|process:name|file:hashes\.'?(?:MD5|SHA-1|SHA-256)'?)\s*=\s*'([^'\\]{1,1024})'\s*\]$",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100));
    private static readonly Regex IpTokens = new(@"(?<![A-Za-z0-9_.:])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![A-Za-z0-9_.])|[0-9A-Fa-f]*:[0-9A-Fa-f:.%]+", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex DomainTokens = new(@"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_.-])", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

    public static async Task<AnalysisReport> AnalyzeAsync(Snapshot snapshot, string path, CancellationToken cancellationToken = default)
    {
        var text = await SnapshotIO.ReadTextAsync(path, cancellationToken);
        var import = Parse(text, Path.GetExtension(path).Equals(".json", StringComparison.OrdinalIgnoreCase) || text.TrimStart().StartsWith('{') ? "stix" : "csv");
        var warnings = import.Warnings.ToList();
        var hashes = await ReadLiveExecutableHashesAsync(snapshot, import.Indicators, warnings, cancellationToken);
        return AnalyzeInternal(snapshot, import.Indicators, hashes, warnings);
    }

    public static AnalysisReport Analyze(Snapshot snapshot, IReadOnlyList<IocIndicator> indicators)
    {
        var normalized = indicators.Select(Normalize).DistinctBy(item => (item.Type, item.Value)).ToArray();
        if (normalized.Length > MaximumIndicators) throw new InvalidDataException($"At most {MaximumIndicators} IoCs are supported.");
        return AnalyzeInternal(snapshot, normalized, new Dictionary<int, Dictionary<string, string>>(), []);
    }

    public static IocImport Parse(string text, string format)
    {
        if (Encoding.UTF8.GetByteCount(text) > SnapshotIO.MaximumBytes) throw new InvalidDataException("IoC input exceeds the 16 MiB limit.");
        var indicators = new List<IocIndicator>();
        var warnings = new List<string>();
        if (format.Equals("csv", StringComparison.OrdinalIgnoreCase))
        {
            var rows = ReadCsv(text).GetEnumerator();
            if (!rows.MoveNext()) throw new InvalidDataException("IoC CSV is empty; expected type,value[,label] header.");
            var header = rows.Current.Select(value => value.Trim().ToLowerInvariant()).ToArray();
            var typeIndex = Array.IndexOf(header, "type");
            var valueIndex = Array.IndexOf(header, "value");
            var labelIndex = Array.IndexOf(header, "label");
            if (typeIndex < 0 || valueIndex < 0) throw new InvalidDataException("IoC CSV requires type and value columns.");
            var rowNumber = 1;
            while (rows.MoveNext())
            {
                rowNumber++;
                var row = rows.Current;
                if (row.Count <= Math.Max(typeIndex, valueIndex)) throw new InvalidDataException($"IoC CSV row {rowNumber} has too few fields.");
                AddNormalized(indicators, new IocIndicator(row[typeIndex], row[valueIndex], labelIndex >= 0 && labelIndex < row.Count ? row[labelIndex] : null));
            }
        }
        else if (format.Equals("stix", StringComparison.OrdinalIgnoreCase) || format.Equals("json", StringComparison.OrdinalIgnoreCase))
        {
            using var document = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 32 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("STIX input must be a bundle or observable object.");
            var objects = root.TryGetProperty("objects", out var values) && values.ValueKind == JsonValueKind.Array ? values.EnumerateArray().ToArray() : [root];
            if (objects.Length > MaximumIndicators) throw new InvalidDataException($"STIX input exceeds {MaximumIndicators} objects.");
            foreach (var item in objects)
            {
                if (item.ValueKind != JsonValueKind.Object || !item.TryGetProperty("type", out var typeValue)) { warnings.Add("Skipped STIX object without a type."); continue; }
                if (item.TryGetProperty("revoked", out var revoked) && revoked.ValueKind == JsonValueKind.True) { warnings.Add("Skipped revoked STIX object."); continue; }
                var type = typeValue.GetString();
                var label = item.TryGetProperty("name", out var name) ? name.ToString() : null;
                if (type is "ipv4-addr" or "ipv6-addr" or "domain-name")
                {
                    if (item.TryGetProperty("value", out var value)) AddNormalized(indicators, new IocIndicator(type, value.ToString(), label));
                }
                else if (type == "process" && item.TryGetProperty("name", out var process)) AddNormalized(indicators, new IocIndicator("process", process.ToString(), label));
                else if (type == "file" && item.TryGetProperty("hashes", out var hashes) && hashes.ValueKind == JsonValueKind.Object)
                {
                    foreach (var hash in hashes.EnumerateObject())
                        if (NormalizeType(hash.Name) is "md5" or "sha1" or "sha256") AddNormalized(indicators, new IocIndicator(hash.Name, hash.Value.ToString(), label));
                        else warnings.Add($"Unsupported STIX hash algorithm: {Reporter.SafeDisplay(hash.Name)}.");
                }
                else if (type == "indicator" && item.TryGetProperty("pattern", out var pattern))
                {
                    if (item.TryGetProperty("pattern_type", out var patternType) && patternType.ToString() != "stix") { warnings.Add("Skipped non-STIX indicator pattern."); continue; }
                    if (item.TryGetProperty("valid_until", out var until) && DateTimeOffset.TryParse(until.ToString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var expiry) && expiry < DateTimeOffset.UtcNow)
                    { warnings.Add("Skipped expired STIX indicator."); continue; }
                    if (item.TryGetProperty("valid_from", out var from) && DateTimeOffset.TryParse(from.ToString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var starts) && starts > DateTimeOffset.UtcNow)
                    { warnings.Add("Skipped STIX indicator whose validity has not started."); continue; }
                    var match = SimpleStixPattern.Match(pattern.ToString());
                    if (!match.Success) { warnings.Add("Unsupported STIX compound, escaped, or non-equality pattern; not partially evaluated."); continue; }
                    var selector = match.Groups[1].Value;
                    var normalizedType = selector.StartsWith("file:", StringComparison.OrdinalIgnoreCase) ? selector[(selector.LastIndexOf('.') + 1)..].Trim('\'') : selector.Split(':')[0];
                    AddNormalized(indicators, new IocIndicator(normalizedType, match.Groups[2].Value, label));
                }
                else if (type is not ("identity" or "marking-definition" or "relationship")) warnings.Add($"STIX object type '{Reporter.SafeDisplay(type)}' has no supported observable.");
            }
        }
        else throw new ArgumentException("Supported IoC formats: csv, stix/json.", nameof(format));
        if (indicators.Count == 0) warnings.Add("No supported active IoCs were imported; this does not establish absence of compromise.");
        return new IocImport(indicators.DistinctBy(item => (item.Type, item.Value)).ToArray(), warnings.Distinct().ToArray());
    }

    private static AnalysisReport AnalyzeInternal(Snapshot snapshot, IReadOnlyList<IocIndicator> indicators,
        IReadOnlyDictionary<int, Dictionary<string, string>> hashes, List<string> warnings)
    {
        var matches = new List<IocMatch>();
        var observables = new List<(string Source, string Text)>();
        observables.AddRange(snapshot.Processes.Take(1000).Where(process => process.CommandLine is not null)
            .Select(process => ($"process:{process.Id}", process.CommandLine![..Math.Min(4096, process.CommandLine!.Length)])));
        observables.AddRange(snapshot.Listeners.Take(10000).Select(listener => ($"listener:{listener.Protocol}", listener.LocalAddress)));
        observables.AddRange(snapshot.Network.Take(4096).SelectMany(adapter => adapter.Addresses.Take(64).Select(address => ($"interface:{adapter.Name}", address))));
        observables.AddRange(snapshot.Services.Take(10000).Where(service => service.Description is not null)
            .Select(service => ($"service:{service.Name}", service.Description![..Math.Min(4096, service.Description!.Length)])));
        var ipObservables = observables.Select(observable => (observable.Source, observable.Text,
            Addresses: IpTokens.Matches(observable.Text).Select(match => IPAddress.TryParse(match.Value, out var address) ? address.ToString() : null)
                .Where(address => address is not null).ToHashSet(StringComparer.OrdinalIgnoreCase))).ToArray();
        // Tokenize once; per-indicator regular-expression scans would be quadratic for large feeds.
        var domains = observables.SelectMany(observable => DomainTokens.Matches(observable.Text).Select(match =>
                (Domain: match.Value.ToLowerInvariant(), observable.Source)))
            .GroupBy(item => item.Domain, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Select(item => item.Source).Distinct().ToArray(), StringComparer.OrdinalIgnoreCase);
        var nameComparison = snapshot.Host.Platform.Equals("windows", StringComparison.OrdinalIgnoreCase) ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        foreach (var indicator in indicators)
        {
            if (matches.Count >= MaximumMatches) { warnings.Add($"IoC matches limited to {MaximumMatches}."); break; }
            if (indicator.Type == "ip")
            {
                foreach (var observable in ipObservables.Where(observable => observable.Addresses.Contains(indicator.Value)).Take(MaximumMatches - matches.Count))
                    AddMatch(snapshot, matches, indicator, observable.Source, "Exact IP observable match; no network request performed.");
            }
            else if (indicator.Type == "domain")
            {
                if (domains.TryGetValue(indicator.Value, out var sources))
                    foreach (var source in sources.Take(MaximumMatches - matches.Count))
                        AddMatch(snapshot, matches, indicator, source, "Exact domain text observable match; no DNS query performed.");
            }
            else if (indicator.Type == "process")
            {
                foreach (var process in snapshot.Processes.Where(process => process.Name.Equals(indicator.Value, nameComparison)
                    || nameComparison == StringComparison.OrdinalIgnoreCase && (process.Name + ".exe").Equals(indicator.Value, nameComparison)).Take(MaximumMatches - matches.Count))
                    AddMatch(snapshot, matches, indicator, $"process:{process.Id}", $"Process name {process.Name} matched exactly.");
                foreach (var service in snapshot.Services.Where(service => service.Name.Equals(indicator.Value, nameComparison)).Take(MaximumMatches - matches.Count))
                    AddMatch(snapshot, matches, indicator, $"service:{service.Name}", "Service name matched exactly.");
            }
            else if (indicator.Type is "md5" or "sha1" or "sha256")
            {
                foreach (var process in hashes.Where(process => process.Value.TryGetValue(indicator.Type, out var value) && value.Equals(indicator.Value, StringComparison.OrdinalIgnoreCase)).Take(MaximumMatches - matches.Count))
                    AddMatch(snapshot, matches, indicator, $"process:{process.Key}:executable", $"Read-only {indicator.Type} digest matched a kernel-identified running executable.");
                if (hashes.Count == 0) warnings.Add("Executable hashes could not be evaluated: offline snapshots do not contain executable hashes and no authorized live executable was available.");
            }
        }
        warnings.Add("IoC coverage is limited to recorded processes, listening endpoints, interface addresses and service descriptions; established connections, DNS history and arbitrary files are not scanned.");
        return new AnalysisReport("ioc", snapshot.CollectedAtUtc,
            matches.Select(match => new Finding(FindingSeverity.Critical, "IOC_MATCH", $"IoC matched ({match.Indicator.Type})", EvidenceCollector.Safe(snapshot, $"{match.Source}: {match.Indicator.Value}; {match.Evidence}"),
                "Validate the indicator and investigate the referenced evidence. No process, service, connection or file was changed.")).ToArray(),
            new IocData(indicators.Count, observables.Count + hashes.Count, matches), warnings.Distinct().ToArray());
    }

    private static void AddMatch(Snapshot snapshot, List<IocMatch> matches, IocIndicator indicator, string source, string evidence) =>
        matches.Add(new IocMatch(indicator with { Value = EvidenceCollector.Safe(snapshot, indicator.Value), Label = indicator.Label is null ? null : EvidenceCollector.Safe(snapshot, indicator.Label) },
            EvidenceCollector.Safe(snapshot, source), EvidenceCollector.Safe(snapshot, evidence)));

    private static void AddNormalized(List<IocIndicator> indicators, IocIndicator indicator)
    {
        if (indicators.Count >= MaximumIndicators) throw new InvalidDataException($"At most {MaximumIndicators} IoCs are supported.");
        indicators.Add(Normalize(indicator));
    }

    private static string NormalizeType(string type) => type.Trim().ToLowerInvariant() switch
    {
        "ipv4" or "ipv6" or "ipv4-addr" or "ipv6-addr" or "ip" => "ip",
        "domain-name" or "domain" => "domain",
        "process-name" or "process" => "process",
        "sha-1" or "sha1" => "sha1", "sha-256" or "sha256" => "sha256", "md5" => "md5",
        var value => value
    };

    private static IocIndicator Normalize(IocIndicator indicator)
    {
        if (indicator.Value.Length > 1024 || indicator.Label?.Length > 1024) throw new InvalidDataException("IoC values and labels must be at most 1024 characters.");
        var type = NormalizeType(indicator.Type);
        var value = indicator.Value.Trim();
        if (type == "hash") type = value.Length switch { 32 => "md5", 40 => "sha1", 64 => "sha256", _ => throw new InvalidDataException("Unrecognized hash length; specify md5, sha1 or sha256.") };
        switch (type)
        {
            case "ip":
                if (!IPAddress.TryParse(value, out var address)) throw new InvalidDataException("Invalid IP indicator.");
                value = address.ToString(); break;
            case "domain":
                value = value.TrimEnd('.').ToLowerInvariant();
                if (value.Length > 253 || Uri.CheckHostName(value) != UriHostNameType.Dns || !value.Contains('.')) throw new InvalidDataException("Invalid domain indicator; no URL or wildcard is accepted.");
                break;
            case "process":
                if (value.Length is 0 or > 256 || value.Any(character => char.IsControl(character) || character is '/' or '\\')) throw new InvalidDataException("Process indicators must be executable names, not commands or paths.");
                break;
            case "md5": case "sha1": case "sha256":
                var length = type == "md5" ? 32 : type == "sha1" ? 40 : 64;
                if (value.Length != length || !value.All(Uri.IsHexDigit)) throw new InvalidDataException($"Invalid {type} digest.");
                value = value.ToLowerInvariant(); break;
            default: throw new InvalidDataException($"Unsupported IoC type: {Reporter.SafeDisplay(type)}.");
        }
        return indicator with { Type = type, Value = value };
    }

    private static IEnumerable<IReadOnlyList<string>> ReadCsv(string text)
    {
        var row = new List<string>();
        var field = new StringBuilder();
        var quoted = false;
        var closedQuote = false;
        var rows = 0;
        for (var index = 0; index < text.Length; index++)
        {
            var character = text[index];
            if (quoted)
            {
                if (character == '"')
                {
                    if (index + 1 < text.Length && text[index + 1] == '"') { field.Append('"'); index++; }
                    else { quoted = false; closedQuote = true; }
                }
                else field.Append(character);
            }
            else if (character == '"' && field.Length == 0 && !closedQuote) quoted = true;
            else if (character == ',' || character is '\r' or '\n')
            {
                row.Add(field.ToString()); field.Clear(); closedQuote = false;
                if (row.Count > 32) throw new InvalidDataException("IoC CSV contains too many columns.");
                if (character != ',')
                {
                    if (character == '\r' && index + 1 < text.Length && text[index + 1] == '\n') index++;
                    if (row.Any(value => value.Length > 0))
                    {
                        if (++rows > MaximumIndicators + 1) throw new InvalidDataException("IoC CSV contains too many rows.");
                        yield return row.ToArray();
                    }
                    row.Clear();
                }
            }
            else
            {
                if (character == '"') throw new InvalidDataException("Unexpected quote in unquoted CSV field.");
                if (closedQuote && !char.IsWhiteSpace(character)) throw new InvalidDataException("Unexpected content after quoted CSV field.");
                if (!closedQuote) field.Append(character);
            }
            if (field.Length > 4096) throw new InvalidDataException("IoC CSV field exceeds 4096 characters.");
        }
        if (quoted) throw new InvalidDataException("Unterminated quoted CSV field.");
        if (field.Length > 0 || row.Count > 0) { row.Add(field.ToString()); yield return row; }
    }

    [SuppressMessage("Security", "CA5351", Justification = "MD5 is used solely to compare an externally supplied legacy IoC, never for signatures, integrity guarantees or authentication.")]
    [SuppressMessage("Security", "CA5350", Justification = "SHA-1 is used solely to compare an externally supplied legacy IoC, never for signatures, integrity guarantees or authentication.")]
    private static async Task<Dictionary<int, Dictionary<string, string>>> ReadLiveExecutableHashesAsync(Snapshot snapshot,
        IReadOnlyList<IocIndicator> indicators, List<string> warnings, CancellationToken ct)
    {
        var hashes = new Dictionary<int, Dictionary<string, string>>();
        var algorithms = indicators.Select(indicator => indicator.Type).Where(type => type is "md5" or "sha1" or "sha256").Distinct().ToArray();
        if (algorithms.Length == 0) return hashes;
        if (!OperatingSystem.IsLinux() || snapshot.Host.Hostname != Environment.MachineName || snapshot.CollectedAtUtc < DateTimeOffset.UtcNow.AddMinutes(-2) || snapshot.CollectedAtUtc > DateTimeOffset.UtcNow.AddSeconds(5))
        { warnings.Add("Live hash inspection is available only for recent same-host Linux snapshots; saved/foreign snapshots remain offline and hashes are not guessed."); return hashes; }
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(TimeSpan.FromSeconds(5));
        foreach (var info in snapshot.Processes.Take(128))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var process = Process.GetProcessById(info.Id);
                if (process.ProcessName != info.Name || process.StartTime.ToUniversalTime() > snapshot.CollectedAtUtc.UtcDateTime) continue;
                // The path is constructed from a positive observed PID, never from an IoC, command line or plugin.
                if (info.Id <= 0) continue;
                await using var executable = new FileStream($"/proc/{info.Id}/exe", FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 8192, FileOptions.Asynchronous | FileOptions.SequentialScan);
                if (!executable.CanSeek || executable.Length > 64 * 1024 * 1024) { warnings.Add("A live executable exceeded the 64 MiB hash limit or was not seekable."); continue; }
                var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var algorithm in algorithms)
                {
                    executable.Position = 0;
                    var digest = algorithm switch
                    {
                        "md5" => await MD5.HashDataAsync(executable, budget.Token),
                        "sha1" => await SHA1.HashDataAsync(executable, budget.Token),
                        _ => await SHA256.HashDataAsync(executable, budget.Token)
                    };
                    values[algorithm] = Convert.ToHexString(digest).ToLowerInvariant();
                }
                hashes[info.Id] = values;
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { warnings.Add("Live executable hashing reached its five-second budget; remaining hashes were not evaluated."); break; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException or System.ComponentModel.Win32Exception or System.Security.SecurityException)
            { warnings.Add($"Executable for PID {info.Id} was inaccessible or no longer matched the snapshot."); }
        }
        return hashes;
    }
}
