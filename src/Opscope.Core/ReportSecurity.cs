using System.Text.Json;
using System.Text.Json.Nodes;

namespace Opscope;

public static class ReportSecurity
{
    public static JsonSerializerOptions JsonOptions { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        MaxDepth = 48,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    public static AnalysisReport Redact(AnalysisReport report)
    {
        var count = 0;
        var source = JsonSerializer.SerializeToNode(report.Data, JsonOptions);
        var identifiers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        CollectIdentifiers(source, identifiers, 0);
        var sensitive = identifiers.Take(1024).ToArray();
        var data = report.Data is Snapshot snapshot
            ? JsonSerializer.SerializeToNode(Reporter.RedactForOutput(snapshot), JsonOptions)
            : Sanitize(source, null, ref count, 0, sensitive);
        return report with
        {
            Kind = Reporter.RedactEvidenceText(report.Kind, sensitive),
            Findings = report.Findings.Select(f => f with
            {
                Code = Reporter.RedactEvidenceText(f.Code, sensitive),
                Title = Reporter.RedactEvidenceText(f.Title, sensitive),
                Detail = Reporter.RedactEvidenceText(f.Detail, sensitive),
                Recommendation = Reporter.RedactEvidenceText(f.Recommendation, sensitive)
            }).ToArray(),
            Data = data,
            Warnings = (report.Warnings ?? []).Select(w => Reporter.RedactEvidenceText(w, sensitive)).ToArray()
        };
    }

    public static string Serialize(AnalysisReport report, bool redact = true) =>
        JsonSerializer.Serialize(redact ? Redact(report) : report, JsonOptions);

    private static bool IsIdentifier(string key) => key is "id" or "resourceid" or "account" or "accountid" or "subscription" or "subscriptionid" or
        "hostname" or "host" or "members" or "user" or "username" or "currentuser" or "name" or "ipaddress" or "localaddress" or
        "privateip" or "publicip" or "arn" or "profile" or "instanceid" or "tenantid" or "groupid" or "vmid" or "resourcegroup" or
        "accounts" or "subscriptions" or "profiles" or "resourceids" or "addresses" or "scopes" or
        "resource" or "resourcename" or "vmname" or "image" or "vpc" or "subnet" or "volume" or "instance" or "interface" or "association" or "groups" or "logicalid";

    private static void CollectIdentifiers(JsonNode? node, HashSet<string> identifiers, int depth)
    {
        if (depth > 24 || identifiers.Count >= 1024) return;
        if (node is JsonObject obj)
            foreach (var pair in obj)
            {
                var key = pair.Key.Replace("_", string.Empty, StringComparison.Ordinal).Replace("-", string.Empty, StringComparison.Ordinal).ToLowerInvariant();
                if (IsIdentifier(key) && pair.Value is JsonValue value && value.TryGetValue<string>(out var text) && text.Length is >= 3 and <= 512)
                    identifiers.Add(text);
                if (IsIdentifier(key) && pair.Value is JsonArray identifiersArray)
                    foreach (var item in identifiersArray.Take(1024))
                        if (item is JsonValue arrayValue && arrayValue.TryGetValue<string>(out var identifier) && identifier.Length is >= 3 and <= 512)
                            identifiers.Add(identifier);
                CollectIdentifiers(pair.Value, identifiers, depth + 1);
            }
        else if (node is JsonArray array)
            foreach (var item in array.Take(10000)) CollectIdentifiers(item, identifiers, depth + 1);
    }

    private static readonly HashSet<string> SchemaKeys = new(
        typeof(Snapshot).Assembly.GetExportedTypes().SelectMany(t => t.GetProperties(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance)).Select(p => p.Name)
            .Concat(new[] { "resources", "provider", "account", "region", "id", "type", "name", "properties", "scope", "subscriptions", "regions", "profiles", "identity", "records", "coverage", "summary", "source", "metadata", "group", "state", "status", "evidence", "count", "metrics", "agentVersion", "timestampUtc", "resourceGroup", "operation" }),
        StringComparer.OrdinalIgnoreCase);

    private static bool SensitiveKey(string key, string[] identifiers)
    {
        if (SchemaKeys.Contains(key)) return false;
        if (key.StartsWith('/') || key.StartsWith("\\\\", StringComparison.Ordinal) || key.StartsWith("arn:", StringComparison.OrdinalIgnoreCase) ||
            key.Length > 2 && char.IsLetter(key[0]) && key[1] == ':' && key[2] is '\\' or '/') return true;
        if ((key.Contains(':') || key.Count(c => c == '.') == 3) && System.Net.IPAddress.TryParse(key, out _)) return true;
        return Guid.TryParse(key, out _) || identifiers.Contains(key, StringComparer.OrdinalIgnoreCase);
    }

    private static JsonNode? Sanitize(JsonNode? node, string? key, ref int count, int depth, string[] sensitive)
    {
        if (++count > 100000 || depth > 32) return JsonValue.Create("[redacted-limit]");
        var lower = key?.Replace("_", string.Empty, StringComparison.Ordinal).Replace("-", string.Empty, StringComparison.Ordinal).ToLowerInvariant() ?? string.Empty;
        if (lower.Contains("password", StringComparison.Ordinal) || lower.Contains("secret", StringComparison.Ordinal) ||
            lower.Contains("token", StringComparison.Ordinal) || lower.Contains("credential", StringComparison.Ordinal) ||
            lower.Contains("accesskey", StringComparison.Ordinal) || lower is "privatekey" or "authorization" or "environment" or "parameters" or "tags" or "commandline" or "arguments" or "args")
            return JsonValue.Create("[redacted-secret]");
        if (node is JsonObject obj)
        {
            var result = new JsonObject();
            var index = 0;
            foreach (var pair in obj)
            {
                var sanitizedKey = SensitiveKey(pair.Key, sensitive) ? $"[redacted-key-{index}]" : pair.Key;
                result[sanitizedKey] = Sanitize(pair.Value, pair.Key, ref count, depth + 1, sensitive);
                index++;
            }
            return result;
        }
        if (node is JsonArray array)
        {
            var result = new JsonArray();
            foreach (var item in array.Take(10000)) result.Add(Sanitize(item, key, ref count, depth + 1, sensitive));
            return result;
        }
        if (node is JsonValue value && value.TryGetValue<string>(out var text))
        {
            if (IsIdentifier(lower))
            {
                if (System.Text.RegularExpressions.Regex.IsMatch(text, @"\A\[redacted-(?:host|service|process|identifier)(?:-[0-9]{1,4})?\]\z", System.Text.RegularExpressions.RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50)))
                    return JsonValue.Create(text);
                return JsonValue.Create("[redacted-identifier]");
            }
            return JsonValue.Create(Reporter.RedactEvidenceText(text, sensitive));
        }
        return node?.DeepClone();
    }
}
