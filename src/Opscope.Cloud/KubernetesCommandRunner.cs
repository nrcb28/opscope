using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Opscope.Cloud;

/// <summary>Fixed kubectl read projections. Pod specs, environment, commands and event messages never enter Opscope output.</summary>
public sealed class KubernetesCommandRunner : ICloudCommandRunner
{
    internal const int MaximumRows = 1000;
    private const int MaximumOutput = 1024 * 1024;
    internal static readonly IReadOnlyDictionary<string, string> Columns = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["namespaces"] = "name:.metadata.name,uid:.metadata.uid,state:.status.phase",
        ["nodes"] = "name:.metadata.name,uid:.metadata.uid,ready:.status.conditions[?(@.type==\"Ready\")].status,cpu:.status.capacity.cpu,memory:.status.capacity.memory,version:.status.nodeInfo.kubeletVersion",
        ["pods"] = "name:.metadata.name,uid:.metadata.uid,state:.status.phase,ready:.status.containerStatuses[*].ready,restarts:.status.containerStatuses[*].restartCount",
        ["deployments"] = "name:.metadata.name,uid:.metadata.uid,desired:.spec.replicas,available:.status.availableReplicas,updated:.status.updatedReplicas",
        ["statefulsets"] = "name:.metadata.name,uid:.metadata.uid,desired:.spec.replicas,available:.status.availableReplicas,updated:.status.updatedReplicas",
        ["daemonsets"] = "name:.metadata.name,uid:.metadata.uid,desired:.status.desiredNumberScheduled,available:.status.numberAvailable,updated:.status.updatedNumberScheduled",
        ["services"] = "name:.metadata.name,uid:.metadata.uid,type:.spec.type,ports:.spec.ports[*].port",
        ["events.events.k8s.io"] = "name:.metadata.name,uid:.metadata.uid,type:.type,reason:.reason,observedAt:.eventTime,count:.series.count"
    };

    public async Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        if (tool != "kubectl") throw new InvalidOperationException("Only the configured Kubernetes read client is allowed.");
        var query = Validate(arguments);
        var result = await CommandRunner.RunAsync("kubectl", arguments, TimeSpan.FromSeconds(10), MaximumOutput, cancellationToken);
        if (result.TimedOut) throw new KubernetesQueryException("timed_out", "The bounded Kubernetes read timed out.");
        if (result.ExitCode != 0)
        {
            var state = result.StandardError.Contains("forbidden", StringComparison.OrdinalIgnoreCase) || result.StandardError.Contains("unauthorized", StringComparison.OrdinalIgnoreCase)
                ? "permission_denied" : "unavailable";
            throw new KubernetesQueryException(state, "The configured Kubernetes read was unavailable. Check the context, RBAC and client installation outside Opscope.");
        }
        if (query == "metrics")
        {
            if (result.OutputTruncated) throw new KubernetesQueryException("partial", "The Kubernetes metrics response exceeded its output bound.");
            using var document = JsonDocument.Parse(result.StandardOutput, new JsonDocumentOptions { MaxDepth = 32 });
            return document.RootElement.Clone();
        }
        return ParseProjection(query, result.StandardOutput, result.OutputTruncated);
    }

    internal static string Validate(IReadOnlyList<string> args)
    {
        if (args.Count is < 6 or > 12 || args.Any(value => value is null || value.Length > 2048 || value.Any(char.IsControl)) ||
            args[0] != "--context" || !ValidContext(args[1]) || args[2] != "--request-timeout=10s" || args[3] != "get")
            throw new InvalidOperationException("Kubernetes read arguments are outside the fixed allowlist.");
        if (args[4] == "--raw")
        {
            if (args.Count != 6 || !ValidMetricPath(args[5])) throw new InvalidOperationException("Kubernetes metrics path is outside the fixed namespace allowlist.");
            return "metrics";
        }
        var kind = args[4];
        if (!Columns.TryGetValue(kind, out var columns)) throw new InvalidOperationException("Kubernetes resource is outside the read allowlist.");
        var index = 5;
        if (kind == "namespaces")
        {
            if (args.Count != 9 || !ValidName(args[index++])) throw new InvalidOperationException("Only a configured namespace may be inspected.");
        }
        else if (kind != "nodes")
        {
            if (args.Count != 10 || args[index++] != "--namespace" || !ValidName(args[index++])) throw new InvalidOperationException("Namespaced Kubernetes reads need one explicit namespace.");
        }
        else if (args.Count != 8) throw new InvalidOperationException("Invalid node read.");
        if (args[index++] != "--chunk-size=100" || args[index++] != "--no-headers" || args[index] != "--output=custom-columns=" + columns)
            throw new InvalidOperationException("Only the fixed Kubernetes metadata projection is allowed.");
        return kind;
    }

    internal static bool ValidName(string value) => value.Length is > 0 and <= 63 && Regex.IsMatch(value, @"\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    internal static bool ValidContext(string value) => value.Length is > 0 and <= 256 && !value.StartsWith('-') && !value.StartsWith('@') && !value.Any(char.IsControl);

    private static bool ValidMetricPath(string path)
    {
        const string prefix = "/apis/metrics.k8s.io/v1beta1/namespaces/";
        if (!path.StartsWith(prefix, StringComparison.Ordinal) || path.Length > 2048 || path.Contains('#') || path.Contains('\\')) return false;
        var rest = path[prefix.Length..];
        var marker = rest.IndexOf("/pods?limit=100", StringComparison.Ordinal);
        if (marker < 1 || !ValidName(rest[..marker])) return false;
        var query = rest[(marker + "/pods?limit=100".Length)..];
        if (query.Length == 0) return true;
        if (!query.StartsWith("&continue=", StringComparison.Ordinal) || query.Length > 1536) return false;
        var token = query[10..];
        return token.Length > 0 && Regex.IsMatch(token, @"\A(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    }

    internal static JsonElement ParseProjection(string kind, string output, bool truncated = false)
    {
        var fields = Columns[kind].Split(',').Select(column => column[..column.IndexOf(':')]).ToArray();
        var rows = new List<Dictionary<string, string?>>();
        var invalid = 0;
        foreach (var line in output.Split('\n'))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            if (rows.Count >= MaximumRows) { truncated = true; break; }
            if (line.Length > 4096) { invalid++; continue; }
            var values = Regex.Split(line.Trim(), @"\s+", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
            if (values.Length != fields.Length || !ValidObjectName(values[0])) { invalid++; continue; }
            var row = new Dictionary<string, string?>(StringComparer.Ordinal);
            for (var index = 0; index < fields.Length; index++) row[fields[index]] = values[index] is "<none>" or "<unknown>" ? null : values[index];
            rows.Add(row);
        }
        return JsonSerializer.SerializeToElement(new { kind, rows, truncated, malformedRows = invalid });
    }

    internal static bool ValidObjectName(string value) => value.Length is > 0 and <= 253 && Regex.IsMatch(value, @"\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
}

public sealed class KubernetesQueryException(string state, string message) : IOException(message)
{
    public string State { get; } = state;
}
