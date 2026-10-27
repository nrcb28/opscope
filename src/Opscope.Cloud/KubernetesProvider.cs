using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Opscope.Cloud;

/// <summary>Namespace-allowlisted cluster observations. Kubernetes is a cluster source, not an infrastructure cloud.</summary>
public sealed class KubernetesProvider(ICloudCommandRunner? runner = null) : ICloudProvider
{
    private readonly ICloudCommandRunner client = runner ?? new KubernetesCommandRunner();
    private const int ResourceBudget = 1000;
    private const int MetricBudget = 1000;
    private static readonly HashSet<string> EventReasons = new(StringComparer.Ordinal)
        { "BackOff", "Failed", "FailedScheduling", "Unhealthy", "FailedMount", "Killing", "Pulled", "Scheduled", "Created", "Started", "ScalingReplicaSet", "FailedCreate", "SuccessfulCreate", "NodeNotReady", "NodeReady", "FailedGetResourceMetric" };
    public string Name => "kubernetes";

    /// <summary>Checks literal name syntax without loading kubeconfig or discovering credentials.</summary>
    public static bool IsValidContext(string? context) => context is not null && KubernetesCommandRunner.ValidContext(context.Trim());

    public static bool IsValidNamespaceAllowlist(string? namespaces)
    {
        if (namespaces is null || namespaces.Length > 8192) return false;
        var values = namespaces.Split(',', StringSplitOptions.TrimEntries);
        return values.Length is >= 1 and <= 20 && values.All(KubernetesCommandRunner.ValidName) &&
            values.Distinct(StringComparer.Ordinal).Count() == values.Length;
    }

    public async Task<AnalysisReport> CollectAsync(string operation, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        var now = DateTimeOffset.UtcNow;
        var resources = new List<CloudResource>();
        var resourceKeys = new HashSet<string>(StringComparer.Ordinal);
        var findings = new List<Finding>();
        var metrics = new List<KubernetesMetricSeries>();
        var metricKeys = new HashSet<string>(StringComparer.Ordinal);
        var warnings = new List<string>();
        var expectedScopes = 0;
        var completedScopes = 0;
        var attemptedReads = 0;
        var completedReads = 0;
        var failedReads = 0;
        var limited = false;
        var unavailableState = "unavailable";
        var context = Option("context");
        var namespaces = Option("namespaces").Length == 0 ? Option("namespace") : Option("namespaces");
        var allowedNamespaces = namespaces.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.Ordinal).ToArray();
        var includeNodes = Option("kubernetes-nodes") == "true";
        if (operation is not ("inventory" or "health" or "metrics")) return Report("unsupported", false, "This cluster adapter supports inventory, health and explicitly selected metrics only.");
        if (!IsValidContext(context) || !IsValidNamespaceAllowlist(namespaces) || Option("kubernetes-nodes") is not ("" or "false" or "true"))
            return Report("not_configured", false, "Select an existing context and 1–20 distinct explicit namespaces. Wildcards, all-namespaces and browser-supplied cluster credentials are unsupported.");
        expectedScopes = allowedNamespaces.Length;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(60));
        warnings.Add("Cluster evidence is limited to configured namespaces and fixed metadata/status projections. It does not prove application availability or an infrastructure-cloud identity. Kubernetes Secrets, pod environment/commands, ConfigMaps and logs are not queried.");
        if (includeNodes && operation != "metrics") await ReadMetadata("nodes", null);
        foreach (var ns in allowedNamespaces)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (limited && (resources.Count >= ResourceBudget || metrics.Count >= MetricBudget)) break;
            var failuresBefore = failedReads;
            var readsBefore = completedReads;
            if (operation == "metrics") await ReadMetrics(ns);
            else
            {
                var namespaceRows = await ReadMetadata("namespaces", ns);
                if (namespaceRows is not { Count: 1 } || Text(namespaceRows[0], "name") != ns)
                {
                    if (namespaceRows is not null) { failedReads++; unavailableState = "scope_mismatch"; warnings.Add("The selected namespace could not be verified; its resource reads were skipped."); }
                    continue;
                }
                foreach (var kind in new[] { "pods", "deployments", "statefulsets", "daemonsets" }) await ReadMetadata(kind, ns);
                if (operation == "inventory") await ReadMetadata("services", ns);
                await ReadMetadata("events.events.k8s.io", ns);
            }
            if (completedReads > readsBefore && failedReads == failuresBefore) completedScopes++;
        }
        if (operation == "metrics")
        {
            warnings.Add("Metrics are actual recent Metrics Server observations in millicores and bytes. They are not percentages or a historical series; missing Metrics Server or RBAC never becomes a zero measurement.");
            if (metrics.Count == 0 && completedReads > 0)
                warnings.Add("No pod metric observations were returned for these namespaces. No zero usage or workload-health conclusion was inferred.");
        }
        else
            warnings.Add("kubectl uses 100-item server chunks; its internal page count is controlled by each ten-second command deadline and 1 MiB projected-output limit. Opscope retains at most 1,000 resource rows across the whole collection.");
        if (limited) warnings.Add("A row, sample, malformed projection or query bound was reached; cluster coverage is incomplete.");
        var succeeded = attemptedReads > 0 && failedReads == 0 && !limited && completedScopes == expectedScopes;
        return Report(succeeded ? operation == "metrics" && metrics.Count == 0 ? "no_data" : "complete" : completedReads > 0 ? "partial" : unavailableState, succeeded);

        string Option(string key) => options.TryGetValue(key, out var value) ? value.Trim() : string.Empty;

        AnalysisReport Report(string state, bool succeeded, string? warning = null)
        {
            if (warning is not null) warnings.Add(warning);
            return new("cluster/kubernetes/" + operation, now, findings, new
            {
                schemaVersion = 1, provider = "kubernetes", operation,
                cluster = new { scopeKind = "cluster", relation = "unverified", cloudCorrelationVerified = false, namespacesQueried = completedScopes, includesNodes = includeNodes && operation != "metrics" },
                scope = new { accounts = context.Length == 0 ? Array.Empty<string>() : new[] { context }, namespaces = allowedNamespaces },
                resources, metrics,
                coverage = new { state, observedAtUtc = now, enumeratedResources = operation == "metrics" ? metrics.Select(series => series.ResourceId).Distinct(StringComparer.Ordinal).Count() : resources.Count, expectedScopes, completedScopes, attemptedReads, completedReads },
                source = operation == "metrics" ? "metrics-server" : "kubectl-fixed-metadata-projection"
            }, warnings.Distinct(StringComparer.Ordinal).ToArray()) { OperationSucceeded = succeeded };
        }

        async Task<JsonElement?> Query(IReadOnlyList<string> arguments)
        {
            if (++attemptedReads > 150 || deadline.IsCancellationRequested) { limited = true; failedReads++; unavailableState = "timed_out"; return null; }
            try
            {
                var value = await client.RunAsync("kubectl", arguments, deadline.Token);
                if (value.ValueKind != JsonValueKind.Object) throw new JsonException("Invalid Kubernetes projection envelope.");
                completedReads++;
                return value;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception error) when (error is IOException or JsonException or ArgumentException or InvalidOperationException or OperationCanceledException or System.ComponentModel.Win32Exception)
            {
                failedReads++;
                unavailableState = error is KubernetesQueryException classified ? classified.State : error is OperationCanceledException ? "timed_out" : "unavailable";
                warnings.Add("A selected cluster metadata or metrics read was unavailable. Check the configured context, namespace RBAC, kubectl and optional Metrics Server outside Opscope. Provider error text is omitted.");
                return null;
            }
        }

        async Task<List<JsonElement>?> ReadMetadata(string kind, string? ns)
        {
            if (resources.Count >= ResourceBudget) { limited = true; return null; }
            var args = new List<string> { "--context", context, "--request-timeout=10s", "get", kind };
            if (kind == "namespaces") args.Add(ns!);
            else if (ns is not null) args.AddRange(["--namespace", ns]);
            args.AddRange(["--chunk-size=100", "--no-headers", "--output=custom-columns=" + KubernetesCommandRunner.Columns[kind]]);
            var result = await Query(args);
            if (result is not { } response) return null;
            if (Text(response, "kind") != kind || !response.TryGetProperty("rows", out var array) || array.ValueKind != JsonValueKind.Array)
            { failedReads++; limited = true; return null; }
            if (Bool(response, "truncated") || Integer(response, "malformedRows") is > 0) limited = true;
            var rows = new List<JsonElement>();
            foreach (var row in array.EnumerateArray())
            {
                if (resources.Count >= ResourceBudget) { limited = true; break; }
                var name = Text(row, "name");
                if (!KubernetesCommandRunner.ValidObjectName(name) || kind == "namespaces" && name != ns) { limited = true; continue; }
                var properties = Properties(kind, row);
                var resource = new CloudResource("kubernetes", context, ns ?? "cluster", $"{ns ?? "cluster"}/{kind}/{name}", "kubernetes." + (kind == "events.events.k8s.io" ? "event" : kind.TrimEnd('s')), name, properties);
                if (!resourceKeys.Add(resource.Id)) { limited = true; continue; }
                resources.Add(resource); rows.Add(row);
                if (findings.Count >= 200) { limited = true; continue; }
                if (kind == "pods" && properties["state"] is "Failed") AddFinding("KUBERNETES_POD_FAILED", "An observed pod reports Failed", resource.Id);
                if (kind == "pods" && properties["state"] is "Running" && properties["readyContainers"] is int ready && properties["observedContainerStatuses"] is int observed && ready < observed)
                    AddFinding("KUBERNETES_POD_NOT_READY", "An observed running pod has containers without Ready status", resource.Id);
                if (kind == "nodes" && properties["state"] is "not-ready") AddFinding("KUBERNETES_NODE_NOT_READY", "An observed node reports Ready=False", resource.Id);
                if (kind is "deployments" or "statefulsets" or "daemonsets" && properties["state"] is "degraded") AddFinding("KUBERNETES_WORKLOAD_REPLICAS", "Observed available replicas are below desired replicas", resource.Id);
                if (kind == "events.events.k8s.io" && properties["type"] is "Warning") AddFinding("KUBERNETES_WARNING_EVENT", "A selected namespace contains an observed Warning event", resource.Id);
            }
            return rows;
        }

        void AddFinding(string code, string title, string resource) => findings.Add(new(FindingSeverity.Warning, code, title,
            resource + ": metadata/status observation only; no pod log or command was read.", "Review the configured workload and controller observations through the administrator's normal workflow; Opscope makes no changes."));

        async Task ReadMetrics(string ns)
        {
            string? next = null;
            var seen = new HashSet<string>(StringComparer.Ordinal);
            for (var page = 0; page < 10; page++)
            {
                if (metrics.Count >= MetricBudget) { limited = true; return; }
                var path = $"/apis/metrics.k8s.io/v1beta1/namespaces/{ns}/pods?limit=100" + (next is null ? string.Empty : "&continue=" + Uri.EscapeDataString(next));
                var result = await Query(["--context", context, "--request-timeout=10s", "get", "--raw", path]);
                if (result is not { } root) return;
                if (Text(root, "kind") != "PodMetricsList" || Text(root, "apiVersion") != "metrics.k8s.io/v1beta1" ||
                    !root.TryGetProperty("items", out var array) || array.ValueKind != JsonValueKind.Array) { failedReads++; limited = true; return; }
                foreach (var pod in array.EnumerateArray().Take(101))
                {
                    if (array.GetArrayLength() > 100) limited = true;
                    if (metrics.Count >= MetricBudget) { limited = true; break; }
                    var metadata = Property(pod, "metadata");
                    var name = Text(metadata, "name");
                    if (Text(metadata, "namespace") != ns || !KubernetesCommandRunner.ValidObjectName(name) ||
                        !DateTimeOffset.TryParse(Text(pod, "timestamp"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var timestamp) || timestamp < now.AddMinutes(-15) || timestamp > now.AddMinutes(2) ||
                        !pod.TryGetProperty("containers", out var containers) || containers.ValueKind != JsonValueKind.Array || containers.GetArrayLength() is < 1 or > 100)
                    { limited = true; continue; }
                    var cpuKnown = true; var memoryKnown = true; double cpu = 0; long memory = 0;
                    foreach (var container in containers.EnumerateArray())
                    {
                        var usage = Property(container, "usage");
                        if (TryCpuMillicores(Text(usage, "cpu"), out var part)) cpu += part; else cpuKnown = false;
                        if (TryMemoryBytes(Text(usage, "memory"), out var bytes) && memory <= long.MaxValue - bytes) memory += bytes; else memoryKnown = false;
                    }
                    var id = $"{ns}/pods/{name}";
                    var window = Text(pod, "window");
                    if (!ValidObservationWindow(window)) { window = "unknown"; limited = true; }
                    if (cpuKnown && double.IsFinite(cpu)) AddMetric(new(id, "pod.cpu", "millicores", "observed", null, "metrics-server", window, [new(timestamp, cpu)])); else limited = true;
                    if (memoryKnown && metrics.Count < MetricBudget) AddMetric(new(id, "pod.memory", "bytes", "observed", null, "metrics-server", window, [new(timestamp, memory)])); else limited = true;
                }
                next = Text(Property(root, "metadata"), "continue");
                if (next.Length == 0) return;
                if (next.Length > 1024 || next.Any(char.IsControl) || !seen.Add(next) || page == 9) { limited = true; return; }
            }
        }

        void AddMetric(KubernetesMetricSeries series)
        {
            var key = series.ResourceId + "/" + series.Metric + "/" + series.Points[0].TimeUtc.ToString("O", CultureInfo.InvariantCulture);
            if (metricKeys.Add(key)) metrics.Add(series);
            else limited = true;
        }
    }

    private static Dictionary<string, object?> Properties(string kind, JsonElement row)
    {
        var result = new Dictionary<string, object?>(StringComparer.Ordinal);
        if (kind == "namespaces") result["state"] = Text(row, "state") is "Active" or "Terminating" ? Text(row, "state") : "unknown";
        else if (kind == "nodes")
        {
            result["state"] = Text(row, "ready") switch { "True" => "ready", "False" => "not-ready", _ => "unknown" };
            result["capacityCpuMillicores"] = TryCpuMillicores(Text(row, "cpu"), out var cpu) ? cpu : null;
            result["capacityMemoryBytes"] = TryMemoryBytes(Text(row, "memory"), out var memory) ? memory : null;
            var version = Text(row, "version");
            result["kubeletVersion"] = Regex.IsMatch(version, @"\Av[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)) ? version : "unknown";
        }
        else if (kind == "pods")
        {
            var phase = Text(row, "state");
            result["state"] = phase is "Pending" or "Running" or "Succeeded" or "Failed" or "Unknown" ? phase : "unknown";
            var statuses = Text(row, "ready").Split(',');
            result["readyContainers"] = statuses.All(value => value is "true" or "false") ? statuses.Count(value => value == "true") : null;
            result["observedContainerStatuses"] = statuses.All(value => value is "true" or "false") ? statuses.Length : null;
            var restarts = Text(row, "restarts").Split(',').Select(value => int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var count) && count is >= 0 and <= 1000000 ? (int?)count : null).ToArray();
            result["restartCount"] = restarts.All(value => value is not null) ? restarts.Sum(value => (long)value!.Value) : null;
        }
        else if (kind is "deployments" or "statefulsets" or "daemonsets")
        {
            var desired = Integer(row, "desired"); var available = Integer(row, "available");
            result["desired"] = desired; result["available"] = available; result["updated"] = Integer(row, "updated");
            result["state"] = desired is null || available is null ? "unknown" : available < desired ? "degraded" : "available";
        }
        else if (kind == "services")
        {
            var type = Text(row, "type"); result["type"] = type is "ClusterIP" or "NodePort" or "LoadBalancer" or "ExternalName" ? type : "unknown";
            var ports = Text(row, "ports").Split(','); result["portCount"] = ports.All(value => int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port is > 0 and <= 65535) ? ports.Length : null;
        }
        else
        {
            result["type"] = Text(row, "type") is "Normal" or "Warning" ? Text(row, "type") : "unknown";
            result["reason"] = EventReasons.Contains(Text(row, "reason")) ? Text(row, "reason") : "Other";
            result["count"] = Integer(row, "count");
            result["observedAtUtc"] = DateTimeOffset.TryParse(Text(row, "observedAt"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var time) ? time : null;
        }
        return result;
    }

    internal static bool TryCpuMillicores(string value, out double millicores)
    {
        millicores = 0;
        if (!TryQuantity(value, out var amount, out var suffix)) return false;
        var factor = suffix switch
        {
            "" => 1000m, "m" => 1m, "u" => .001m, "n" => .000001m,
            "k" => 1000000m, "M" => 1000000000m, "G" => 1000000000000m,
            "T" => 1000000000000000m, "P" => 1000000000000000000m, "E" => 1000000000000000000000m,
            _ => -1m
        };
        if (factor < 0) return false;
        try { var result = amount * factor; if (result > 1000000000m) return false; millicores = (double)result; return true; }
        catch (OverflowException) { return false; }
    }

    internal static bool TryMemoryBytes(string value, out long bytes)
    {
        bytes = 0;
        if (!TryQuantity(value, out var amount, out var suffix)) return false;
        var factor = suffix switch
        {
            "" => 1m, "m" => .001m, "u" => .000001m, "n" => .000000001m,
            "k" or "K" => 1000m, "M" => 1000000m, "G" => 1000000000m, "T" => 1000000000000m, "P" => 1000000000000000m, "E" => 1000000000000000000m,
            "Ki" => 1024m, "Mi" => 1048576m, "Gi" => 1073741824m, "Ti" => 1099511627776m, "Pi" => 1125899906842624m, "Ei" => 1152921504606846976m, _ => -1m
        };
        if (factor < 0) return false;
        try { var result = amount * factor; if (result > long.MaxValue) return false; bytes = (long)decimal.Ceiling(result); return true; }
        catch (OverflowException) { return false; }
    }

    private static bool ValidObservationWindow(string window)
    {
        if (window.Length is < 2 or > 64) return false;
        var match = Regex.Match(window, @"\A(?<amount>[0-9]+(?:\.[0-9]+)?)(?<unit>ns|us|ms|s|m|h)\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
        if (!match.Success || !decimal.TryParse(match.Groups["amount"].Value, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var amount)) return false;
        var factor = match.Groups["unit"].Value switch { "ns" => .000000001m, "us" => .000001m, "ms" => .001m, "s" => 1m, "m" => 60m, _ => 3600m };
        try { return amount * factor is > 0 and <= 900; }
        catch (OverflowException) { return false; }
    }

    private static bool TryQuantity(string text, out decimal amount, out string suffix)
    {
        amount = 0; suffix = string.Empty;
        if (text.Length is 0 or > 64) return false;
        var match = Regex.Match(text, @"\A(?<number>(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)(?<suffix>[A-Za-z]*)\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
        if (!match.Success || !decimal.TryParse(match.Groups["number"].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out amount) || amount < 0) return false;
        suffix = match.Groups["suffix"].Value;
        return true;
    }

    private static JsonElement Property(JsonElement value, string key) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var property) ? property : default;
    private static string Text(JsonElement value, string key) => Property(value, key) is { ValueKind: JsonValueKind.String } text ? text.GetString() ?? string.Empty : string.Empty;
    private static bool Bool(JsonElement value, string key) => Property(value, key).ValueKind == JsonValueKind.True;
    private static int? Integer(JsonElement value, string key)
    {
        var property = Property(value, key);
        return property.ValueKind == JsonValueKind.Number && property.TryGetInt32(out var number) && number >= 0 ? number :
            property.ValueKind == JsonValueKind.String && int.TryParse(property.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out number) && number >= 0 ? number : null;
    }
}

public sealed record KubernetesMetricPoint(DateTimeOffset TimeUtc, double Value);
public sealed record KubernetesMetricSeries(string ResourceId, string Metric, string Unit, string Aggregation,
    double? SamplingPeriodSeconds, string Source, string ObservedWindow, IReadOnlyList<KubernetesMetricPoint> Points);
