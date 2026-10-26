using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Opscope.Cloud;

/// <summary>Optional Google Cloud read-only collector using the caller's existing gcloud session.</summary>
/// <remarks>gcloud credentials are separate from Application Default Credentials. This collector never logs in.</remarks>
public sealed class GcpProvider(ICloudCommandRunner runner, IGcpMonitoringReader? monitoring = null) : ICloudProvider
{
    private const int MaxRowsPerRead = 500;
    private const int MaxResources = 10000;
    private const int MaxQueries = 60;
    private const string AssetTypes = "compute.googleapis.com/Instance,compute.googleapis.com/Disk,compute.googleapis.com/Address,compute.googleapis.com/Network,compute.googleapis.com/Firewall,container.googleapis.com/Cluster,sqladmin.googleapis.com/Instance,run.googleapis.com/Service,storage.googleapis.com/Bucket";
    private readonly IGcpMonitoringReader metrics = monitoring ?? new GcpMonitoringReader();
    public string Name => "gcp";

    public async Task<AnalysisReport> CollectAsync(string operation, IReadOnlyDictionary<string, string> options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(60));
        operation = operation.ToLowerInvariant();
        if (operation is not ("inventory" or "health" or "posture" or "vm" or "bundle" or "metrics" or "patches" or "cost" or "drift"))
            throw new ArgumentException("Unsupported Google Cloud operation.", nameof(operation));
        var context = new Collection(runner, options, deadline.Token);
        if (operation is "patches" or "cost" or "drift")
        {
            context.Warnings.Add(operation switch
            {
                "patches" => "OS Config / VM Manager patch evidence is not configured. Patch compliance is unknown.",
                "cost" => "Cloud Billing exports are not configured. Billing cost is unavailable, not zero; no BigQuery jobs or dataset changes were made.",
                _ => "Google Cloud drift comparison requires an explicit baseline workflow; no change or compliance claim was inferred."
            });
            return context.Report(operation, CoverageState.Unsupported);
        }
        var projects = ParseProjects(Option(options, "projects") ?? Option(options, "project"));
        if (projects.Length == 0)
        {
            context.Warnings.Add("Select a preconfigured Google Cloud project with --project or --projects. No project discovery or login was attempted.");
            return context.Report(operation, CoverageState.NotConfigured);
        }
        context.ExpectedScopes = projects.Length;
        var region = Option(options, "region");
        if (region is not null && !Regex.IsMatch(region, @"\A[a-z]+(?:-[a-z0-9]+)+[0-9]\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)))
            throw new ArgumentException("Google Cloud region must be a region name, not a URL or zone.");
        var target = Option(options, "resource");
        if (target is not null && !projects.Any(project => IsResourceInProject(target, project)))
            throw new ArgumentException("Google Cloud resource must be a canonical resource ID in one of the explicitly selected projects.");
        if (target is not null && operation is "posture" or "bundle")
            throw new ArgumentException("Google Cloud resource-specific firewall attachment analysis is not implemented. Use the explicit project scope for posture or bundle; no provider request was sent.");
        try
        {
            foreach (var project in projects)
            {
                deadline.Token.ThrowIfCancellationRequested();
                var before = context.SuccessfulReads;
                var beforeFailures = context.FailedReads;
                var beforeTruncation = context.IncompleteReads;
                var metricTarget = target;
                if (operation == "inventory") await Inventory(context, project, region, target);
                else if (operation != "metrics")
                {
                    var instances = await context.Read(["compute", "instances", "list"], project, "Compute instance state");
                    foreach (var instance in instances)
                    {
                        if (!Regex.IsMatch(Text(instance, "name"), @"\A[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)) ||
                            !Regex.IsMatch(LastSegment(Text(instance, "zone")), @"\A[a-z]+(?:-[a-z0-9]+)+[0-9]-[a-z]\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)))
                        { context.Partial = true; continue; }
                        if (!MatchesRegion(instance, region)) continue;
                        var resource = Instance(project, instance);
                        if (target is not null && !SameResource(target, resource.Id)) continue;
                        var numericId = instance.TryGetProperty("id", out var numeric) && numeric.ValueKind == JsonValueKind.String ? numeric.GetString() : null;
                        if (target is not null && numericId is not null && numericId.All(char.IsAsciiDigit))
                            metricTarget = resource.Id[..(resource.Id.LastIndexOf('/') + 1)] + numericId;
                        context.Add(resource);
                        if (operation is "health" or "vm" or "bundle")
                        {
                            var state = Text(instance, "status");
                            if (state.Length != 0 && state is not ("RUNNING" or "PROVISIONING" or "STAGING"))
                                context.Findings.Add(new(FindingSeverity.Info, "GCP_VM_STATE", "Compute instance is not running",
                                    $"{resource.Id}: observed platform state {state}.", "Check whether this state is expected. VM state does not establish application availability."));
                        }
                    }
                    if (operation is "posture" or "bundle") await Posture(context, project);
                }
                if (operation is "metrics" or "health" or "bundle")
                    context.AddMetrics(await metrics.ReadCpuAsync(project, deadline.Token), region, metricTarget);
                if (context.SuccessfulReads > before && context.FailedReads == beforeFailures && context.IncompleteReads == beforeTruncation) context.CompletedScopes++;
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            context.Partial = true;
            context.Warnings.Add("Google Cloud collection reached its 60-second total budget. Remaining reads were omitted; coverage is incomplete.");
        }
        if (operation == "vm")
            context.Warnings.Add("VM evidence covers observed Compute Engine state and selected configuration only. CPU metrics were not requested; VM state does not establish application availability.");
        if (operation is "health" or "bundle")
            context.Warnings.Add("Health covers observed Compute Engine VM state and available Cloud Monitoring CPU samples only. Application availability, latency and platform incidents are outside coverage; RUNNING does not prove a service is available.");
        if (operation is "posture" or "bundle")
            context.Warnings.Add("Posture covers selected ingress firewall configuration only. Effective reachability, IAM privileges, SCC findings and guest security are unknown; no services or permissions were enabled.");
        if (target is not null && context.Resources.Count == 0 && operation != "metrics")
        {
            context.Partial = true;
            context.Warnings.Add("The selected Google Cloud resource was not visible in the requested project scope. Check resource type, permissions and filters.");
        }
        if (target is not null && operation == "metrics" && context.Metrics.Count == 0)
        {
            context.Partial = true;
            context.Warnings.Add("No CPU series matched the selected resource. Monitoring resource IDs use numeric instance IDs; absent series are unavailable, not zero.");
        }
        if (target is not null && (operation is "health" or "bundle") && context.Metrics.Count == 0)
        {
            context.Partial = true;
            context.Warnings.Add("The selected resource has no matching CPU series. VM state evidence and CPU coverage are separate; unavailable CPU was not treated as zero.");
        }
        if (operation == "vm" && target is null)
        {
            context.Partial = true;
            context.Warnings.Add("The VM operation requires --resource with a canonical Compute instance ID. No single VM was selected.");
        }
        if (context.Resources.Count == 0 && context.SuccessfulReads > 0 && operation != "metrics")
            context.Warnings.Add("No resources were visible in these reads. An empty response does not establish a secure account or complete service coverage.");
        return context.Report(operation, context.SuccessfulReads == 0 ? context.FailureState : context.Partial || context.FailedReads > 0 ? CoverageState.Partial : CoverageState.Complete);
    }

    private static async Task Inventory(Collection context, string project, string? region, string? target)
    {
        var rows = await context.Read(["asset", "search-all-resources"], project, "Cloud Asset Inventory", assetSearch: true);
        foreach (var asset in rows)
        {
            var id = Text(asset, "name");
            var type = Text(asset, "assetType");
            var bucket = type == "storage.googleapis.com/Bucket" && id.StartsWith("//storage.googleapis.com/", StringComparison.Ordinal) &&
                Regex.IsMatch(id["//storage.googleapis.com/".Length..], @"\A[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
            if ((!IsResourceInProject(id, project) && !bucket) || !AssetTypes.Split(',').Contains(type, StringComparer.Ordinal))
            {
                context.Partial = true;
                continue;
            }
            var location = Text(asset, "location");
            if (region is not null && location != region && !location.StartsWith(region + "-", StringComparison.Ordinal)) continue;
            if (target is not null && !SameResource(target, id)) continue;
            // Remote labels, descriptions, URLs, metadata and IAM policy are deliberately excluded.
            context.Add(new("gcp", project, location, id, type, Text(asset, "displayName"), new
            {
                state = Text(asset, "state"),
                observedAtUtc = DateTimeOffset.UtcNow
            }));
        }
        context.Warnings.Add("Inventory uses a bounded Cloud Asset search for selected Compute, GKE, Cloud SQL, Cloud Run and Storage resource types. Asset visibility and freshness depend on API permissions; unqueried services are outside coverage.");
    }

    private static async Task Posture(Collection context, string project)
    {
        foreach (var firewall in await context.Read(["compute", "firewall-rules", "list"], project, "Compute ingress firewall configuration"))
        {
            if (Boolean(firewall, "disabled") || Text(firewall, "direction") is not ("" or "INGRESS")) continue;
            var internet = Array(firewall, "sourceRanges").Any(value => value.ValueKind == JsonValueKind.String && value.GetString() is "0.0.0.0/0" or "::/0");
            if (!internet) continue;
            var allowances = Array(firewall, "allowed").ToArray();
            if (allowances.Length == 0) continue;
            var administrative = allowances.Any(rule =>
                Text(rule, "IPProtocol") is "all" or "-1" ||
                Text(rule, "IPProtocol") is "tcp" or "6" && (Array(rule, "ports").Count() == 0 || Array(rule, "ports").Any(port => IncludesPort(port, 22) || IncludesPort(port, 3389))) ||
                Text(rule, "IPProtocol") is "udp" or "17" && (Array(rule, "ports").Count() == 0 || Array(rule, "ports").Any(port => IncludesPort(port, 3389))));
            var name = Text(firewall, "name");
            var id = $"//compute.googleapis.com/projects/{project}/global/firewalls/{name}";
            context.Add(new("gcp", project, "global", id, "compute.googleapis.com/Firewall", name,
                new { state = "enabled-ingress", internetSource = true, administrativePorts = administrative }));
            context.Findings.Add(new(administrative ? FindingSeverity.Critical : FindingSeverity.Warning,
                administrative ? "GCP_FIREWALL_ADMIN_INTERNET" : "GCP_FIREWALL_INTERNET", "Ingress firewall permits internet source ranges",
                $"{id}: enabled ingress rule includes an unrestricted IPv4 or IPv6 source range.",
                "Review rule targets, priorities, routes and effective policy. Published configuration does not prove effective reachability; apply changes through the approved workflow."));
        }
    }

    private static CloudResource Instance(string project, JsonElement instance)
    {
        var zone = LastSegment(Text(instance, "zone"));
        var name = Text(instance, "name");
        var id = $"//compute.googleapis.com/projects/{project}/zones/{zone}/instances/{name}";
        return new("gcp", project, zone, id, "compute.googleapis.com/Instance", name, new
        {
            state = Text(instance, "status"),
            machineType = LastSegment(Text(instance, "machineType")),
            diskCount = Array(instance, "disks").Count(),
            networkInterfaceCount = Array(instance, "networkInterfaces").Count(),
            hasPublicAddress = Array(instance, "networkInterfaces").Any(network => Array(network, "accessConfigs").Any(config => Text(config, "natIP").Length > 0)),
            serviceAccountCount = Array(instance, "serviceAccounts").Count()
        });
    }

    private static string[] ParseProjects(string? input)
    {
        if (input is null) return [];
        var projects = input.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.Ordinal).ToArray();
        if (projects.Length is 0 or > 20 || projects.Any(project => !Regex.IsMatch(project, @"\A[a-z][a-z0-9-]{4,28}[a-z0-9]\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100))))
            throw new ArgumentException("Google Cloud scope must contain 1–20 explicit project IDs (6–30 lower-case letters, digits or hyphens).");
        return projects;
    }

    private static bool IsResourceInProject(string id, string project)
    {
        if (id.Length > 2048 || id.Any(char.IsControl) || id.Contains('\\') || id.Contains('%') || id.Contains('?') || id.Contains('#')) return false;
        var local = id.StartsWith("//", StringComparison.Ordinal) ? id[(id.IndexOf('/', 2) + 1)..] : id;
        if (id.StartsWith("//", StringComparison.Ordinal) && !new[] { "compute.googleapis.com", "container.googleapis.com", "sqladmin.googleapis.com", "run.googleapis.com", "storage.googleapis.com" }.Any(host => id.StartsWith("//" + host + "/", StringComparison.Ordinal))) return false;
        return local.StartsWith($"projects/{project}/", StringComparison.Ordinal) && !local.Split('/').Any(segment => segment is "." or ".." or "");
    }

    private static bool SameResource(string left, string right) => string.Equals(left.StartsWith("projects/", StringComparison.Ordinal) ? "//compute.googleapis.com/" + left : left, right, StringComparison.Ordinal);
    private static bool MatchesRegion(JsonElement row, string? region) => region is null || LastSegment(Text(row, "zone")).StartsWith(region + "-", StringComparison.Ordinal);
    private static bool IncludesPort(JsonElement value, int port)
    {
        if (value.ValueKind != JsonValueKind.String) return false;
        var text = value.GetString() ?? "";
        if (int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var single)) return single == port;
        var parts = text.Split('-');
        return parts.Length == 2 && int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var from) &&
            int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var to) && from <= port && to >= port;
    }
    private static string LastSegment(string value) => value.Split('/').LastOrDefault() ?? "";
    private static string? Option(IReadOnlyDictionary<string, string> options, string key) => options.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value.Trim() : null;
    private static string Text(JsonElement row, string key) => row.ValueKind == JsonValueKind.Object && row.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.String
        ? Clean(value.GetString() ?? "") : "";
    private static string Clean(string value) => new(value.Where(character => !char.IsControl(character)).Take(2048).ToArray());
    private static bool Boolean(JsonElement row, string key) => row.ValueKind == JsonValueKind.Object && row.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.True;
    private static IEnumerable<JsonElement> Array(JsonElement row, string key) => row.ValueKind == JsonValueKind.Object && row.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.Array ? value.EnumerateArray() : [];

    private sealed class Collection(ICloudCommandRunner runner, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken)
    {
        public List<CloudResource> Resources { get; } = [];
        public List<Finding> Findings { get; } = [];
        public List<string> Warnings { get; } = [];
        public int ExpectedScopes { get; set; }
        public int CompletedScopes { get; set; }
        public int SuccessfulReads { get; private set; }
        public int FailedReads { get; private set; }
        public int IncompleteReads { get; private set; }
        public List<GcpCpuSeries> Metrics { get; } = [];
        public CoverageState FailureState { get; private set; } = CoverageState.Failed;
        public bool Partial { get; set; }
        private int queries;
        private int metricPointCount;

        public void AddMetrics(GcpMetricResult result, string? region, string? target)
        {
            Warnings.AddRange(result.Warnings);
            if (result.State is CoverageState.Complete or CoverageState.Partial) SuccessfulReads++;
            else { FailedReads++; FailureState = result.State; }
            if (result.State == CoverageState.Partial) { Partial = true; IncompleteReads++; }
            foreach (var series in result.Series.Where(series => (region is null || series.Region.StartsWith(region + "-", StringComparison.Ordinal)) &&
                (target is null || SameResource(target, series.ResourceId))))
            {
                var remaining = 10000 - metricPointCount;
                if (Metrics.Count >= 1000 || remaining <= 0)
                {
                    MetricLimit();
                    break;
                }
                var points = series.Points.Take(remaining).ToArray();
                Metrics.Add(series with { Points = points });
                metricPointCount += points.Length;
                if (points.Length != series.Points.Count) { MetricLimit(); break; }
            }
            void MetricLimit()
            {
                Partial = true;
                IncompleteReads++;
                Warnings.Add("The whole Google Cloud operation reached its aggregate limit of 1,000 metric series or 10,000 metric points across all projects. Remaining metric evidence was omitted; coverage is partial.");
            }
        }

        public void Add(CloudResource resource)
        {
            if (Resources.Count < MaxResources) Resources.Add(resource);
            else Partial = true;
        }

        public async Task<JsonElement[]> Read(string[] command, string project, string label, bool assetSearch = false)
        {
            if (++queries > MaxQueries)
            {
                Partial = true;
                IncompleteReads++;
                Warnings.Add("Google Cloud read budget exhausted; remaining reads were omitted.");
                return [];
            }
            var args = command.ToList();
            args.AddRange(["--project", project, "--limit", (MaxRowsPerRead + 1).ToString(CultureInfo.InvariantCulture), "--page-size", MaxRowsPerRead.ToString(CultureInfo.InvariantCulture), "--format", "json", "--quiet", "--verbosity", "error"]);
            if (assetSearch) args.AddRange(["--scope", $"projects/{project}", "--asset-types", AssetTypes]);
            try
            {
                var result = await runner.RunAsync("gcloud", args, cancellationToken);
                if (result.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Unexpected Google Cloud collection shape.");
                var rows = result.EnumerateArray().Take(MaxRowsPerRead + 1).ToArray();
                if (rows.Any(row => row.ValueKind != JsonValueKind.Object)) throw new InvalidDataException("Unexpected Google Cloud resource shape.");
                SuccessfulReads++;
                if (rows.Length > MaxRowsPerRead)
                {
                    Partial = true;
                    IncompleteReads++;
                    Warnings.Add($"{label} reached its row bound; coverage is partial.");
                }
                return rows.Take(MaxRowsPerRead).ToArray();
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception ex) when (ex is IOException or InvalidDataException or JsonException or InvalidOperationException or System.ComponentModel.Win32Exception or HttpRequestException)
            {
                FailedReads++;
                Warnings.Add($"{label} was unavailable. Check the installed gcloud CLI, existing session, enabled API and read permissions. No login or credential writes were attempted.");
                return [];
            }
        }

        public AnalysisReport Report(string operation, CoverageState state)
        {
            var now = DateTimeOffset.UtcNow;
            var warnings = Warnings.Distinct(StringComparer.Ordinal).ToArray();
            return new($"cloud.gcp.{operation}", now, Findings, new
            {
                provider = "gcp", operation,
                resources = Resources,
                metrics = Metrics,
                scope = new { schemaVersion = 1, accounts = ParseProjects(Option(options, "projects") ?? Option(options, "project")), region = Option(options, "region") },
                coverage = new CloudCoverage(state, now, Resources.Count, ExpectedScopes, CompletedScopes, warnings),
                source = operation == "metrics" ? "cloud-monitoring" : operation is "health" or "bundle" ? "gcloud-and-cloud-monitoring" : "gcloud-read-only",
                authentication = operation == "metrics" ? "application-default-credentials" : operation is "health" or "bundle" ? "existing-gcloud-session-and-adc" : "existing-gcloud-session",
                observation = "Selected resource configuration and state only; unqueried services and permissions are outside coverage."
            }, warnings) { OperationSucceeded = state == CoverageState.Complete };
        }
    }
}
