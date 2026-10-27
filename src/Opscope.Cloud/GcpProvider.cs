using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Opscope.Cloud;

/// <summary>Optional Google Cloud read-only collector using the caller's existing gcloud session.</summary>
/// <remarks>gcloud credentials are separate from Application Default Credentials. This collector never logs in.</remarks>
public sealed class GcpProvider(ICloudCommandRunner runner, IGcpMonitoringReader? monitoring = null, IGcpAdvancedReader? advanced = null) : ICloudProvider
{
    private const int MaxRowsPerRead = 500;
    private const int MaxResources = 10000;
    private const int MaxQueries = 60;
    private const string AssetTypes = "compute.googleapis.com/Instance,compute.googleapis.com/Disk,compute.googleapis.com/Address,compute.googleapis.com/Network,compute.googleapis.com/Firewall,container.googleapis.com/Cluster,sqladmin.googleapis.com/Instance,run.googleapis.com/Service,storage.googleapis.com/Bucket";
    private readonly IGcpMonitoringReader metrics = monitoring ?? new GcpMonitoringReader();
    private readonly IGcpAdvancedReader advancedReads = advanced ?? new GcpAdvancedReader();
    public string Name => "gcp";

    public async Task<AnalysisReport> CollectAsync(string operation, IReadOnlyDictionary<string, string> options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(60));
        operation = operation.ToLowerInvariant();
        if (operation is not ("inventory" or "health" or "posture" or "vm" or "bundle" or "metrics" or "patches" or "cost" or "drift" or "scc" or "services"))
            throw new ArgumentException("Unsupported Google Cloud operation.", nameof(operation));
        var context = new Collection(runner, options, deadline.Token);
        if (operation is "patches" or "drift")
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
        if (operation is "scc" or "cost")
        {
            if (Option(options, "resource") is not null || Option(options, "region") is not null)
                throw new ArgumentException("SCC/billing use explicit project scopes only; resource or regional filtering is unsupported. No provider query was sent.");
            return await Advanced(operation, projects, options, deadline.Token, cancellationToken);
        }
        var region = Option(options, "region");
        if (region is not null && !Regex.IsMatch(region, @"\A[a-z]+(?:-[a-z0-9]+)+[0-9]\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)))
            throw new ArgumentException("Google Cloud region must be a region name, not a URL or zone.");
        var target = Option(options, "resource");
        if (target is not null && !projects.Any(project => IsResourceInProject(target, project)))
            throw new ArgumentException("Google Cloud resource must be a canonical resource ID in one of the explicitly selected projects.");
        if (target is not null && operation is "posture" or "bundle")
            throw new ArgumentException("Google Cloud resource-specific firewall attachment analysis is not implemented. Use the explicit project scope for posture or bundle; no provider request was sent.");
        if (operation == "services" && target is not null)
            throw new ArgumentException("Service metadata reads accept explicit project/region scopes, not a Compute resource filter. No provider request was sent.");
        var services = operation == "services" ? ParseServices(Option(options, "gcp-services")) : [];
        if (services.Contains("run", StringComparer.Ordinal) && region is null)
            throw new ArgumentException("Cloud Run service metadata requires an explicit --region. No provider request was sent.");
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
                else if (operation == "services") await Services(context, project, region, services);
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
        if (operation == "services")
            context.Warnings.Add("Service evidence is selected control-plane metadata only. Reported state, backup configuration, cluster version and public-access prevention do not prove application availability, recoverability or effective IAM access. No pods, bucket objects, service URLs or secrets were read.");
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

    private async Task<AnalysisReport> Advanced(string operation, string[] projects, IReadOnlyDictionary<string, string> options, CancellationToken deadline, CancellationToken cancellationToken)
    {
        var results = new List<GcpAdvancedResult>();
        var truncated = false;
        try
        {
            if (operation == "cost") results.Add(await advancedReads.ReadBillingAsync(projects, options, deadline));
            else foreach (var project in projects)
            {
                deadline.ThrowIfCancellationRequested();
                results.Add(await advancedReads.ReadSccAsync(project, deadline));
                if (results.Sum(result => result.Scc?.FindingsCount ?? 0) >= 1000) { truncated = results.Count < projects.Length; break; }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { truncated = true; }
        var now = DateTimeOffset.UtcNow;
        var records = results.SelectMany(result => result.Scc?.Findings ?? []).Take(1000).ToArray();
        var warnings = results.SelectMany(result => result.Warnings).ToList();
        if (truncated || results.Sum(result => result.Scc?.FindingsCount ?? 0) > 1000)
        { warnings.Add("Advanced Google Cloud collection reached its aggregate row or total time bound; remaining project evidence was omitted."); truncated = true; }
        var completed = results.Count(result => result.State is CoverageState.Complete or CoverageState.Partial);
        var state = results.Count == 0 ? CoverageState.Failed : truncated || results.Select(result => result.State).Distinct().Count() != 1 ? CoverageState.Partial : results[0].State;
        return new($"cloud.gcp.{operation}", now, results.SelectMany(result => result.Findings).Take(1000).ToArray(), new
        {
            provider = "gcp", operation, resources = System.Array.Empty<CloudResource>(),
            scope = new { accounts = projects },
            scc = operation == "scc" ? new GcpSccEvidence(records.Length, "project", "global", "security-command-center-v1", records) : null,
            billing = results.FirstOrDefault()?.Billing,
            coverage = new CloudCoverage(state, now, records.Length, operation == "cost" ? 1 : projects.Length, completed, warnings),
            source = operation == "scc" ? "security-command-center-v1" : "bigquery-tabledata-read-only",
            authentication = "application-default-credentials"
        }, warnings.Distinct(StringComparer.Ordinal).ToArray()) { OperationSucceeded = completed > 0 && state is CoverageState.Complete or CoverageState.Partial };
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

    private static string[] ParseServices(string? value)
    {
        var services = (value ?? "gke,sql,storage").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.Ordinal).ToArray();
        if (services.Length == 0 || services.Any(service => service is not ("gke" or "sql" or "run" or "storage")))
            throw new ArgumentException("--gcp-services accepts only gke,sql,run,storage. Cloud Run also requires --region.");
        return services;
    }

    private static async Task Services(Collection context, string project, string? region, string[] services)
    {
        var identity = await context.ProjectIdentity(project);
        if (identity is null) return;
        foreach (var service in services)
        {
            var command = service switch
            {
                "gke" => new[] { "container", "clusters", "list" },
                "sql" => ["sql", "instances", "list"],
                "run" => ["run", "services", "list"],
                _ => ["storage", "buckets", "list"]
            };
            foreach (var row in await context.Read(command, project, "Selected " + service + " service metadata", region: service == "run" ? region : null))
            {
                string name, location, id;
                object properties;
                if (service == "gke")
                {
                    name = Text(row, "name"); location = Text(row, "location");
                    var selfLink = Text(row, "selfLink");
                    if (!ServiceName(name) || !OwnedLink(selfLink, "container.googleapis.com", project)) { Invalid(); continue; }
                    if (!InRegion(location, region)) continue;
                    id = $"//container.googleapis.com/projects/{project}/locations/{location}/clusters/{name}";
                    properties = new { state = Text(row, "status"), masterVersion = Text(row, "currentMasterVersion"), nodeVersion = Text(row, "currentNodeVersion"), nodeCount = Integer(row, "currentNodeCount") };
                }
                else if (service == "sql")
                {
                    name = Text(row, "name"); location = Text(row, "region");
                    if (!ServiceName(name, 98) || Text(row, "project") != project || !OwnedLink(Text(row, "selfLink"), "sqladmin.googleapis.com", project)) { Invalid(); continue; }
                    if (!InRegion(location, region)) continue;
                    id = $"//sqladmin.googleapis.com/projects/{project}/instances/{name}";
                    var settings = Property(row, "settings");
                    properties = new { state = Text(row, "state"), databaseVersion = Text(row, "databaseVersion"), tier = Text(settings, "tier"), availabilityType = Text(settings, "availabilityType"), backupsEnabled = NullableBoolean(Property(settings, "backupConfiguration"), "enabled"), storageAutoResize = NullableBoolean(settings, "storageAutoResize"), diskSizeGb = Numeric(settings, "dataDiskSizeGb") };
                }
                else if (service == "run")
                {
                    var metadata = Property(row, "metadata"); name = Text(metadata, "name"); location = region!;
                    var observedProject = Text(metadata, "namespace");
                    if (!ServiceName(name) || observedProject != project && observedProject != identity) { Invalid(); continue; }
                    var status = Property(row, "status");
                    id = $"//run.googleapis.com/projects/{project}/locations/{location}/services/{name}";
                    var ready = Array(status, "conditions").FirstOrDefault(condition => Text(condition, "type") == "Ready");
                    properties = new { state = Text(ready, "status"), ingress = "unavailable", observedGeneration = Numeric(status, "observedGeneration"), readyRevisionObserved = Text(status, "latestReadyRevisionName").Length > 0 };
                }
                else
                {
                    name = Text(row, "name"); location = Text(row, "location");
                    var observedProject = Numeric(row, "project_number"); if (observedProject.Length == 0) observedProject = Numeric(row, "projectNumber");
                    if (!Regex.IsMatch(name, @"\A[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)) || observedProject != identity) { Invalid(); continue; }
                    if (!InRegion(location.ToLowerInvariant(), region)) continue;
                    id = "//storage.googleapis.com/" + name;
                    var iam = Property(row, "iamConfiguration");
                    properties = new { state = "configuration-observed", storageClass = Text(row, "storage_class") is { Length: > 0 } storageClass ? storageClass : Text(row, "storageClass"), uniformBucketLevelAccess = NullableBoolean(row, "uniform_bucket_level_access") ?? NullableBoolean(Property(iam, "uniformBucketLevelAccess"), "enabled"), publicAccessPrevention = Text(row, "public_access_prevention") is { Length: > 0 } prevention ? prevention : Text(iam, "publicAccessPrevention") };
                }
                context.Add(new("gcp", project, location, id, service switch { "gke" => "gke.cluster", "sql" => "sql.instance", "run" => "run.service", _ => "storage.bucket" }, name, properties));
            }
        }
        void Invalid() { context.Partial = true; context.Warnings.Add("A service metadata row lacked a verified project identity or valid resource name and was omitted."); }
    }

    private static bool ServiceName(string value, int limit = 63) => value.Length <= limit && Regex.IsMatch(value, @"\A[a-z][a-z0-9-]*\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static bool InRegion(string location, string? region) => region is null || location == region || location.StartsWith(region + "-", StringComparison.Ordinal);
    private static bool OwnedLink(string value, string host, string project)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.Host != host || uri.Port != 443 || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0) return false;
        var versions = host == "container.googleapis.com" ? new[] { "/v1/", "/v1beta1/" } : new[] { "/sql/v1/", "/sql/v1beta4/", "/v1/", "/v1beta4/" };
        return versions.Any(version => uri.AbsolutePath.StartsWith(version + "projects/" + project + "/", StringComparison.Ordinal));
    }
    private static JsonElement Property(JsonElement value, string key) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var property) ? property : default;
    private static bool? NullableBoolean(JsonElement value, string key) => Property(value, key).ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => null };
    private static int? Integer(JsonElement value, string key) => Property(value, key) is { ValueKind: JsonValueKind.Number } number && number.TryGetInt32(out var parsed) && parsed >= 0 ? parsed : null;
    private static string Numeric(JsonElement value, string key)
    {
        var text = Property(value, key).ValueKind == JsonValueKind.Number ? Property(value, key).GetRawText() : Text(value, key);
        return text.Length <= 64 && decimal.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var number) && number >= 0 ? text : string.Empty;
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

        public async Task<string?> ProjectIdentity(string project)
        {
            if (++queries > MaxQueries)
            {
                Partial = true; IncompleteReads++;
                Warnings.Add("Google Cloud service metadata reached its whole-operation query budget; remaining project reads were omitted.");
                return null;
            }
            try
            {
                var result = await runner.RunAsync("gcloud", ["projects", "describe", project, "--format", AdditionalCloudCommandRunner.GcpProjection("projects describe")!, "--quiet", "--verbosity", "error"], cancellationToken);
                var number = Numeric(result, "projectNumber");
                if (Text(result, "projectId") != project || !Regex.IsMatch(number, @"\A[0-9]{1,30}\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)))
                    throw new InvalidDataException("Service metadata project identity was invalid.");
                SuccessfulReads++;
                return number;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception error) when (error is IOException or JsonException or InvalidOperationException or System.ComponentModel.Win32Exception or HttpRequestException)
            {
                FailedReads++; Partial = true;
                Warnings.Add("Service metadata requires the existing gcloud identity to read and verify the configured project descriptor. No unverified service resources were retained.");
                return null;
            }
        }

        public async Task<JsonElement[]> Read(string[] command, string project, string label, bool assetSearch = false, string? region = null)
        {
            if (++queries > MaxQueries)
            {
                Partial = true;
                IncompleteReads++;
                Warnings.Add("Google Cloud read budget exhausted; remaining reads were omitted.");
                return [];
            }
            var args = command.ToList();
            args.AddRange(["--project", project, "--limit", (MaxRowsPerRead + 1).ToString(CultureInfo.InvariantCulture), "--page-size", MaxRowsPerRead.ToString(CultureInfo.InvariantCulture), "--format", AdditionalCloudCommandRunner.GcpProjection(string.Join(' ', command)) ?? "json", "--quiet", "--verbosity", "error"]);
            if (region is not null) args.AddRange(["--region", region]);
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
