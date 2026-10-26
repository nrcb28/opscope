using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Opscope.Cloud;

/// <summary>Opt-in, narrow-coverage adapters. Authentication and endpoints are configured on the host.</summary>
public static class AdditionalCloudProviders
{
    private static readonly HashSet<string> Ids = new(StringComparer.Ordinal)
        { "oci", "digitalocean", "hetzner", "cloudflare", "openstack", "alibaba", "ibm", "scaleway" };
    public static bool Supports(string id) => Ids.Contains(id);
    public static bool SupportsTool(string tool) => tool is "oci" or "digitalocean-api" or "hetzner-api" or "cloudflare-api" or "openstack" or "aliyun" or "scaleway-api" or "ibm-api";
    public static ICloudProvider Create(string providerId, ICloudCommandRunner? runner = null) => Supports(providerId)
        ? new ReadOnlyAdapter(providerId, runner ?? new AdditionalCloudCommandRunner())
        : throw new ArgumentException("Unknown experimental cloud provider.", nameof(providerId));

    private sealed class ReadOnlyAdapter(string providerId, ICloudCommandRunner runner) : ICloudProvider
    {
        private const int RowBudget = 1000;
        public string Name => providerId;

        public async Task<AnalysisReport> CollectAsync(string operation, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(options);
            cancellationToken.ThrowIfCancellationRequested();
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromSeconds(60));
            var now = DateTimeOffset.UtcNow;
            var resources = new List<CloudResource>();
            var resourceKeys = new HashSet<string>(StringComparer.Ordinal);
            var findings = new List<Finding>();
            var warnings = new List<string>();
            var completed = 0;
            var attempted = 0;
            var failure = "partial";
            var limited = false;
            var failed = false;
            var metrics = new List<object>();
            var metricPointCount = 0;
            var omittedMetricTimes = false;
            var postureSupported = Name is "oci" or "digitalocean" or "hetzner" or "openstack" or "cloudflare" or "alibaba";
            if (operation is not ("inventory" or "health") && !(operation == "posture" && postureSupported) && !(operation == "metrics" && Name is "hetzner" or "digitalocean"))
                return Report("unsupported", false, "This adapter does not support the requested operation; no provider request was sent.");
            var required = Name switch
            {
                "oci" => new[] { "compartment", "region" },
                "digitalocean" or "hetzner" => new[] { "project" },
                "cloudflare" => new[] { "account" },
                "openstack" => new[] { "cloud-name", "project", "region" },
                "alibaba" => new[] { "account", "region" },
                "ibm" => new[] { "account", "resource-group", "region" },
                "scaleway" => new[] { "project", "zone" },
                _ => System.Array.Empty<string>()
            };
            if (required.Any(key => !Valid(Option(key))))
                return Report("not_configured", false, "Explicit authorized scope is required: " + string.Join(", ", required) + ". Configure credentials outside the browser.");
            if (Name == "digitalocean" && !Guid.TryParseExact(Option("project"), "D", out _) ||
                Name == "cloudflare" && !Regex.IsMatch(Option("account"), "^[a-fA-F0-9]{32}$", RegexOptions.CultureInvariant) ||
                Name == "scaleway" && !Guid.TryParseExact(Option("project"), "D", out _) ||
                Name == "oci" && !Option("compartment").StartsWith("ocid1.compartment.", StringComparison.Ordinal))
                return Report("not_configured", false, "The configured provider scope has an invalid format; no request was sent.");
            if (Name == "cloudflare" && Option("zones").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Any(z => !Regex.IsMatch(z, "^[a-fA-F0-9]{32}$", RegexOptions.CultureInvariant)))
                return Report("not_configured", false, "The configured zone allowlist is invalid; no request was sent.");
            warnings.Add("Experimental adapter: coverage is limited to the listed services and configured scope. A running resource is not proof of service availability.");
            try
            {
                switch (Name)
                {
                    case "oci":
                        await Oci("compute instance list", "compute.vm", ["lifecycle-state", "shape", "availability-domain"]);
                        if (operation == "inventory")
                        {
                            await Oci("bv volume list", "storage.volume", ["lifecycle-state", "size-in-gbs", "is-auto-tune-enabled"]);
                            await Oci("network vcn list", "network.vpc", ["lifecycle-state"]);
                        }
                        if (operation == "posture")
                        {
                            var rules = await Oci("network security-list list", "network.security-list", ["lifecycle-state"]);
                            foreach (var row in rules)
                                if (Array(row, "ingress-security-rules").Any(rule => World(Text(rule, "source"))))
                                    Exposure("OCI_WORLD_INGRESS", "A configured security-list rule permits ingress from a global CIDR. This does not establish reachability.");
                        }
                        break;
                    case "digitalocean":
                    {
                        var memberships = await ApiPages("digitalocean-api", "project-resources", Option("project"), "resources");
                        var urns = memberships.Select(x => Text(x, "urn")).Where(x => x.Length != 0).ToHashSet(StringComparer.Ordinal);
                        var droplets = await ApiPages("digitalocean-api", "droplets", "configured", "droplets");
                        var selected = droplets.Where(x => urns.Contains("do:droplet:" + Text(x, "id"))).ToArray();
                        Add(selected, "compute.vm", ["status", "vcpus", "memory", "disk"], region: row => TextAt(row, "region", "slug"));
                        if (operation == "metrics")
                        {
                            if (selected.Length > 10) { limited = true; warnings.Add("Metrics are limited to the first 10 project droplets; coverage is partial."); }
                            foreach (var droplet in selected.Take(10))
                            {
                                if (metrics.Count >= 256 || metricPointCount >= 10000) { limited = true; break; }
                                var response = await Query("digitalocean-api", ["cpu-metrics", Text(droplet, "id"), "1"]);
                                if (Text(response, "status") != "success" || TextAt(response, "data", "resultType") != "matrix")
                                    throw new JsonException("Cloud metric response context is missing.");
                                var counters = ArrayAt(response, "data", "result");
                                if (counters.Count > 256) { limited = true; counters = counters.Take(256).ToList(); }
                                foreach (var counter in counters)
                                {
                                    if (metrics.Count >= 256 || metricPointCount >= 10000) { limited = true; break; }
                                    var samples = new List<object>();
                                    var mode = TextAt(counter, "metric", "mode");
                                    var cpu = TextAt(counter, "metric", "cpu");
                                    if (mode.Length > 32 || cpu.Length > 32) throw new JsonException("Metric label exceeds limit.");
                                    foreach (var sample in Array(counter, "values").Take(720))
                                    {
                                        if (metricPointCount >= 10000) { limited = true; break; }
                                        if (sample.ValueKind != JsonValueKind.Array || sample.GetArrayLength() != 2 ||
                                            !MetricTimestamp(sample[0], out var timestamp) ||
                                            !double.TryParse(sample[1].ToString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var value) || !double.IsFinite(value) || value < 0) continue;
                                        samples.Add(new { timestampUtc = timestamp, value });
                                    metricPointCount++;
                                    }
                                    metrics.Add(new { resourceId = Text(droplet, "id"), metric = "cpu_seconds_total", unit = "seconds", aggregation = "cumulative_counter", labels = new { cpu, mode }, source = "DigitalOcean Monitoring droplet CPU", observedAtUtc = now, state = samples.Count == 0 ? "no_data" : "available", samples });
                                }
                                if (counters.Count == 0) metrics.Add(new { resourceId = Text(droplet, "id"), metric = "cpu_seconds_total", unit = "seconds", aggregation = "cumulative_counter", source = "DigitalOcean Monitoring droplet CPU", observedAtUtc = now, state = "no_data", samples = System.Array.Empty<object>() });
                            }
                            warnings.Add("DigitalOcean CPU samples are cumulative CPU seconds per mode/core, not utilization percent; counters are not mixed with host CPU percentages or filled across gaps.");
                        }
                        if (operation == "inventory")
                        {
                            var volumes = await ApiPages("digitalocean-api", "volumes", "configured", "volumes");
                            Add(volumes.Where(x => urns.Contains("do:volume:" + Text(x, "id"))), "storage.volume", ["size_gigabytes"], region: row => TextAt(row, "region", "slug"));
                        }
                        if (operation == "posture")
                        {
                            var firewalls = await ApiPages("digitalocean-api", "firewalls", "configured", "firewalls");
                            var dropletIds = selected.Select(x => Text(x, "id")).ToHashSet(StringComparer.Ordinal);
                            foreach (var row in firewalls.Where(x => Array(x, "droplet_ids").Any(id => dropletIds.Contains(id.ToString()))))
                            {
                                Add([row], "network.firewall", ["status"]);
                                foreach (var rule in Array(row, "inbound_rules"))
                                    if (ArrayAt(rule, "sources", "addresses").Any(address => World(address.ToString())))
                                        Exposure("DIGITALOCEAN_WORLD_INGRESS", "A firewall attached directly to a selected droplet permits ingress from a global CIDR. Tag-based firewall membership is not evaluated.");
                            }
                            warnings.Add("Tag-based DigitalOcean firewall membership and project resources other than droplets/volumes are not evaluated.");
                        }
                        break;
                    }
                    case "hetzner":
                    {
                        var servers = await ApiPages("hetzner-api", "servers", "configured", "servers");
                        Add(servers, "compute.vm", ["status", "rescue_enabled"], region: row => TextAt(row, "datacenter", "name"));
                        if (operation == "metrics")
                        {
                            if (servers.Count > 10) { limited = true; warnings.Add("Metrics are limited to the first 10 enumerated servers; coverage is partial."); }
                            foreach (var server in servers.Take(10))
                            {
                                var response = await Query("hetzner-api", ["cpu-metrics", Text(server, "id"), "1"]);
                                if (!response.TryGetProperty("metrics", out var series) || series.ValueKind != JsonValueKind.Object ||
                                    !series.TryGetProperty("step", out var step) || !step.TryGetDouble(out var period) || !double.IsFinite(period) || period < 1 ||
                                    !series.TryGetProperty("time_series", out var timeSeries) || timeSeries.ValueKind != JsonValueKind.Object)
                                    throw new JsonException("Cloud metric context is missing.");
                                var samples = new List<object>();
                                foreach (var sample in ArrayAt(timeSeries, "cpu", "values").Take(720))
                                {
                                    if (sample.ValueKind != JsonValueKind.Array || sample.GetArrayLength() != 2 ||
                                        !MetricTimestamp(sample[0], out var timestamp) ||
                                        !double.TryParse(sample[1].ToString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var value) || !double.IsFinite(value) || value < 0 || value > 100) continue;
                                    samples.Add(new { timestampUtc = timestamp, value });
                                }
                                metrics.Add(new { resourceId = Text(server, "id"), metric = "cpu", unit = "percent", aggregation = "provider", periodSeconds = period, source = "Hetzner Cloud server metrics", observedAtUtc = now, state = samples.Count == 0 ? "no_data" : "available", samples });
                            }
                        }
                        if (operation == "inventory")
                        {
                            Add(await ApiPages("hetzner-api", "volumes", "configured", "volumes"), "storage.volume", ["status", "size"]);
                            Add(await ApiPages("hetzner-api", "networks", "configured", "networks"), "network.vpc", []);
                            Add(await ApiPages("hetzner-api", "load_balancers", "configured", "load_balancers"), "network.load-balancer", ["algorithm"]);
                        }
                        if (operation == "posture")
                        {
                            var firewalls = await ApiPages("hetzner-api", "firewalls", "configured", "firewalls");
                            Add(firewalls, "network.firewall", []);
                            foreach (var row in firewalls)
                                if (Array(row, "rules").Any(rule => Text(rule, "direction") == "in" && Array(rule, "source_ips").Any(address => World(address.ToString()))))
                                    Exposure("HETZNER_WORLD_INGRESS", "A configured firewall permits ingress from a global CIDR. Attachment and external reachability must be reviewed separately.");
                        }
                        warnings.Add("Hetzner scope is defined by HCLOUD_TOKEN's project. The configured project label is descriptive and is not an independent identity assertion.");
                        break;
                    }
                    case "cloudflare":
                    {
                        var zones = await ApiPages("cloudflare-api", "zones", Option("account"), "result");
                        var allowlisted = Option("zones").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        if (allowlisted.Any(z => !Regex.IsMatch(z, "^[a-fA-F0-9]{32}$", RegexOptions.CultureInvariant)))
                            return Report("not_configured", false, "The configured zone allowlist is invalid.");
                        var matching = zones.Where(z => TextAt(z, "account", "id") == Option("account") && (allowlisted.Length == 0 || allowlisted.Contains(Text(z, "id"), StringComparer.Ordinal))).ToArray();
                        Add(matching, "edge.zone", ["status", "paused", "type"]);
                        if (operation == "posture")
                            foreach (var row in matching)
                                if (row.TryGetProperty("paused", out var paused) && paused.ValueKind == JsonValueKind.True)
                                    AddFinding(new(FindingSeverity.Warning, "CLOUDFLARE_ZONE_PAUSED", "A configured zone is paused", "Cloudflare reports a paused zone; proxy security and performance features are bypassed for that zone. DNS-only records and individual WAF/TLS rules are not evaluated.", "Review whether pausing the zone is intended in the Cloudflare console."));
                        warnings.Add("Cloudflare coverage is zone metadata only. DNS contents, WAF rules, billing and analytics are not queried or inferred.");
                        break;
                    }
                    case "openstack":
                    {
                        var token = await Query("openstack", ["token", "issue", "--os-cloud", Option("cloud-name"), "--os-project-id", Option("project"), "--os-region-name", Option("region"), "-f", "json", "-c", "project_id"]);
                        if (Text(token, "project_id", "projectId") != Option("project"))
                            return Report("permission_denied", false, "The authenticated OpenStack project does not match the authorized project.");
                        Add(await OpenStack("server list", ["--long", "--limit", "1001"]), "compute.vm", ["Status", "Power State", "Flavor", "Availability Zone"]);
                        if (operation == "inventory")
                        {
                            Add(await OpenStack("volume list", ["--long"]), "storage.volume", ["Status", "Size"]);
                            Add(await OpenStack("network list", []), "network.vpc", []);
                        }
                        if (operation == "posture")
                        {
                            var rules = await OpenStack("security group rule list", ["--long"]);
                            Add(rules, "network.security-rule", ["Direction", "IP Protocol", "Port Range"]);
                            foreach (var row in rules)
                                if (Text(row, "Direction", "direction") == "ingress" && World(Text(row, "IP Range", "Remote IP Prefix", "remote_ip_prefix")))
                                    Exposure("OPENSTACK_WORLD_INGRESS", "A configured security group rule permits ingress from a global CIDR. This does not establish reachability.");
                        }
                        warnings.Add("Only the administrator-configured clouds.yaml entry is used; telemetry, service health and other projects are not inferred.");
                        break;
                    }
                    case "alibaba":
                    {
                        var identity = await Query("aliyun", Profile(["sts", "GetCallerIdentity"]));
                        if (Text(identity, "AccountId") != Option("account"))
                            return Report("permission_denied", false, "The authenticated Alibaba account does not match the authorized account.");
                        Add(await Alibaba("ecs", "DescribeInstances", "Instances", "Instance"), "compute.vm", ["Status", "InstanceType", "ZoneId"], idFields: ["InstanceId"], nameFields: ["InstanceName"]);
                        if (operation is "inventory" or "posture")
                        {
                            var disks = await Alibaba("ecs", "DescribeDisks", "Disks", "Disk");
                            Add(disks, "storage.volume", ["Status", "Size", "Encrypted"], idFields: ["DiskId"], nameFields: ["DiskName"]);
                            if (operation == "posture")
                                foreach (var disk in disks)
                                    if (disk.TryGetProperty("Encrypted", out var encrypted) && encrypted.ValueKind == JsonValueKind.False)
                                        AddFinding(new(FindingSeverity.Warning, "ALIBABA_DISK_UNENCRYPTED", "An observed ECS disk is not encrypted", "ECS reports Encrypted=false for an observed disk. This check covers disk encryption metadata only; no Security Group or account-wide posture is inferred.", "Review intended disk encryption requirements outside Opscope."));
                        }
                        if (operation == "inventory") Add(await Alibaba("vpc", "DescribeVpcs", "Vpcs", "Vpc"), "network.vpc", ["Status"], idFields: ["VpcId"], nameFields: ["VpcName"]);
                        warnings.Add("Alibaba empty lists remain partial: this adapter cannot independently certify the account's IAM visibility.");
                        break;
                    }
                    case "ibm":
                    {
                        foreach (var state in new[] { "active", "provisioning", "failed", "inactive", "pre_provisioning", "pending_reclamation" })
                        {
                            var instances = await Ibm(state);
                            Add(instances.Where(row => Text(row, "region_id") == Option("region")), "service.instance", ["state", "type", "region_id"], idFields: ["id", "guid", "crn"]);
                            if (resources.Count >= RowBudget) { limited = true; break; }
                        }
                        warnings.Add("IBM coverage is Resource Controller metadata in the authorized account/resource group and selected region. Removed instances, VPC guest state and Monitoring are not queried. IAM access tokens are configured and refreshed outside Opscope.");
                        break;
                    }
                    case "scaleway":
                        Add(await Scaleway("servers"), "compute.vm", ["state", "commercial_type"], idFields: ["id"], region: _ => Option("zone"));
                        if (operation == "inventory") Add(await Scaleway("volumes"), "storage.volume", ["state", "size", "volume_type"]);
                        warnings.Add("Scaleway coverage is zonal Instance servers/volumes only. Regional VPC, gateways, billing and monitoring are not inferred.");
                        break;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception ex) when (ex is IOException or HttpRequestException or JsonException or InvalidOperationException or ArgumentException or OperationCanceledException)
            {
                failed = true;
                failure = ex is AdditionalCloudQueryException classified ? classified.State : "failed";
                warnings.Add("A required read-only provider query was unavailable or returned an invalid response. Verify the selected identity, read permissions, API availability and local CLI configuration; raw provider errors are omitted.");
            }
            if (operation == "health")
                foreach (var resource in resources.Where(r => r.Type is "compute.vm" or "edge.zone" or "service.instance"))
                {
                    var props = resource.Properties as Dictionary<string, object?>;
                    var state = props?.FirstOrDefault(p => p.Key.Equals("state", StringComparison.OrdinalIgnoreCase) || p.Key.Equals("status", StringComparison.OrdinalIgnoreCase) || p.Key.Equals("lifecycle-state", StringComparison.OrdinalIgnoreCase)).Value?.ToString() ?? "unknown";
                    if (state.Equals("error", StringComparison.OrdinalIgnoreCase) || state.Equals("failed", StringComparison.OrdinalIgnoreCase) || state.Equals("impaired", StringComparison.OrdinalIgnoreCase))
                        AddFinding(new(FindingSeverity.Warning, Name.ToUpperInvariant() + "_RESOURCE_STATE", "Provider reports an abnormal resource state", "A resource state is reported as " + state + ". This is a provider control-plane observation, not a guest availability test.", "Inspect provider diagnostics for the affected resource."));
                }
            if (omittedMetricTimes) warnings.Add("Provider CPU samples with invalid timestamps, outside the requested last-hour window or more than two minutes in the future were omitted; metric coverage is partial.");
            if (limited) warnings.Add("A resource, pagination, metric-series, timestamp-validation or total-point budget was reached; coverage is partial and the collection cannot establish absence.");
            var succeeded = attempted != 0 && completed == attempted && !limited && !failed;
            return Report(succeeded ? "partial" : completed == 0 ? failure : "partial", succeeded);

            string Option(string key) => options.TryGetValue(key, out var value) ? value.Trim() : string.Empty;
            bool MetricTimestamp(JsonElement value, out DateTimeOffset timestamp)
            {
                if (TryTimestamp(value, out timestamp) && timestamp >= now.AddHours(-1) && timestamp <= now.AddMinutes(2)) return true;
                omittedMetricTimes = true;
                limited = true;
                return false;
            }
            static bool Valid(string value) => value.Length is > 0 and <= 256 && !value.StartsWith('-') && !value.StartsWith('@') && !value.Contains("://", StringComparison.Ordinal) && !value.Any(char.IsControl);
            AnalysisReport Report(string state, bool succeeded, string? warning = null)
            {
                if (warning is not null) warnings.Add(warning);
                return new AnalysisReport($"{Name}.{operation}", now, findings, new
                {
                    provider = Name, operation, schemaVersion = 1, resources,
                    coverage = new { state, observedAtUtc = now, enumeratedResources = resources.Count, expectedScopes = 1, completedScopes = succeeded ? 1 : 0, warnings = warnings.ToArray() },
                    source = "provider control-plane read-only query", metrics
                }, warnings) { OperationSucceeded = succeeded };
            }
            void AddFinding(Finding finding)
            {
                if (findings.Count >= 1000) { limited = true; return; }
                findings.Add(finding);
            }
            void Exposure(string code, string detail) => AddFinding(new(FindingSeverity.Warning, code, "Configured global ingress requires review", detail, "Review intended source restrictions and resource attachment in the provider console; Opscope does not apply changes."));
            async Task<JsonElement> Query(string tool, IReadOnlyList<string> args)
            {
                cancellationToken.ThrowIfCancellationRequested();
                attempted++;
                var value = await runner.RunAsync(tool, args, deadline.Token);
                if (value.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array)) throw new JsonException("Cloud response must be an object or list.");
                completed++;
                return value;
            }
            void Add(IEnumerable<JsonElement> rows, string type, string[] fields, string[]? idFields = null, string[]? nameFields = null, Func<JsonElement, string>? region = null)
            {
                foreach (var row in rows)
                {
                    if (resources.Count >= RowBudget) { limited = true; break; }
                    if (row.ValueKind != JsonValueKind.Object) throw new JsonException("Invalid cloud resource row.");
                    var id = Text(row, idFields ?? ["id", "ID"]);
                    if (id.Length == 0) throw new JsonException("Cloud resource identifier is missing.");
                    if (!resourceKeys.Add(type + "\0" + id)) continue;
                    var props = new Dictionary<string, object?>(StringComparer.Ordinal);
                    foreach (var field in fields)
                        if (row.TryGetProperty(field, out var value) && value.ValueKind is JsonValueKind.String or JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False)
                            props[field] = value.Clone();
                    resources.Add(new(Name, Name == "oci" ? Option("compartment") : Option("account").Length != 0 ? Option("account") : Option("project"), region?.Invoke(row) ?? Option("region"), id, type, Text(row, nameFields ?? ["name", "Name", "display-name"]), props));
                }
            }
            async Task<List<JsonElement>> ApiPages(string tool, string collection, string scope, string key)
            {
                var all = new List<JsonElement>();
                for (var page = 1; page <= 20; page++)
                {
                    var response = await Query(tool, [collection, scope, page.ToString(CultureInfo.InvariantCulture)]);
                    if (tool == "cloudflare-api" && (!response.TryGetProperty("success", out var success) || success.ValueKind != JsonValueKind.True))
                        throw new AdditionalCloudQueryException("permission_denied", "Cloudflare query was not successful.");
                    var rows = RequiredArray(response, key);
                    all.AddRange(rows.Take(RowBudget + 1 - all.Count));
                    if (all.Count > RowBudget) { limited = true; break; }
                    var more = tool switch
                    {
                        "digitalocean-api" => TextAt(response, "links", "pages", "next").Length != 0,
                        "hetzner-api" => NumberAt(response, "meta", "pagination", "next_page") > page,
                        "cloudflare-api" => NumberAt(response, "result_info", "total_pages") > page,
                        _ => false
                    };
                    if (!more) return all;
                    if (page == 20) limited = true;
                }
                warnings.Add("Provider pagination or resource budget was reached; the result cannot establish complete absence of resources.");
                return all.Take(RowBudget).ToList();
            }
            async Task<List<JsonElement>> Oci(string command, string type, string[] fields)
            {
                var all = new List<JsonElement>();
                string? page = null;
                for (var number = 0; number < 20; number++)
                {
                    var args = command.Split(' ').Concat(new[] { "--compartment-id", Option("compartment"), "--region", Option("region"), "--limit", "200", "--output", "json" }).ToList();
                    if (Option("profile").Length != 0) args.AddRange(["--profile", Option("profile")]);
                    if (page is not null) args.AddRange(["--page", page]);
                    var response = await Query("oci", args);
                    var rows = RequiredArray(response, "data");
                    all.AddRange(rows.Take(RowBudget + 1 - all.Count));
                    page = Text(response, "opc-next-page", "next-page");
                    if (all.Count > RowBudget || number == 19 && page.Length != 0) { limited = true; break; }
                    if (page.Length == 0) break;
                }
                Add(all.Take(RowBudget), type, fields);
                return all;
            }
            async Task<List<JsonElement>> OpenStack(string command, string[] extra)
            {
                var args = command.Split(' ').Concat(new[] { "--os-cloud", Option("cloud-name"), "--os-project-id", Option("project"), "--os-region-name", Option("region"), "-f", "json" }).Concat(extra).ToArray();
                var response = await Query("openstack", args);
                var rows = RequiredArray(response);
                if (rows.Count > RowBudget) limited = true;
                return rows.Take(RowBudget).ToList();
            }
            List<string> Profile(string[] args)
            {
                var list = args.ToList();
                if (Option("profile").Length != 0) list.AddRange(["--profile", Option("profile")]);
                return list;
            }
            async Task<List<JsonElement>> Alibaba(string product, string command, string container, string key)
            {
                var all = new List<JsonElement>();
                for (var page = 1; page <= 20; page++)
                {
                    var args = Profile([product, command, "--RegionId", Option("region"), "--PageNumber", page.ToString(CultureInfo.InvariantCulture), "--PageSize", "100"]);
                    var response = await Query("aliyun", args);
                    if (!response.TryGetProperty("TotalCount", out var count) || !count.TryGetInt32(out var total) || total < 0) throw new JsonException("Missing provider total count.");
                    var rows = RequiredArray(response, container, key);
                    all.AddRange(rows.Take(RowBudget + 1 - all.Count));
                    if (all.Count > RowBudget || page == 20 && total > all.Count) { limited = true; break; }
                    if (total <= all.Count) return all;
                    if (rows.Count == 0) throw new JsonException("Provider pagination did not advance.");
                }
                return all.Take(RowBudget).ToList();
            }
            async Task<List<JsonElement>> Ibm(string state)
            {
                var all = new List<JsonElement>();
                var cursor = "1";
                var seenCursors = new HashSet<string>(StringComparer.Ordinal);
                for (var page = 1; page <= 20; page++)
                {
                    var response = await Query("ibm-api", ["resources-" + state, Option("account") + "@" + Option("resource-group"), cursor]);
                    var rows = RequiredArray(response, "resources");
                    if (rows.Any(row => Text(row, "account_id") != Option("account") || Text(row, "resource_group_id") != Option("resource-group")))
                        throw new AdditionalCloudQueryException("permission_denied", "An IBM resource was returned outside the authorized account/resource group.");
                    all.AddRange(rows.Take(RowBudget + 1 - all.Count));
                    var next = Text(response, "next_url");
                    if (next.Length == 0) return all;
                    if (all.Count > RowBudget || page == 20) { limited = true; break; }
                    if (!Uri.TryCreate(new Uri("https://resource-controller.cloud.ibm.com"), next, out var link) ||
                        link.Scheme != "https" || link.Host != "resource-controller.cloud.ibm.com" || link.AbsolutePath != "/v2/resource_instances")
                        throw new JsonException("IBM pagination link is outside its fixed API route.");
                    var startPair = link.Query.TrimStart('?').Split('&').FirstOrDefault(pair => pair.StartsWith("start=", StringComparison.Ordinal));
                    if (startPair is null) throw new JsonException("IBM pagination cursor is missing.");
                    cursor = Uri.UnescapeDataString(startPair[6..]);
                    if (cursor.Length is 0 or > 1024 || !seenCursors.Add(cursor)) throw new JsonException("IBM pagination did not advance.");
                }
                return all.Take(RowBudget).ToList();
            }
            async Task<List<JsonElement>> Scaleway(string command)
            {
                var all = new List<JsonElement>();
                for (var page = 1; page <= 20; page++)
                {
                    var response = await Query("scaleway-api", [command, Option("project") + "@" + Option("zone"), page.ToString(CultureInfo.InvariantCulture)]);
                    var rows = RequiredArray(response, command);
                    if (rows.Any(row => Text(row, "project").Length != 0 && Text(row, "project") != Option("project")))
                        throw new AdditionalCloudQueryException("permission_denied", "A Scaleway resource was returned outside the authorized project.");
                    all.AddRange(rows.Take(RowBudget + 1 - all.Count));
                    if (all.Count > RowBudget || page == 20 && rows.Count == 100) { limited = true; break; }
                    if (rows.Count < 100) return all;
                }
                return all.Take(RowBudget).ToList();
            }
        }
    }

    private static bool TryTimestamp(JsonElement value, out DateTimeOffset timestamp)
    {
        timestamp = default;
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetDouble(out var seconds) || !double.IsFinite(seconds) || seconds < 0 || seconds >= 253402300799) return false;
        timestamp = DateTimeOffset.UnixEpoch.AddSeconds(seconds);
        return true;
    }
    private static bool World(string value) => value is "0.0.0.0/0" or "::/0";
    private static string Text(JsonElement value, params string[] keys)
    {
        if (value.ValueKind != JsonValueKind.Object) return string.Empty;
        foreach (var key in keys)
            if (value.TryGetProperty(key, out var found) && found.ValueKind is JsonValueKind.String or JsonValueKind.Number)
                return found.ToString().Length <= 1024 ? found.ToString() : string.Empty;
        return string.Empty;
    }
    private static string TextAt(JsonElement value, params string[] keys)
    {
        foreach (var key in keys)
            if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(key, out value)) return string.Empty;
        return value.ValueKind is JsonValueKind.String or JsonValueKind.Number ? value.ToString() : string.Empty;
    }
    private static int NumberAt(JsonElement value, params string[] keys) => int.TryParse(TextAt(value, keys), CultureInfo.InvariantCulture, out var number) ? number : 0;
    private static List<JsonElement> Array(JsonElement value, string key) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var rows) && rows.ValueKind == JsonValueKind.Array ? rows.EnumerateArray().Select(r => r.Clone()).ToList() : [];
    private static List<JsonElement> ArrayAt(JsonElement value, params string[] keys)
    {
        foreach (var key in keys)
            if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(key, out value)) return [];
        return value.ValueKind == JsonValueKind.Array ? value.EnumerateArray().Select(r => r.Clone()).ToList() : [];
    }
    private static List<JsonElement> Rows(JsonElement value, string key) => value.ValueKind == JsonValueKind.Array ? RequiredArray(value) : RequiredArray(value, key);
    private static List<JsonElement> RequiredArray(JsonElement value, params string[] keys)
    {
        foreach (var key in keys)
            if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(key, out value)) throw new JsonException("Required cloud response collection is missing.");
        if (value.ValueKind != JsonValueKind.Array) throw new JsonException("Required cloud response collection is not an array.");
        if (value.GetArrayLength() > 10000) throw new JsonException("Cloud response collection exceeded its row budget.");
        return value.EnumerateArray().Select(row => row.Clone()).ToList();
    }
}
