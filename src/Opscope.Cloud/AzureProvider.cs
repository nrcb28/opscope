using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Opscope.Cloud;

/// <summary>Optional read-only Azure CLI collector. Authentication must already be configured.</summary>
public sealed class AzureProvider(ICloudCommandRunner runner) : ICloudProvider
{
    public string Name => "azure";
    private const int MaxRows = 10000;
    private const string InventoryQuery = "Resources | where type in~ ('microsoft.compute/virtualmachines','microsoft.compute/disks','microsoft.network/networkinterfaces','microsoft.network/publicipaddresses','microsoft.network/networksecuritygroups','microsoft.hybridcompute/machines') | project id,name,type,subscriptionId,location,resourceGroup,vmSize=tostring(properties.hardwareProfile.vmSize),osType=tostring(properties.storageProfile.osDisk.osType),powerState=tostring(properties.extended.instanceView.powerState.code),provisioningState=tostring(properties.provisioningState),diskState=tostring(properties.diskState),managedBy=tostring(managedBy),encryptionType=tostring(properties.encryption.type),diskEncryptionSetId=tostring(properties.encryption.diskEncryptionSetId),encryptionAtHost=tostring(properties.securityProfile.encryptionAtHost),ipAddress=tostring(properties.ipAddress),ipConfigurationId=tostring(properties.ipConfiguration.id),virtualMachineId=tostring(properties.virtualMachine.id),networkSecurityGroupId=tostring(properties.networkSecurityGroup.id),arcStatus=tostring(properties.status),agentVersion=tostring(properties.agentVersion),lastStatusChange=tostring(properties.lastStatusChange),bootDiagnosticsEnabled=tostring(properties.diagnosticsProfile.bootDiagnostics.enabled)";
    private const string RulesQuery = "Resources | where type =~ 'microsoft.network/networksecuritygroups' | mv-expand rule=properties.securityRules | project id,name,subscriptionId,location,resourceGroup,ruleName=tostring(rule.name),access=tostring(rule.properties.access),direction=tostring(rule.properties.direction),protocol=tostring(rule.properties.protocol),priority=toint(rule.properties.priority),sourceAddressPrefix=tostring(rule.properties.sourceAddressPrefix),sourceAddressPrefixes=rule.properties.sourceAddressPrefixes,destinationPortRange=tostring(rule.properties.destinationPortRange),destinationPortRanges=rule.properties.destinationPortRanges";
    private const string ExtensionsQuery = "Resources | where type in~ ('microsoft.compute/virtualmachines/extensions','microsoft.hybridcompute/machines/extensions') | project id,name,type,subscriptionId,location,resourceGroup,publisher=tostring(properties.publisher),extensionType=tostring(properties.type),provisioningState=tostring(properties.provisioningState)";
    private const string DefenderQuery = "SecurityResources | where type in~ ('microsoft.security/securescores','microsoft.security/assessments') | project id,name,type,subscriptionId,location,displayName=tostring(properties.displayName),status=tostring(properties.status.code),scoreCurrent=todouble(properties.score.current),scoreMax=todouble(properties.score.max),scorePercentage=todouble(properties.score.percentage),resourceId=tostring(properties.resourceDetails.Id)";
    private const string ResourceHealthQuery = "HealthResources | where type =~ 'microsoft.resourcehealth/availabilitystatuses' | project id,name,type,subscriptionId,location,resourceId=tostring(properties.targetResourceId),availabilityState=tostring(properties.availabilityState),occurredTime=tostring(properties.occurredTime)";
    private const string ServiceHealthQuery = "ServiceHealthResources | project id,name,type,subscriptionId,location,eventType=tostring(properties.EventType),status=tostring(properties.Status),impactStartTime=tostring(properties.ImpactStartTime),lastUpdateTime=tostring(properties.LastUpdateTime)";
    private const string AlertsQuery = "AlertsManagementResources | where type =~ 'microsoft.alertsmanagement/alerts' | project id,name,type,subscriptionId,location,severity=tostring(properties.essentials.severity),monitorCondition=tostring(properties.essentials.monitorCondition),alertState=tostring(properties.essentials.alertState),targetResource=tostring(properties.essentials.targetResource),startDateTime=tostring(properties.essentials.startDateTime)";
    private const string PatchQuery = "PatchAssessmentResources | where type in~ ('microsoft.compute/virtualmachines/patchassessmentresults','microsoft.hybridcompute/machines/patchassessmentresults') | project id,name,type,subscriptionId,location,status=tostring(properties.status),lastModifiedDateTime=tostring(properties.lastModifiedDateTime),rebootPending=tobool(properties.rebootPending),critical=toint(properties.availablePatchCountByClassification.critical),security=toint(properties.availablePatchCountByClassification.security),updates=toint(properties.availablePatchCountByClassification.updates),updateRollups=toint(properties.availablePatchCountByClassification.updateRollups),other=toint(properties.availablePatchCountByClassification.other)";
    private static readonly string[] InventoryFields = ["id", "name", "type", "subscriptionId", "location", "resourceGroup", "vmSize", "osType", "powerState", "provisioningState", "diskState", "managedBy", "encryptionType", "diskEncryptionSetId", "encryptionAtHost", "ipAddress", "ipConfigurationId", "virtualMachineId", "networkSecurityGroupId", "arcStatus", "agentVersion", "lastStatusChange", "bootDiagnosticsEnabled"];
    private static readonly string[] RuleFields = ["id", "name", "subscriptionId", "location", "resourceGroup", "ruleName", "access", "direction", "protocol", "priority", "sourceAddressPrefix", "sourceAddressPrefixes", "destinationPortRange", "destinationPortRanges"];
    private static readonly string[] ExtensionFields = ["id", "name", "type", "subscriptionId", "location", "resourceGroup", "publisher", "extensionType", "provisioningState"];
    private static readonly string[] DefenderFields = ["id", "name", "type", "subscriptionId", "location", "displayName", "status", "scoreCurrent", "scoreMax", "scorePercentage", "resourceId"];

    public async Task<AnalysisReport> CollectAsync(string operation, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default)
    {
        operation = operation.ToLowerInvariant();
        if (operation is not ("inventory" or "posture" or "health" or "vm" or "bundle" or "drift" or "patches" or "cost" or "arc" or "metadata"))
            throw new ArgumentException("Unsupported Azure operation.", nameof(operation));
        var findings = new List<Finding>();
        var warnings = new List<string>();
        var data = new Dictionary<string, object?>(StringComparer.Ordinal) { ["provider"] = Name, ["operation"] = operation };
        if (operation == "metadata")
        {
            var enabled = Option(options, "metadata") ?? Option(options, "imds");
            if (enabled is not ("true" or "1" or "yes")) warnings.Add("Azure instance identity metadata requires explicit --metadata true or --imds true opt-in; no request was sent.");
            else
            {
                try { data["identity"] = await AzureMetadata.ReadIdentityAsync(cancellationToken); }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or JsonException or IOException or InvalidDataException)
                { warnings.Add("Azure instance identity metadata was unavailable or invalid; no token endpoint was contacted."); }
            }
            return new("cloud.azure.metadata", DateTimeOffset.UtcNow, findings, data, warnings) { OperationSucceeded = data.TryGetValue("identity", out var identity) && identity is not null };
        }
        var subscriptions = await ResolveSubscriptions(options, warnings, cancellationToken);
        data["subscriptions"] = subscriptions;
        data["scope"] = new { schemaVersion = 1, subscriptions, region = Option(options, "region"), resource = Option(options, "resource") };
        if (subscriptions.Count == 0) return new($"cloud.azure.{operation}", DateTimeOffset.UtcNow, findings, data, warnings) { OperationSucceeded = false };
        var context = new Context(runner, subscriptions, options, findings, warnings, cancellationToken);
        var resources = await context.Graph(InventoryQuery, InventoryFields, "resource inventory", required: operation != "health");
        if (Option(options, "resource") is not null && resources.Count == 1) context.ResolvedResourceId = Text(resources[0], "id");
        data["resources"] = resources.Select(ToResource).ToArray();
        switch (operation)
        {
            case "posture":
                await CollectPosture(context, resources, data);
                break;
            case "health":
                await CollectHealth(context, data);
                break;
            case "vm":
                await CollectVm(context, resources, data);
                break;
            case "bundle":
                await CollectBundle(context, resources, data);
                break;
            case "drift":
                CollectDrift(context, resources, data);
                break;
            case "patches":
                await CollectPatches(context, resources, data);
                break;
            case "cost":
                await CollectCost(context, resources, data);
                break;
        }
        if (operation is "inventory" or "arc" or "posture" or "patches")
        {
            var arc = resources.Where(IsArc).ToArray();
            data["arc"] = arc;
            foreach (var resource in arc.Where(r => Text(r, "arcStatus").Length != 0 && !Equal(r, "arcStatus", "Connected")))
                Add(findings, FindingSeverity.Warning, "AZURE_ARC_DISCONNECTED", "Arc agent is not connected", $"{Text(resource, "id")}: connection state {Text(resource, "arcStatus")}.", "Check the Connected Machine agent and its network connectivity; this collector does not change the agent.");
            if (operation == "arc" && arc.Length == 0) warnings.Add("No Arc machines were visible in this scope. This does not establish whether local or critical hosts should be enrolled in Arc.");
        }
        return new($"cloud.azure.{operation}", DateTimeOffset.UtcNow, findings, data, warnings) { OperationSucceeded = context.OperationSucceeded };
    }

    private async Task<List<string>> ResolveSubscriptions(IReadOnlyDictionary<string, string> options, List<string> warnings, CancellationToken ct)
    {
        var requested = Option(options, "subscriptions") ?? Option(options, "subscription");
        if (requested is not null)
        {
            var ids = requested.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (ids.Count is 0 or > 50 || ids.Any(x => !Guid.TryParseExact(x, "D", out _)))
                throw new ArgumentException("Azure subscription scope must contain 1–50 subscription GUIDs.");
            return ids;
        }
        try
        {
            var account = await runner.RunAsync("az", ["account", "show", "--output", "json", "--only-show-errors"], ct);
            var id = Get(account, "id");
            if (Guid.TryParseExact(id, "D", out _)) return [id];
            warnings.Add("The active Azure CLI account did not provide a valid subscription ID. Pass --subscription or --subscriptions.");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { warnings.Add("Azure CLI authentication or subscription discovery was unavailable. Configure Azure CLI authentication first (including an existing managed identity session), or supply subscription IDs; no login or credential writes were attempted."); }
        return [];
    }

    private static async Task CollectPosture(Context c, List<Dictionary<string, object?>> resources, Dictionary<string, object?> data)
    {
        var rules = await c.Graph(RulesQuery, RuleFields, "NSG rules");
        data["networkRules"] = rules;
        foreach (var rule in rules.Where(r => Equal(r, "access", "Allow") && Equal(r, "direction", "Inbound") && Sources(r).Any(IsInternet)))
        {
            var ports = Ports(rule).ToArray();
            var tcp = Equal(rule, "protocol", "Tcp") || Equal(rule, "protocol", "*");
            var udp = Equal(rule, "protocol", "Udp") || Equal(rule, "protocol", "*");
            var sensitive = ports.Any(p => (tcp && (IncludesPort(p, 22) || IncludesPort(p, 3389))) || (udp && IncludesPort(p, 3389)));
            Add(c.Findings, sensitive ? FindingSeverity.Critical : FindingSeverity.Warning, sensitive ? "AZURE_NSG_ADMIN_INTERNET" : "AZURE_NSG_INTERNET", "NSG permits inbound internet traffic", $"{Text(rule, "id")}, rule {Text(rule, "ruleName")}, destination ports {string.Join(", ", ports)}.", "Review effective NSG rules, routes and resource associations. Restrict unneeded access using approved network controls.");
        }
        var extensions = await c.Graph(ExtensionsQuery, ExtensionFields, "VM and Arc extension inventory");
        data["extensions"] = extensions;
        foreach (var vm in resources.Where(IsVm))
        {
            var id = Text(vm, "id");
            if (!extensions.Any(e => Text(e, "id").StartsWith(id + "/extensions/", StringComparison.OrdinalIgnoreCase) && IsMonitorExtension(e) && Equal(e, "provisioningState", "Succeeded")))
                Add(c.Findings, FindingSeverity.Warning, "AZURE_MONITOR_EXTENSION_NOT_OBSERVED", "Monitoring extension was not observed", $"{id}: no successfully provisioned Azure Monitor or legacy monitoring extension was visible.", "Verify monitoring requirements, extension permissions and coverage. Missing evidence does not prove monitoring is disabled.");
            if (Equal(vm, "encryptionAtHost", "false"))
                Add(c.Findings, FindingSeverity.Info, "AZURE_HOST_ENCRYPTION_DISABLED", "Encryption at host is disabled", id, "Assess whether encryption at host is required by policy. Azure managed disks have server-side encryption by default.");
        }
        foreach (var disk in resources.Where(r => Equal(r, "type", "microsoft.compute/disks") && Equal(r, "encryptionType", "EncryptionAtRestWithPlatformKey")))
            Add(c.Findings, FindingSeverity.Info, "AZURE_DISK_PLATFORM_KEY", "Managed disk uses a platform-managed encryption key", Text(disk, "id"), "Confirm whether policy requires a customer-managed key; platform-managed encryption is not an unencrypted disk.");
        data["defender"] = await CollectDefender(c);
        c.Warnings.Add("NSG rules are configuration evidence, not proof of effective reachability. TLS cipher suites, guest volume encryption and guest endpoint posture require host or service-specific evidence and are not inferred from Resource Graph.");
    }

    private static async Task<List<Dictionary<string, object?>>> CollectDefender(Context c)
    {
        var rows = await c.Graph(DefenderQuery, DefenderFields, "Defender for Cloud score and assessments");
        foreach (var row in rows.Where(r => Equal(r, "status", "Unhealthy")))
            Add(c.Findings, FindingSeverity.Warning, "AZURE_DEFENDER_RECOMMENDATION", "Defender for Cloud recommendation needs review", $"{Text(row, "resourceId")}: {Text(row, "displayName")}", "Review this assessment in Defender for Cloud and validate applicability before remediation.");
        if (rows.Count == 0) c.Warnings.Add("No Defender score or assessment evidence was returned. This may reflect scope, permissions or service coverage; no paid services were enabled.");
        return rows;
    }

    private static async Task CollectHealth(Context c, Dictionary<string, object?> data)
    {
        var successfulBefore = c.SuccessfulGraphQueries;
        var health = await c.Graph(ResourceHealthQuery, ["id", "name", "type", "subscriptionId", "location", "resourceId", "availabilityState", "occurredTime"], "Resource Health");
        data["resourceHealth"] = health;
        foreach (var item in health.Where(r => Equal(r, "availabilityState", "Unavailable") || Equal(r, "availabilityState", "Degraded")))
            Add(c.Findings, FindingSeverity.Warning, "AZURE_RESOURCE_HEALTH", "Azure resource health needs review", $"{Text(item, "resourceId")}: {Text(item, "availabilityState")}.", "Review Resource Health details and recent platform events.");
        var service = await c.Graph(ServiceHealthQuery, ["id", "name", "type", "subscriptionId", "location", "eventType", "status", "impactStartTime", "lastUpdateTime"], "Service Health");
        data["serviceHealth"] = service;
        foreach (var item in service.Where(r => Equal(r, "status", "Active")))
            Add(c.Findings, FindingSeverity.Warning, "AZURE_SERVICE_HEALTH", "Active Azure Service Health event", $"{Text(item, "id")}: {Text(item, "eventType")}.", "Review the event's affected services and regions in Service Health.");
        var alerts = await c.Graph(AlertsQuery, ["id", "name", "type", "subscriptionId", "location", "severity", "monitorCondition", "alertState", "targetResource", "startDateTime"], "Azure Monitor alerts");
        data["alerts"] = alerts;
        foreach (var alert in alerts.Where(r => Equal(r, "monitorCondition", "Fired") && !Equal(r, "alertState", "Closed")))
            Add(c.Findings, Equal(alert, "severity", "Sev0") ? FindingSeverity.Critical : FindingSeverity.Warning, "AZURE_MONITOR_ALERT", "Azure Monitor alert is firing", $"{Text(alert, "targetResource")}: {Text(alert, "name")} ({Text(alert, "severity")}).", "Review alert context and recent changes in Azure Monitor.");
        if (health.Count + service.Count + alerts.Count == 0) c.Warnings.Add("No health or alert evidence was visible. Empty results do not establish that all resources are healthy.");
        if (c.SuccessfulGraphQueries == successfulBefore) c.OperationSucceeded = false;
    }

    private static async Task CollectVm(Context c, List<Dictionary<string, object?>> resources, Dictionary<string, object?> data)
    {
        var vm = ResolveResource(c, resources, true);
        if (vm is null) return;
        var id = Text(vm, "id");
        data["vm"] = vm;
        if (IsArc(vm))
        {
            data["extensions"] = (await c.Graph(ExtensionsQuery, ExtensionFields, "Arc extension inventory")).Where(r => Text(r, "id").StartsWith(id + "/extensions/", StringComparison.OrdinalIgnoreCase)).ToArray();
            c.Warnings.Add("Arc exposes connection and extension metadata; Azure VM boot diagnostics and platform CPU metrics are unavailable for this Arc resource.");
            return;
        }
        var view = await c.Command(["vm", "get-instance-view", "--ids", id, "--output", "json", "--only-show-errors"], "VM instance view");
        if (view.HasValue)
        {
            var root = view.Value;
            if (root.TryGetProperty("instanceView", out var nested)) root = nested;
            data["instanceView"] = new Dictionary<string, object?>
            {
                ["statuses"] = Array(root, "statuses").Select(s => Project(s, ["code", "level", "displayStatus", "time"])).ToArray(),
                ["vmAgent"] = root.TryGetProperty("vmAgent", out var agent) ? Project(agent, ["vmAgentVersion"]) : null
            };
        }
        var extensions = await c.Command(["vm", "extension", "list", "--vm-name", Text(vm, "name"), "--resource-group", ResourceGroup(vm), "--subscription", Text(vm, "subscriptionId"), "--output", "json", "--only-show-errors"], "VM extensions");
        if (extensions.HasValue) data["extensions"] = Elements(extensions.Value).Select(e => Project(e, ["id", "name", "publisher", "typePropertiesType", "typeHandlerVersion", "provisioningState", "autoUpgradeMinorVersion", "enableAutomaticUpgrade"])).ToArray();
        data["cpuMetrics"] = await CpuMetrics(c, id);
        data["bootDiagnostics"] = new { Enabled = Text(vm, "bootDiagnosticsEnabled"), ContentCollected = false };
        c.Warnings.Add("Boot diagnostic enablement is recorded without serial logs, screenshot contents or SAS URLs. Local host snapshots are collected separately and must be explicitly correlated with this VM identity.");
    }

    private static async Task CollectBundle(Context c, List<Dictionary<string, object?>> resources, Dictionary<string, object?> data)
    {
        var resource = ResolveResource(c, resources, false);
        if (resource is null) return;
        var id = Text(resource, "id");
        var activity = await c.Command(["monitor", "activity-log", "list", "--resource-id", id, "--subscription", Text(resource, "subscriptionId"), "--offset", "7d", "--max-events", "1000", "--output", "json", "--only-show-errors"], "resource Activity Log");
        if (activity.HasValue)
        {
            var events = Elements(activity.Value).Take(1000).Select(e => new Dictionary<string, object?>
            {
                ["eventTimestamp"] = Get(e, "eventTimestamp"), ["resourceId"] = Get(e, "resourceId"),
                ["operation"] = GetPath(e, "operationName", "value"), ["status"] = GetPath(e, "status", "value"),
                ["level"] = Get(e, "level"), ["category"] = GetPath(e, "category", "value"), ["correlationId"] = Get(e, "correlationId")
            }).ToArray();
            data["activityLog"] = events;
            if (events.Length == 1000) c.Warnings.Add("Activity Log reached the 1,000-event limit; the seven-day bundle may be incomplete.");
        }
        var defender = await CollectDefender(c);
        data["recommendations"] = defender.Where(r => Equal(r, "resourceId", id) || Text(r, "id").StartsWith(id + "/providers/Microsoft.Security/", StringComparison.OrdinalIgnoreCase)).ToArray();
        data["resource"] = resource;
        c.Warnings.Add("Azure bundle contains resource-scoped cloud evidence. Activity Log caller identities, claims, request properties and diagnostic log contents are deliberately excluded.");
    }

    private static async Task CollectPatches(Context c, List<Dictionary<string, object?>> resources, Dictionary<string, object?> data)
    {
        var patches = await c.Graph(PatchQuery, ["id", "name", "type", "subscriptionId", "location", "status", "lastModifiedDateTime", "rebootPending", "critical", "security", "updates", "updateRollups", "other"], "Azure Update Manager patch assessments");
        data["patchAssessments"] = patches;
        foreach (var row in patches)
        {
            if (Number(row, "critical") + Number(row, "security") > 0)
                Add(c.Findings, FindingSeverity.Warning, "AZURE_PATCHES_MISSING", "Security or critical updates are available", $"{Text(row, "id")}: critical={Number(row, "critical")}, security={Number(row, "security")}.", "Review assessment age and approve patching through your change process; this command does not start assessment or installation.");
            if (Equal(row, "rebootPending", "true")) Add(c.Findings, FindingSeverity.Warning, "AZURE_REBOOT_PENDING", "Patch assessment reports a pending reboot", Text(row, "id"), "Schedule an approved reboot after checking workload availability requirements.");
            if (DateTimeOffset.TryParse(Text(row, "lastModifiedDateTime"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var when) && when < DateTimeOffset.UtcNow.AddDays(-7))
                Add(c.Findings, FindingSeverity.Warning, "AZURE_PATCH_ASSESSMENT_STALE", "Patch assessment is more than seven days old", Text(row, "id"), "Verify Update Manager assessment coverage. This collector does not trigger an assessment.");
        }
        foreach (var vm in resources.Where(r => IsVm(r) || IsArc(r)).Where(vm => !patches.Any(p => Text(p, "id").StartsWith(Text(vm, "id") + "/patchAssessmentResults/", StringComparison.OrdinalIgnoreCase))))
            Add(c.Findings, FindingSeverity.Warning, "AZURE_PATCH_COVERAGE_UNKNOWN", "No patch assessment was visible", Text(vm, "id"), "Check Update Manager coverage and read permissions. Missing assessment data is not a compliant result.");
    }

    private static async Task CollectCost(Context c, List<Dictionary<string, object?>> resources, Dictionary<string, object?> data)
    {
        var orphanDisks = resources.Where(r => Equal(r, "type", "microsoft.compute/disks") && Equal(r, "diskState", "Unattached") && Text(r, "managedBy").Length == 0).ToArray();
        var orphanIps = resources.Where(r => Equal(r, "type", "microsoft.network/publicipaddresses") && Text(r, "ipConfigurationId").Length == 0).ToArray();
        data["unattachedDisks"] = orphanDisks;
        data["unassociatedPublicIps"] = orphanIps;
        foreach (var resource in orphanDisks.Concat(orphanIps))
            Add(c.Findings, FindingSeverity.Warning, "AZURE_COST_UNASSOCIATED_RESOURCE", "Potential unused Azure resource", Text(resource, "id"), "Confirm ownership, retention and workload dependencies before any cleanup. This is a review candidate, not authorization to delete.");
        var vms = resources.Where(IsVm).Take(21).ToArray();
        if (vms.Length > 20) c.Warnings.Add("CPU utilization collection is limited to 20 VMs. Narrow --resource or --region to inspect additional VMs.");
        var metrics = new List<object>();
        foreach (var vm in vms.Take(20))
        {
            var cpu = await CpuMetrics(c, Text(vm, "id"));
            if (cpu is not null) metrics.Add(cpu);
            if (cpu is not null && cpu.Samples >= 120 && cpu.LastSampleUtc - cpu.FirstSampleUtc >= TimeSpan.FromDays(6) && cpu.Average < 5 && cpu.Maximum < 20)
                Add(c.Findings, FindingSeverity.Info, "AZURE_VM_LOW_CPU", "VM has low observed CPU utilization", $"{Text(vm, "id")}: mean {cpu.Average:F1}%, maximum {cpu.Maximum:F1}% across {cpu.Samples} hourly samples in seven days.", "Review memory, disk, network, workload schedules and business requirements before considering a size change. Missing metric intervals are not zero utilization.");
        }
        data["cpuMetrics"] = metrics;
        c.Warnings.Add("Cost findings use configuration and seven-day CPU evidence. Prices, billing, memory utilization and savings estimates are not collected.");
    }

    private static async Task<CpuEvidence?> CpuMetrics(Context c, string id)
    {
        var result = await c.Command(["monitor", "metrics", "list", "--resource", id, "--metric", "Percentage CPU", "--aggregation", "Average", "Maximum", "--interval", "PT1H", "--offset", "7d", "--output", "json", "--only-show-errors"], "VM CPU metrics");
        if (!result.HasValue) return null;
        var points = new SortedDictionary<DateTimeOffset, (double Average, double Maximum)>();
        foreach (var metric in Array(result.Value, "value"))
            foreach (var series in Array(metric, "timeseries"))
                foreach (var point in Array(series, "data"))
                {
                    if (point.TryGetProperty("average", out var average) && average.TryGetDouble(out var avg) && double.IsFinite(avg) && avg is >= 0 and <= 100
                        && point.TryGetProperty("maximum", out var maximum) && maximum.TryGetDouble(out var max) && double.IsFinite(max) && max is >= 0 and <= 100 && max >= avg
                        && DateTimeOffset.TryParse(Get(point, "timeStamp"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var at)
                        && at >= DateTimeOffset.UtcNow.AddDays(-7).AddMinutes(-5) && at <= DateTimeOffset.UtcNow.AddMinutes(5))
                        points[at] = (avg, max);
                }
        if (points.Count == 0) { c.Warnings.Add($"CPU metrics were not available for {id}; utilization is unknown."); return null; }
        if (points.Count < 120 || points.Last().Key - points.First().Key < TimeSpan.FromDays(6)) c.Warnings.Add($"CPU metrics for {id} have insufficient seven-day coverage for a low-utilization finding.");
        return new(id, "7d", "PT1H", points.Count, points.Values.Average(p => p.Average), points.Values.Max(p => p.Maximum), points.First().Key, points.Last().Key);
    }

    private static void CollectDrift(Context c, List<Dictionary<string, object?>> actual, Dictionary<string, object?> data)
    {
        var baseline = Option(c.Options, "baseline");
        if (string.IsNullOrWhiteSpace(baseline)) { c.OperationSucceeded = false; c.Warnings.Add("Azure drift requires --baseline pointing to an exported JSON inventory, ARM template with concrete resource IDs, or Terraform state JSON. No comparison was performed."); return; }
        if (Path.GetExtension(baseline).Equals(".bicep", StringComparison.OrdinalIgnoreCase)) { c.OperationSucceeded = false; c.Warnings.Add("Bicep source is not executed. Export a compiled ARM JSON template with resolved resource IDs before comparing drift."); return; }
        try
        {
            var info = new FileInfo(baseline);
            if (!info.Exists || info.Length > 8 * 1024 * 1024) { c.OperationSucceeded = false; c.Warnings.Add("Drift baseline is missing or exceeds the eight MiB limit."); return; }
            using var document = JsonDocument.Parse(File.ReadAllBytes(baseline), new JsonDocumentOptions { MaxDepth = 64 });
            var declared = new Dictionary<string, Dictionary<string, object?>>(StringComparer.OrdinalIgnoreCase);
            var unresolved = 0;
            ExtractDeclared(document.RootElement, declared, ref unresolved, c.Subscriptions, actual);
            if (declared.Count == 0)
            {
                if (unresolved == 0 && IsMatchingEmptyInventory(document.RootElement, c, actual))
                {
                    data["drift"] = System.Array.Empty<object>();
                    data["declaredResourceCount"] = 0;
                    data["baselineScopeMatched"] = true;
                    c.Warnings.Add("The explicitly scoped empty Azure inventory baseline matches empty live inventory for the six supported resource types. This is not a complete IaC or subscription compliance assessment.");
                    return;
                }
                c.OperationSucceeded = false;
                c.Warnings.Add("Baseline contains no usable, supported, unredacted Azure resource identities in the selected scope; no comparison was performed.");
                return;
            }
            if (unresolved > 0) c.Warnings.Add($"Skipped {unresolved} baseline resources with unresolved expressions or unsupported identities. Compile and resolve template parameters before comparing.");
            var changes = new List<object>();
            foreach (var entry in declared)
            {
                var current = actual.FirstOrDefault(r => Equal(r, "id", entry.Key));
                if (current is null)
                {
                    changes.Add(new { Id = entry.Key, Change = "notObserved" });
                    Add(c.Findings, FindingSeverity.Warning, "AZURE_DRIFT_RESOURCE_NOT_OBSERVED", "Declared resource was not observed", entry.Key, "Check subscription, region, inventory coverage and read permissions before concluding that the resource is missing.");
                    continue;
                }
                foreach (var field in new[] { "location", "vmSize", "osType", "encryptionType", "encryptionAtHost" })
                {
                    var desired = Text(entry.Value, field);
                    var observed = Text(current, field);
                    if (desired.Length == 0 || observed.Length == 0 || desired.Equals(observed, StringComparison.OrdinalIgnoreCase)) continue;
                    changes.Add(new { Id = entry.Key, Field = field, Expected = desired, Actual = observed });
                    Add(c.Findings, FindingSeverity.Warning, "AZURE_DRIFT_PROPERTY", "Azure resource differs from declared baseline", $"{entry.Key}: {field} expected {desired}, observed {observed}.", "Review intentional changes and baseline freshness before remediation.");
                }
            }
            data["drift"] = changes;
            data["declaredResourceCount"] = declared.Count;
            c.Warnings.Add("Drift compares declared resource existence and explicitly supplied location, VM size, OS type and encryption fields within the collected inventory scope. It does not evaluate ARM expressions, Terraform plans, tags, dependencies or all provider properties. Extra live resources are not assumed to be drift.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or ArgumentException or NotSupportedException)
        { c.OperationSucceeded = false; c.Warnings.Add("Drift baseline could not be read as supported bounded JSON; no deployment or validation call was made."); }
    }

    private static bool IsMatchingEmptyInventory(JsonElement root, Context c, List<Dictionary<string, object?>> actual)
    {
        if (actual.Count != 0 || Get(root, "operationSucceeded") != "true" || Get(root, "kind") is not ("cloud/azure/inventory" or "cloud.azure.inventory")
            || !root.TryGetProperty("data", out var source) || source.ValueKind != JsonValueKind.Object
            || Get(source, "provider") != "azure" || Get(source, "operation") != "inventory"
            || !source.TryGetProperty("resources", out var resources) || resources.ValueKind != JsonValueKind.Array || resources.GetArrayLength() != 0
            || !source.TryGetProperty("scope", out var scope) || scope.ValueKind != JsonValueKind.Object || Get(scope, "schemaVersion") != "1"
            || !scope.TryGetProperty("subscriptions", out var subscriptions) || subscriptions.ValueKind != JsonValueKind.Array) return false;
        var baselineSubscriptions = subscriptions.EnumerateArray().Select(Scalar).ToArray();
        return baselineSubscriptions.Length == c.Subscriptions.Count
            && baselineSubscriptions.All(id => Guid.TryParseExact(id, "D", out _))
            && new HashSet<string>(baselineSubscriptions, StringComparer.OrdinalIgnoreCase).SetEquals(c.Subscriptions)
            && Get(scope, "region").Equals(Option(c.Options, "region") ?? "", StringComparison.OrdinalIgnoreCase)
            && Get(scope, "resource").Equals(Option(c.Options, "resource") ?? "", StringComparison.OrdinalIgnoreCase);
    }

    private static void ExtractDeclared(JsonElement root, Dictionary<string, Dictionary<string, object?>> rows, ref int unresolved, IReadOnlyList<string> subscriptions, List<Dictionary<string, object?>> actual)
    {
        if (root.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in root.EnumerateArray()) ExtractDeclared(item, rows, ref unresolved, subscriptions, actual);
            return;
        }
        if (root.ValueKind != JsonValueKind.Object) return;
        var id = Get(root, "id");
        if (id.Length == 0 && Get(root, "type").StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase))
        {
            // Concrete ARM resource names can be resolved only when the selected live scope is unambiguous.
            var name = Get(root, "name");
            if (!name.Contains('[') && !name.Contains("${", StringComparison.Ordinal))
            {
                var matches = actual.Where(r => Equal(r, "name", name) && Equal(r, "type", Get(root, "type"))).ToArray();
                if (matches.Length == 1) id = Text(matches[0], "id");
            }
        }
        // Terraform state resources store ARM IDs and properties in instances[].attributes.
        if (root.TryGetProperty("attributes", out var attrs) && attrs.ValueKind == JsonValueKind.Object) ExtractDeclared(attrs, rows, ref unresolved, subscriptions, actual);
        if (root.TryGetProperty("values", out var values) && values.ValueKind == JsonValueKind.Object) ExtractDeclared(values, rows, ref unresolved, subscriptions, actual);
        if (id.StartsWith("/subscriptions/", StringComparison.OrdinalIgnoreCase))
        {
            var scope = id.Split('/');
            if (scope.Length > 2 && subscriptions.Contains(scope[2], StringComparer.OrdinalIgnoreCase) && SafeResourceId(id) && SupportedInventoryId(id))
            {
                var row = Project(root, InventoryFields);
                row["id"] = id;
                if (root.TryGetProperty("properties", out var p))
                {
                    row["vmSize"] = GetPath(p, "hardwareProfile", "vmSize"); row["osType"] = GetPath(p, "storageProfile", "osDisk", "osType");
                    row["encryptionType"] = GetPath(p, "encryption", "type"); row["encryptionAtHost"] = GetPath(p, "securityProfile", "encryptionAtHost");
                }
                if (Get(root, "vm_size").Length > 0) row["vmSize"] = Get(root, "vm_size");
                if (Get(root, "size").Length > 0 && id.Contains("/Microsoft.Compute/virtualMachines/", StringComparison.OrdinalIgnoreCase)) row["vmSize"] = Get(root, "size");
                rows[id] = row;
            }
            else unresolved++;
        }
        else if (Get(root, "type").Length > 0 && Get(root, "name").Length > 0 && !root.TryGetProperty("instances", out _)) unresolved++;
        foreach (var key in new[] { "resources", "instances", "root_module", "child_modules", "data", "planned_values" })
            if (root.TryGetProperty(key, out var child)) ExtractDeclared(child, rows, ref unresolved, subscriptions, actual);
    }

    private sealed record CpuEvidence(string ResourceId, string Window, string Interval, int Samples, double Average, double Maximum, DateTimeOffset FirstSampleUtc, DateTimeOffset LastSampleUtc);

    private sealed class Context(ICloudCommandRunner commandRunner, List<string> subscriptions, IReadOnlyDictionary<string, string> options, List<Finding> findings, List<string> warnings, CancellationToken cancellationToken)
    {
        public List<string> Subscriptions { get; } = subscriptions;
        public IReadOnlyDictionary<string, string> Options { get; } = options;
        public List<Finding> Findings { get; } = findings;
        public List<string> Warnings { get; } = warnings;
        public string? ResolvedResourceId { get; set; }
        public bool OperationSucceeded { get; set; } = true;
        public int SuccessfulGraphQueries { get; private set; }
        public async Task<JsonElement?> Command(IReadOnlyList<string> args, string evidence, bool required = false)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try { return await commandRunner.RunAsync("az", args, cancellationToken); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception) { if (required) OperationSucceeded = false; Warnings.Add($"Azure {evidence} could not be collected (CLI component, authorization or service coverage may be unavailable). No service was enabled and no authentication was changed."); return null; }
        }
        public async Task<List<Dictionary<string, object?>>> Graph(string query, string[] fields, string evidence, bool required = false)
        {
            var rows = new List<Dictionary<string, object?>>();
            string? token = null;
            for (var page = 0; page < 10; page++)
            {
                var args = new List<string> { "graph", "query", "--graph-query", query, "--first", "1000", "--subscriptions" };
                args.AddRange(Subscriptions);
                if (token is not null) args.AddRange(["--skip-token", token]);
                args.AddRange(["--output", "json", "--only-show-errors"]);
                var result = await Command(args, evidence, required);
                if (!result.HasValue) return rows;
                var body = result.Value;
                if (body.ValueKind != JsonValueKind.Array && (body.ValueKind != JsonValueKind.Object || !body.TryGetProperty("data", out var rowData) || rowData.ValueKind != JsonValueKind.Array))
                {
                    if (required) OperationSucceeded = false;
                    Warnings.Add($"Azure {evidence} returned an unsupported response shape; no resource evidence was inferred.");
                    return rows;
                }
                SuccessfulGraphQueries++;
                var items = body.ValueKind == JsonValueKind.Array ? body.EnumerateArray().ToArray() : Array(body, "data").ToArray();
                foreach (var item in items)
                {
                    if (item.ValueKind != JsonValueKind.Object) continue;
                    var row = Project(item, fields);
                    if (!InScope(row)) continue;
                    rows.Add(row);
                    if (rows.Count >= MaxRows) break;
                }
                token = ContinuationToken(body);
                if (token.Length == 0)
                {
                    if (items.Length >= 1000 && string.Equals(Get(body, "resultTruncated"), "true", StringComparison.OrdinalIgnoreCase)) Warnings.Add($"Azure {evidence} result was truncated without a continuation token.");
                    break;
                }
                if (token.Length > 8192 || token.Any(char.IsControl)) { Warnings.Add($"Azure {evidence} returned an invalid continuation token."); break; }
                if (page == 9 || rows.Count >= MaxRows) { Warnings.Add($"Azure {evidence} reached the 10,000-row collection limit; results are incomplete."); break; }
            }
            return rows;
        }
        private bool InScope(Dictionary<string, object?> row)
        {
            var subscription = Text(row, "subscriptionId");
            if (subscription.Length > 0 && !Subscriptions.Contains(subscription, StringComparer.OrdinalIgnoreCase)) return false;
            var region = Option(Options, "region");
            if (region is not null && Text(row, "location").Length > 0 && !Equal(row, "location", region)) return false;
            var resource = ResolvedResourceId ?? Option(Options, "resource");
            if (resource is null) return true;
            var id = Text(row, "id");
            return Equal(row, "name", resource) || Equal(row, "id", resource) || Equal(row, "resourceId", resource) || Equal(row, "targetResource", resource)
                || id.StartsWith(resource + "/", StringComparison.OrdinalIgnoreCase)
                || Text(row, "resourceId").StartsWith(resource + "/", StringComparison.OrdinalIgnoreCase);
        }
    }

    private static Dictionary<string, object?>? ResolveResource(Context c, List<Dictionary<string, object?>> resources, bool vmOnly)
    {
        var requested = Option(c.Options, "resource");
        var matches = resources.Where(r => !vmOnly || IsVm(r) || IsArc(r)).Where(r => requested is null || Equal(r, "id", requested) || Equal(r, "name", requested)).ToArray();
        if (matches.Length != 1) { c.OperationSucceeded = false; c.Warnings.Add("Specify --resource with a unique visible Azure resource ID or name. The requested operation needs exactly one resource in the selected subscription scope."); return null; }
        if (!SafeResourceId(Text(matches[0], "id"))) { c.OperationSucceeded = false; c.Warnings.Add("The selected resource did not have a valid scoped Azure resource ID."); return null; }
        return matches[0];
    }
    private static bool SafeResourceId(string id) => id.Length < 2048 && Regex.IsMatch(id, @"^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/\r\n]+/providers/[A-Za-z0-9.]+/[^\r\n]+$", RegexOptions.CultureInvariant);
    private static bool SupportedInventoryId(string id)
    {
        var parts = id.Split('/');
        if (parts.Length != 9) return false;
        var type = parts[6] + "/" + parts[7];
        return new[] { "microsoft.compute/virtualmachines", "microsoft.compute/disks", "microsoft.network/networkinterfaces", "microsoft.network/publicipaddresses", "microsoft.network/networksecuritygroups", "microsoft.hybridcompute/machines" }.Contains(type, StringComparer.OrdinalIgnoreCase);
    }
    private static string ResourceGroup(Dictionary<string, object?> resource)
    {
        var group = Text(resource, "resourceGroup");
        if (group.Length > 0) return group;
        var parts = Text(resource, "id").Split('/');
        return parts.Length > 4 ? parts[4] : "";
    }
    private static string ContinuationToken(JsonElement root)
    {
        foreach (var name in new[] { "skip_token", "$skipToken", "skipToken" })
            if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && value.GetString() is { Length: > 0 } token) return token;
        return "";
    }
    private static bool IsVm(Dictionary<string, object?> r) => Equal(r, "type", "microsoft.compute/virtualmachines");
    private static bool IsArc(Dictionary<string, object?> r) => Equal(r, "type", "microsoft.hybridcompute/machines");
    private static CloudResource ToResource(Dictionary<string, object?> r) => new("azure", Text(r, "subscriptionId"), Text(r, "location"), Text(r, "id"), Text(r, "type"), Text(r, "name"), r.Where(x => !new[] { "id", "type", "name", "subscriptionId", "location" }.Contains(x.Key)).ToDictionary(x => x.Key, x => x.Value));
    private static bool IsMonitorExtension(Dictionary<string, object?> e) => new[] { "AzureMonitorWindowsAgent", "AzureMonitorLinuxAgent", "MicrosoftMonitoringAgent", "OmsAgentForLinux" }.Contains(Text(e, "extensionType"), StringComparer.OrdinalIgnoreCase);
    private static IEnumerable<string> Sources(Dictionary<string, object?> row) => Strings(row, "sourceAddressPrefixes").Append(Text(row, "sourceAddressPrefix"));
    private static IEnumerable<string> Ports(Dictionary<string, object?> row) => Strings(row, "destinationPortRanges").Append(Text(row, "destinationPortRange")).Where(x => x.Length > 0);
    private static bool IsInternet(string value) => value.Equals("Internet", StringComparison.OrdinalIgnoreCase) || value is "*" or "0.0.0.0/0" or "::/0";
    private static bool IncludesPort(string value, int port)
    {
        if (value == "*" || value == port.ToString(CultureInfo.InvariantCulture)) return true;
        var pieces = value.Split('-');
        return pieces.Length == 2 && int.TryParse(pieces[0], out var min) && int.TryParse(pieces[1], out var max) && min <= port && port <= max;
    }
    private static IEnumerable<string> Strings(Dictionary<string, object?> row, string field) => row.TryGetValue(field, out var value) && value is string[] values ? values : [];
    private static string? Option(IReadOnlyDictionary<string, string> options, string key) => options.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value.Trim() : null;
    private static string Text(Dictionary<string, object?> row, string key) => row.TryGetValue(key, out var value) ? Convert.ToString(value, CultureInfo.InvariantCulture) ?? "" : "";
    private static bool Equal(Dictionary<string, object?> row, string key, string value) => Text(row, key).Equals(value, StringComparison.OrdinalIgnoreCase);
    private static double Number(Dictionary<string, object?> row, string key) => double.TryParse(Text(row, key), NumberStyles.Float, CultureInfo.InvariantCulture, out var number) ? number : 0;
    private static void Add(List<Finding> findings, FindingSeverity severity, string code, string title, string detail, string recommendation) => findings.Add(new(severity, code, title, detail, recommendation));
    private static IEnumerable<JsonElement> Array(JsonElement root, string name) => root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array ? value.EnumerateArray().Take(MaxRows) : [];
    private static IEnumerable<JsonElement> Elements(JsonElement root) => root.ValueKind == JsonValueKind.Array ? root.EnumerateArray().Take(MaxRows) : [];
    private static string Get(JsonElement root, string name) => root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out var value) ? Scalar(value) : "";
    private static string GetPath(JsonElement root, params string[] path)
    {
        foreach (var key in path) { if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty(key, out var next)) return ""; root = next; }
        return Scalar(root);
    }
    private static string Scalar(JsonElement value)
    {
        var text = value.ValueKind switch { JsonValueKind.String => value.GetString() ?? "", JsonValueKind.Number => value.GetRawText(), JsonValueKind.True => "true", JsonValueKind.False => "false", _ => "" };
        return new string(text.Take(2048).Where(ch => !char.IsControl(ch)).ToArray());
    }
    private static Dictionary<string, object?> Project(JsonElement root, string[] fields)
    {
        var row = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var field in fields)
        {
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty(field, out var value)) continue;
            row[field] = value.ValueKind switch
            {
                JsonValueKind.Array => value.EnumerateArray().Take(100).Where(e => e.ValueKind is JsonValueKind.String or JsonValueKind.Number).Select(Scalar).ToArray(),
                JsonValueKind.True => true, JsonValueKind.False => false,
                JsonValueKind.Number when value.TryGetDouble(out var d) && double.IsFinite(d) => d,
                JsonValueKind.String => Scalar(value), _ => null
            };
        }
        return row;
    }
}
