using System.Text.Json;
using Opscope;
using Opscope.Cloud;

internal static class Program
{
    private const string Subscription = "11111111-1111-1111-1111-111111111111";
    private const string VmId = "/subscriptions/" + Subscription + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-a";
    private const string Secret = "DO-NOT-RETURN-super-secret-password";

    private static async Task<int> Main()
    {
        await TestInventoryProjection();
        await TestSafeFailures();
        await TestSubscriptionValidation();
        await TestSubscriptionScope();
        await TestResourceScopeProvenance();
        await TestCancellation();
        await TestNsgExposureAndArcStatus();
        await TestCostCandidates();
        await TestMetadataRequiresOptIn();
        await TestHealthAndPatches();
        await TestVmAndBundle();
        await TestDrift();
        await TestPagination();
        await TestRequiredResourceResolution();
        await TestExplicitOperationStatus();
        await TestDriftOperationStatus();
        Console.WriteLine("Azure fake-runner tests passed.");
        return 0;
    }

    private static async Task TestInventoryProjection()
    {
        var runner = new FakeRunner((_, arguments) =>
        {
            if (arguments.Take(2).SequenceEqual(new[] { "account", "show" }))
                return "{\"id\":\"" + Subscription + "\",\"accessToken\":\"" + Secret + "\"}";
            return JsonSerializer.Serialize(new
            {
                data = new[]
                {
                    new
                    {
                        id = VmId, name = "vm-a", type = "microsoft.compute/virtualmachines",
                        subscriptionId = Subscription, location = "eastus", resourceGroup = "rg",
                        vmSize = "Standard_D2s_v5", provisioningState = "Succeeded", osType = "Linux",
                        adminPassword = Secret, customData = Secret,
                        properties = new { osProfile = new { adminPassword = Secret }, protectedSettings = new { secret = Secret } },
                        tags = new { password = Secret }
                    }
                },
                count = 1, total_records = 1
            });
        });
        var report = await new AzureProvider(runner).CollectAsync("inventory", Options());
        var json = JsonSerializer.Serialize(report);
        Assert(json.Contains("vm-a", StringComparison.Ordinal), "inventory retains safe resource identity");
        Assert(report.OperationSucceeded, "successful resource inventory has explicit success status");
        Assert(!json.Contains(Secret, StringComparison.Ordinal), "inventory removes nested and top-level credentials");
        Assert(runner.Calls.Any(call => call.Arguments.Take(2).SequenceEqual(new[] { "graph", "query" })), "inventory uses Resource Graph");
        runner.AssertReadOnly();
    }

    private static async Task TestSafeFailures()
    {
        var runner = new FakeRunner((_, _) => throw new InvalidOperationException("Forbidden " + Secret));
        var report = await new AzureProvider(runner).CollectAsync("inventory", Options());
        Assert(report.Warnings is { Count: > 0 }, "denied service produces coverage warning");
        Assert(!report.OperationSucceeded, "failed required inventory query explicitly fails the operation");
        Assert(!JsonSerializer.Serialize(report).Contains(Secret, StringComparison.Ordinal), "failure does not echo server exception secrets");
        runner.AssertReadOnly();
    }

    private static async Task TestSubscriptionValidation()
    {
        var runner = new FakeRunner((_, _) => "{\"data\":[]}");
        try
        {
            var report = await new AzureProvider(runner).CollectAsync("inventory", new Dictionary<string, string> { ["subscription"] = "bad;az account clear" });
            Assert(report.Warnings is { Count: > 0 } || report.Findings.Count > 0, "invalid subscription is explicit");
        }
        catch (ArgumentException)
        {
            // Rejected user input is also an acceptable explicit failure.
        }
        Assert(runner.Calls.Count == 0, "invalid subscription is rejected before executing CLI");
    }

    private static async Task TestSubscriptionScope()
    {
        const string secondSubscription = "22222222-2222-2222-2222-222222222222";
        var runner = new FakeRunner((_, _) => "{\"data\":[],\"count\":0,\"total_records\":0}");
        await new AzureProvider(runner).CollectAsync("inventory", new Dictionary<string, string>
        {
            ["subscriptions"] = Subscription + "," + secondSubscription
        });
        var query = runner.Calls.First(call => call.Arguments.Take(2).SequenceEqual(new[] { "graph", "query" }));
        Assert(query.Arguments.Contains("--subscriptions") && query.Arguments.Contains(Subscription) && query.Arguments.Contains(secondSubscription), "Graph query explicitly scopes all subscriptions");
        runner.AssertReadOnly();
    }

    private static async Task TestResourceScopeProvenance()
    {
        const string outsideSubscription = "22222222-2222-2222-2222-222222222222";
        var outsideId = VmId.Replace(Subscription, outsideSubscription, StringComparison.Ordinal);
        var invalidRows = new object[]
        {
            new { id = outsideId, name = "vm-a", type = "microsoft.compute/virtualmachines", subscriptionId = Subscription },
            new { id = outsideId, name = "vm-a", type = "microsoft.compute/virtualmachines" },
            new { id = VmId, name = "vm-a", type = "microsoft.compute/virtualmachines", subscriptionId = outsideSubscription },
            new { id = "unscoped-resource", name = "vm-a", type = "microsoft.compute/virtualmachines" },
            new { id = VmId, name = "vm-a", type = "microsoft.compute/virtualmachines", subscriptionId = "not-a-guid" }
        };
        foreach (var row in invalidRows)
        {
            var runner = new FakeRunner((_, _) => GraphRows(row));
            var inventory = await new AzureProvider(runner).CollectAsync("inventory", Options());
            var resourceData = JsonSerializer.SerializeToElement(inventory.Data).GetProperty("resources");
            Assert(!inventory.OperationSucceeded && resourceData.GetArrayLength() == 0 && inventory.Warnings is { Count: > 0 }, "inconsistent or missing subscription provenance cannot become successful empty inventory");
            var options = Options();
            options["resource"] = "vm-a";
            var vm = await new AzureProvider(runner).CollectAsync("vm", options);
            Assert(!vm.OperationSucceeded && runner.Calls.All(call => call.Arguments.Take(2).SequenceEqual(new[] { "graph", "query" })), "rejected resource scope cannot trigger VM follow-up queries");
        }
        var missingSubscription = await new AzureProvider(new FakeRunner((_, _) => GraphRows(new { id = VmId, name = "vm-a", type = "microsoft.compute/virtualmachines" }))).CollectAsync("inventory", Options());
        var retained = JsonSerializer.SerializeToElement(missingSubscription.Data).GetProperty("resources");
        Assert(missingSubscription.OperationSucceeded && retained.GetArrayLength() == 1 && retained[0].GetProperty("Account").GetString() == Subscription, "a valid scoped ARM ID supplies missing subscription metadata without losing provenance");

        var multiScope = Options();
        multiScope["subscriptions"] = Subscription + "," + outsideSubscription;
        var mismatched = await new AzureProvider(new FakeRunner((_, _) => GraphRows(invalidRows[0]))).CollectAsync("inventory", multiScope);
        Assert(!mismatched.OperationSucceeded, "two individually allowed subscriptions cannot disagree within one resource identity");

        var healthRunner = new FakeRunner((_, args) => GraphQuery(args).StartsWith("Resources", StringComparison.Ordinal)
            ? GraphRows()
            : GraphQuery(args).StartsWith("ServiceHealthResources", StringComparison.Ordinal)
                ? GraphRows(new { id = outsideId, subscriptionId = Subscription, status = "Active" })
                : GraphRows(new { id = "health-event", subscriptionId = Subscription, resourceId = outsideId, targetResource = outsideId, availabilityState = "Unavailable", monitorCondition = "Fired", alertState = "New", severity = "Sev0" }));
        var health = await new AzureProvider(healthRunner).CollectAsync("health", Options());
        Assert(!health.OperationSucceeded && health.Findings.Count == 0, "out-of-scope related resource IDs cannot generate local-scope health findings or successful coverage");
    }

    private static async Task TestCancellation()
    {
        var runner = new FakeRunner((_, _) => "{\"data\":[]}");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        try
        {
            await new AzureProvider(runner).CollectAsync("inventory", Options(), cancellation.Token);
            throw new InvalidOperationException("Assertion failed: cancelled collection must propagate cancellation");
        }
        catch (OperationCanceledException)
        {
        }
        Assert(runner.Calls.Count == 0, "cancelled collection makes no CLI calls");
    }

    private static async Task TestNsgExposureAndArcStatus()
    {
        var runner = new FakeRunner((_, arguments) =>
        {
            var query = GraphQuery(arguments);
            if (query.Contains("mv-expand rule", StringComparison.Ordinal))
                return GraphRows(new
                {
                    id = VmId.Replace("Microsoft.Compute/virtualMachines/vm-a", "Microsoft.Network/networkSecurityGroups/nsg-a", StringComparison.Ordinal),
                    name = "nsg-a", subscriptionId = Subscription, location = "eastus", ruleName = "ssh-internet",
                    access = "Allow", direction = "Inbound", protocol = "Tcp", priority = 100,
                    sourceAddressPrefix = "0.0.0.0/0", destinationPortRange = "22",
                    protectedSettings = Secret
                });
            if (query.Contains("agentVersion=", StringComparison.Ordinal))
                return GraphRows(new
                {
                    id = VmId.Replace("Microsoft.Compute/virtualMachines/vm-a", "Microsoft.HybridCompute/machines/arc-a", StringComparison.Ordinal),
                    name = "arc-a", type = "microsoft.hybridcompute/machines", subscriptionId = Subscription,
                    location = "eastus", arcStatus = "Disconnected", agentVersion = "1.40", protectedSettings = Secret
                });
            return GraphRows();
        });
        var report = await new AzureProvider(runner).CollectAsync("posture", Options());
        Assert(report.Findings.Any(finding => finding.Code == "AZURE_NSG_ADMIN_INTERNET" && finding.Severity == FindingSeverity.Critical), "public SSH NSG rule produces critical finding");
        Assert(report.Findings.Any(finding => finding.Code == "AZURE_ARC_DISCONNECTED"), "disconnected Arc machine produces finding");
        Assert(!JsonSerializer.Serialize(report).Contains(Secret, StringComparison.Ordinal), "posture excludes raw extension and resource settings");
        runner.AssertReadOnly();
    }

    private static async Task TestCostCandidates()
    {
        var runner = new FakeRunner((_, _) => GraphRows(
            new { id = VmId.Replace("virtualMachines/vm-a", "disks/disk-unused", StringComparison.Ordinal), name = "disk-unused", type = "microsoft.compute/disks", subscriptionId = Subscription, location = "eastus", diskState = "Unattached", managedBy = "" },
            new { id = VmId.Replace("virtualMachines/vm-a", "disks/disk-used", StringComparison.Ordinal), name = "disk-used", type = "microsoft.compute/disks", subscriptionId = Subscription, location = "eastus", diskState = "Attached", managedBy = VmId }
        ));
        var report = await new AzureProvider(runner).CollectAsync("cost", Options());
        var candidates = report.Findings.Where(finding => finding.Code == "AZURE_COST_UNASSOCIATED_RESOURCE").ToArray();
        Assert(candidates.Length == 1 && candidates[0].Detail.Contains("disk-unused", StringComparison.Ordinal), "only unattached disk is a cost review candidate");
        runner.AssertReadOnly();
    }

    private static async Task TestMetadataRequiresOptIn()
    {
        var runner = new FakeRunner((_, _) => throw new InvalidOperationException("Metadata must not call the CLI"));
        var report = await new AzureProvider(runner).CollectAsync("metadata", Options());
        Assert(report.Warnings is { Count: > 0 } && report.Warnings.Any(warning => warning.Contains("opt-in", StringComparison.Ordinal)), "metadata has an explicit opt-in gate");
        Assert(!report.OperationSucceeded, "metadata without opt-in did not perform the requested identity operation");
        Assert(runner.Calls.Count == 0, "metadata gate sends no CLI calls");
    }

    private static async Task TestHealthAndPatches()
    {
        var runner = new FakeRunner((_, args) =>
        {
            var query = GraphQuery(args);
            if (query.StartsWith("HealthResources", StringComparison.Ordinal)) return GraphRows(new { id = VmId + "/providers/Microsoft.ResourceHealth/availabilityStatuses/current", subscriptionId = Subscription, resourceId = VmId, availabilityState = "Unavailable", properties = new { secret = Secret } });
            if (query.StartsWith("ServiceHealthResources", StringComparison.Ordinal)) return GraphRows(new { id = "service-event", subscriptionId = Subscription, status = "Active", eventType = "ServiceIssue" });
            if (query.StartsWith("AlertsManagementResources", StringComparison.Ordinal)) return GraphRows(new { id = "alert", name = "CPU alert", subscriptionId = Subscription, targetResource = VmId, monitorCondition = "Fired", alertState = "New", severity = "Sev0", properties = new { secret = Secret } });
            if (query.StartsWith("PatchAssessmentResources", StringComparison.Ordinal)) return GraphRows(new { id = VmId + "/patchAssessmentResults/latest", subscriptionId = Subscription, status = "Succeeded", critical = 2, security = 3, rebootPending = true, lastModifiedDateTime = DateTimeOffset.UtcNow.AddDays(-8).ToString("O"), errorDetails = Secret });
            return VmRows();
        });
        var health = await new AzureProvider(runner).CollectAsync("health", Options());
        Assert(health.Findings.Any(f => f.Code == "AZURE_RESOURCE_HEALTH") && health.Findings.Any(f => f.Code == "AZURE_SERVICE_HEALTH") && health.Findings.Any(f => f.Code == "AZURE_MONITOR_ALERT" && f.Severity == FindingSeverity.Critical), "health produces resource, service and active alert findings");
        var patches = await new AzureProvider(runner).CollectAsync("patches", Options());
        Assert(new[] { "AZURE_PATCHES_MISSING", "AZURE_REBOOT_PENDING", "AZURE_PATCH_ASSESSMENT_STALE" }.All(code => patches.Findings.Any(f => f.Code == code)), "patch summary reports missing updates, reboot and stale evidence");
        Assert(!JsonSerializer.Serialize(new[] { health, patches }).Contains(Secret, StringComparison.Ordinal), "health/patch projections omit error and raw properties");
        runner.AssertReadOnly();
    }

    private static async Task TestVmAndBundle()
    {
        var samples = Enumerable.Range(1, 160).Select(i => new { timeStamp = DateTimeOffset.UtcNow.AddHours(-i).ToString("O"), average = 2.0, maximum = 8.0 }).ToArray();
        var runner = new FakeRunner((_, args) =>
        {
            if (args.Take(2).SequenceEqual(new[] { "graph", "query" }))
            {
                if (GraphQuery(args).StartsWith("SecurityResources", StringComparison.Ordinal)) return GraphRows(new { id = VmId + "/providers/Microsoft.Security/assessments/a", subscriptionId = Subscription, resourceId = VmId, status = "Unhealthy", displayName = "Review security", properties = new { secret = Secret } });
                return VmRows();
            }
            if (args.Take(2).SequenceEqual(new[] { "vm", "get-instance-view" })) return JsonSerializer.Serialize(new { instanceView = new { statuses = new[] { new { code = "PowerState/running", displayStatus = "VM running", message = Secret } }, vmAgent = new { vmAgentVersion = "2.1", extensionHandlers = Secret } } });
            if (args.Take(3).SequenceEqual(new[] { "vm", "extension", "list" })) return JsonSerializer.Serialize(new[] { new { id = VmId + "/extensions/monitor", name = "monitor", publisher = "Microsoft.Azure.Monitor", settings = Secret, protectedSettings = Secret } });
            if (args.Take(3).SequenceEqual(new[] { "monitor", "metrics", "list" })) return JsonSerializer.Serialize(new { value = new[] { new { timeseries = new[] { new { data = samples, metadata = Secret } } } } });
            if (args.Take(3).SequenceEqual(new[] { "monitor", "activity-log", "list" })) return JsonSerializer.Serialize(new[] { new { resourceId = VmId, eventTimestamp = DateTimeOffset.UtcNow.ToString("O"), operationName = new { value = "Microsoft.Compute/virtualMachines/read" }, status = new { value = "Succeeded" }, caller = Secret, claims = Secret, properties = new { requestBody = Secret } } });
            throw new InvalidOperationException("Unexpected Azure command");
        });
        var options = Options();
        options["resource"] = VmId;
        var provider = new AzureProvider(runner);
        var vm = await provider.CollectAsync("vm", options);
        var bundle = await provider.CollectAsync("bundle", options);
        var cost = await provider.CollectAsync("cost", options);
        Assert(vm.OperationSucceeded && bundle.OperationSucceeded && cost.OperationSucceeded, "resolved targets and collected evidence explicitly succeed");
        Assert(!JsonSerializer.Serialize(new[] { vm, bundle, cost }).Contains(Secret, StringComparison.Ordinal), "VM, metric and bundle projections omit settings, logs, claims and request contents");
        Assert(JsonSerializer.Serialize(vm).Contains("VM running", StringComparison.Ordinal), "VM includes safe instance view");
        Assert(cost.Findings.Any(f => f.Code == "AZURE_VM_LOW_CPU"), "six days of paired low hourly CPU samples supports review candidate");
        Assert(runner.Calls.Any(call => call.Arguments.Take(3).SequenceEqual(new[] { "vm", "extension", "list" }) && call.Arguments.Contains("--vm-name") && call.Arguments.Contains("--resource-group")), "VM extension list uses explicit VM and resource-group arguments");
        runner.AssertReadOnly();
    }

    private static async Task TestDrift()
    {
        var runner = new FakeRunner((_, _) => VmRows());
        var baseline = Path.Combine(Path.GetTempPath(), "opscope-azure-drift-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var options = Options();
            options["baseline"] = baseline;
            await File.WriteAllTextAsync(baseline, JsonSerializer.Serialize(new { resources = new[] { new { type = "Microsoft.Compute/virtualMachines", name = "vm-a", location = "eastus", properties = new { hardwareProfile = new { vmSize = "Standard_D4s_v5" } }, protectedSettings = Secret } } }));
            var arm = await new AzureProvider(runner).CollectAsync("drift", options);
            Assert(arm.OperationSucceeded && arm.Findings.Any(f => f.Code == "AZURE_DRIFT_PROPERTY"), "concrete ARM declaration resolves unique live identity and detects size drift");
            await File.WriteAllTextAsync(baseline, JsonSerializer.Serialize(new { resources = new[] { new { type = "azurerm_linux_virtual_machine", name = "vm", instances = new[] { new { attributes = new { id = VmId, size = "Standard_D4s_v5", admin_password = Secret } } } } } }));
            var terraform = await new AzureProvider(runner).CollectAsync("drift", options);
            Assert(terraform.OperationSucceeded && terraform.Findings.Any(f => f.Code == "AZURE_DRIFT_PROPERTY"), "Terraform state ARM identity and size are compared");
            Assert(!JsonSerializer.Serialize(new[] { arm, terraform }).Contains(Secret, StringComparison.Ordinal), "drift does not return baseline secret fields");
            options["baseline"] = "not-executed.bicep";
            var bicep = await new AzureProvider(runner).CollectAsync("drift", options);
            Assert(!bicep.OperationSucceeded && bicep.Warnings!.Any(w => w.Contains("Bicep", StringComparison.Ordinal)) && bicep.Findings.Count == 0, "Bicep source is explicitly unsupported without execution or false compliance");
        }
        finally { File.Delete(baseline); }
        runner.AssertReadOnly();
    }

    private static async Task TestPagination()
    {
        var runner = new FakeRunner((_, args) => args.Contains("--skip-token")
            ? GraphRows(new { id = VmId + "-second", name = "vm-second", type = "microsoft.compute/virtualmachines", subscriptionId = Subscription })
            : JsonSerializer.Serialize(new { data = new[] { new { id = VmId, name = "vm-a", type = "microsoft.compute/virtualmachines", subscriptionId = Subscription } }, skip_token = "continue-page-two" }));
        var report = await new AzureProvider(runner).CollectAsync("inventory", Options());
        Assert(runner.Calls.Count == 2 && JsonSerializer.Serialize(report).Contains("vm-second", StringComparison.Ordinal), "Resource Graph follows continuation tokens and retains later-page resources");
        runner.AssertReadOnly();
    }

    private static string VmRows() => GraphRows(new { id = VmId, name = "vm-a", type = "microsoft.compute/virtualmachines", subscriptionId = Subscription, location = "eastus", resourceGroup = "rg", vmSize = "Standard_D2s_v5", bootDiagnosticsEnabled = "true" });

    private static async Task TestRequiredResourceResolution()
    {
        foreach (var operation in new[] { "vm", "bundle" })
        {
            var options = Options();
            options["resource"] = "missing";
            var missing = await new AzureProvider(new FakeRunner((_, _) => GraphRows())).CollectAsync(operation, options);
            Assert(!missing.OperationSucceeded, operation + " cannot succeed without its required target");
            options["resource"] = "vm-a";
            var ambiguous = await new AzureProvider(new FakeRunner((_, _) => GraphRows(
                new { id = VmId, name = "vm-a", type = "microsoft.compute/virtualmachines", subscriptionId = Subscription },
                new { id = VmId.Replace("resourceGroups/rg/", "resourceGroups/rg-other/", StringComparison.Ordinal), name = "vm-a", type = "microsoft.compute/virtualmachines", subscriptionId = Subscription }
            ))).CollectAsync(operation, options);
            Assert(!ambiguous.OperationSucceeded, operation + " cannot succeed with an ambiguous target name");
            var invalid = await new AzureProvider(new FakeRunner((_, _) => GraphRows(new { id = "not-an-arm-id", name = "vm-a", type = "microsoft.compute/virtualmachines", subscriptionId = Subscription }))).CollectAsync(operation, options);
            Assert(!invalid.OperationSucceeded, operation + " cannot succeed with an invalid scoped resource ID");
        }
    }

    private static async Task TestExplicitOperationStatus()
    {
        var noSubscription = await new AzureProvider(new FakeRunner((_, _) => "{\"id\":\"invalid\"}")).CollectAsync("inventory", new Dictionary<string, string>());
        Assert(!noSubscription.OperationSucceeded, "failure to resolve any subscription explicitly fails");
        var empty = await new AzureProvider(new FakeRunner((_, _) => GraphRows())).CollectAsync("inventory", Options());
        Assert(empty.OperationSucceeded, "valid empty inventory is successful without inventing missing resources");
        var partialRunner = new FakeRunner((_, args) => GraphQuery(args).Contains("agentVersion=", StringComparison.Ordinal) ? VmRows() : throw new InvalidOperationException("optional service not permitted"));
        var partial = await new AzureProvider(partialRunner).CollectAsync("posture", Options());
        Assert(partial.OperationSucceeded && partial.Warnings is { Count: > 0 }, "optional NSG/extension/Defender failures preserve successful inventory and partial operation status");
        var failedHealth = await new AzureProvider(new FakeRunner((_, _) => throw new InvalidOperationException("service not permitted"))).CollectAsync("health", Options());
        Assert(!failedHealth.OperationSucceeded, "health with no successful primary service query cannot report success");
        var partialHealth = await new AzureProvider(new FakeRunner((_, args) => GraphQuery(args).StartsWith("HealthResources", StringComparison.Ordinal) ? GraphRows() : throw new InvalidOperationException("optional service not permitted"))).CollectAsync("health", Options());
        Assert(partialHealth.OperationSucceeded, "one successful health query preserves partial service coverage without strict mode");
    }

    private static async Task TestDriftOperationStatus()
    {
        var baseline = Path.Combine(Path.GetTempPath(), "opscope-azure-drift-status-" + Guid.NewGuid().ToString("N") + ".json");
        var runner = new FakeRunner((_, _) => VmRows());
        var provider = new AzureProvider(runner);
        var options = Options();
        Assert(!(await provider.CollectAsync("drift", options)).OperationSucceeded, "missing required baseline cannot report successful drift");
        options["baseline"] = baseline;
        Assert(!(await provider.CollectAsync("drift", options)).OperationSucceeded, "unreadable/missing baseline cannot report successful drift");
        try
        {
            var unusable = new[]
            {
                "{invalid-json",
                "[]",
                "{\"resources\":[]}",
                JsonSerializer.Serialize(new { resources = new[] { new { id = "[redacted-identifier]", type = "Microsoft.Compute/virtualMachines", name = "[redacted-identifier]" } } }),
                JsonSerializer.Serialize(new { resources = new[] { new { type = "Microsoft.Compute/virtualMachines", name = "not-observed-and-unscoped" } } }),
                JsonSerializer.Serialize(new { resources = new[] { new { id = VmId.Replace(Subscription, "33333333-3333-3333-3333-333333333333", StringComparison.Ordinal) } } }),
                JsonSerializer.Serialize(new { resources = new[] { new { id = VmId.Replace("Microsoft.Compute/virtualMachines/vm-a", "Microsoft.Storage/storageAccounts/storage", StringComparison.Ordinal) } } })
            };
            foreach (var json in unusable)
            {
                await File.WriteAllTextAsync(baseline, json);
                var result = await provider.CollectAsync("drift", options);
                Assert(!result.OperationSucceeded && result.Findings.Count == 0, "unsupported/redacted/unscoped baseline cannot imply a usable comparison");
            }
            await File.WriteAllTextAsync(baseline, JsonSerializer.Serialize(new { resources = new[] { new { id = VmId }, new { id = VmId.Replace("Microsoft.Compute/virtualMachines/vm-a", "Microsoft.Storage/storageAccounts/storage", StringComparison.Ordinal) } } }));
            var partial = await provider.CollectAsync("drift", options);
            Assert(partial.OperationSucceeded && partial.Warnings!.Any(w => w.Contains("Skipped", StringComparison.Ordinal)), "supported resource comparison remains successful with unsupported-resource coverage warnings");

            var emptyProvider = new AzureProvider(new FakeRunner((_, _) => GraphRows()));
            var emptyInventory = await emptyProvider.CollectAsync("inventory", Options());
            await File.WriteAllTextAsync(baseline, ReportSecurity.Serialize(emptyInventory, redact: false));
            var emptyComparison = await emptyProvider.CollectAsync("drift", options);
            Assert(emptyComparison.OperationSucceeded && emptyComparison.Findings.Count == 0, "successful empty exported inventory with matching explicit scope can be compared with empty live inventory");
            Assert(!(await provider.CollectAsync("drift", options)).OperationSucceeded, "empty baseline does not imply a usable comparison against nonempty live inventory");
            await File.WriteAllTextAsync(baseline, ReportSecurity.Serialize(emptyInventory));
            Assert(!(await emptyProvider.CollectAsync("drift", options)).OperationSucceeded, "redacted empty inventory lacks verifiable subscription scope");
            await File.WriteAllTextAsync(baseline, ReportSecurity.Serialize(emptyInventory with { OperationSucceeded = false }, redact: false));
            Assert(!(await emptyProvider.CollectAsync("drift", options)).OperationSucceeded, "failed empty baseline collection cannot imply successful absence comparison");
            var scoped = Options();
            scoped["region"] = "eastus";
            var regionInventory = await emptyProvider.CollectAsync("inventory", scoped);
            await File.WriteAllTextAsync(baseline, ReportSecurity.Serialize(regionInventory, redact: false));
            Assert(!(await emptyProvider.CollectAsync("drift", options)).OperationSucceeded, "empty inventory from a different region filter has no matching scope");
            options["region"] = "eastus";
            Assert((await emptyProvider.CollectAsync("drift", options)).OperationSucceeded, "empty inventory with the same explicit region filter has matching scope");
        }
        finally { File.Delete(baseline); }
        runner.AssertReadOnly();
    }

    private static string GraphQuery(IReadOnlyList<string> arguments)
    {
        for (var index = 0; index + 1 < arguments.Count; index++)
            if (arguments[index] == "--graph-query") return arguments[index + 1];
        return "";
    }

    private static string GraphRows(params object[] rows) => JsonSerializer.Serialize(new { data = rows, count = rows.Length, total_records = rows.Length });

    private static Dictionary<string, string> Options() => new() { ["subscription"] = Subscription };

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException("Assertion failed: " + message);
    }

    private sealed class FakeRunner(Func<string, IReadOnlyList<string>, string> answer) : ICloudCommandRunner
    {
        public List<(string Tool, IReadOnlyList<string> Arguments)> Calls { get; } = new();

        public Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _ = TrustedCloudCommandRunner.PrepareArguments(tool, arguments);
            Calls.Add((tool, arguments.ToArray()));
            using var document = JsonDocument.Parse(answer(tool, arguments));
            return Task.FromResult(document.RootElement.Clone());
        }

        public void AssertReadOnly()
        {
            foreach (var call in Calls)
            {
                Assert(call.Tool == "az", "provider uses Azure CLI directly");
                Assert(!call.Arguments.Any(argument => new[] { "login", "create", "delete", "update", "set", "assign", "install", "enable", "invoke", "run-command", "write" }.Contains(argument, StringComparer.OrdinalIgnoreCase)), "provider performs no Azure writes or auth mutation");
                Assert(!call.Arguments.Any(argument => argument.Contains(';') || argument.Contains("$(", StringComparison.Ordinal) || argument.Contains('`')), "argument arrays contain no shell commands");
            }
        }
    }
}
