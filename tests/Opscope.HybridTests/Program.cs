using System.Text.Json;
using Opscope;
using Opscope.Cloud;

internal static class Program
{
    private const string Subscription = "11111111-1111-1111-1111-111111111111";
    private const string Tenant = "22222222-2222-2222-2222-222222222222";
    private const string ResourceId = "/subscriptions/" + Subscription + "/resourceGroups/rg/providers/Microsoft.HybridCompute/machines/host-a";
    private const string Secret = "NEVER-RETURN-registration-key-or-credential";

    private static async Task Main()
    {
        await ConnectedArcProjectsOnlySafeIdentity();
        await HumanReadableArcSchemaReportsDisconnected();
        await InconsistentIdentityDoesNotLink();
        await PlainHostHasCoverageGapWithoutEnrollmentFinding();
        await SsmServiceRunningIsNotOnlineEvidence();
        await StoppedSsmHasOnlyLocalServiceEvidence();
        await OversizedAgentResponseIsRejected();
        await CancellationDoesNotInvokeCommand();
        Console.WriteLine("Hybrid agent fake-runner tests passed.");
    }

    private static async Task ConnectedArcProjectsOnlySafeIdentity()
    {
        var runner = JsonRunner(new { resourceId = ResourceId, subscriptionId = Subscription, tenantId = Tenant, agentStatus = "Connected", agentErrorDetails = Secret, registrationKey = Secret, connectivityStatus = new { proxyPassword = Secret }, tags = new { secret = Secret } });
        var report = await HybridAgents.CollectAsync(Snapshot(new ServiceInfo("himdsd.service", "active/running", Secret, "systemctl")), runner);
        var evidence = Evidence(report);
        Check(evidence.AzureArc is { MetadataAvailable: true, LocalServiceObserved: true, ConnectionState: "Connected", ConnectionEvidenceSource: "LocalAgentReport" }, "Connected Arc retains explicitly local status source");
        Check(evidence.AzureArc.ResourceId == ResourceId && evidence.AzureArc.SubscriptionId == Subscription && evidence.AzureArc.TenantId == Tenant, "Arc linkage uses valid resource/subscription/tenant IDs");
        Check(!JsonSerializer.Serialize(report).Contains(Secret, StringComparison.Ordinal), "Arc never serializes raw settings, error contents, tags, keys or service descriptions");
        Check(report.Findings.All(f => f.Code != "AZURE_ARC_DISCONNECTED"), "Connected local status does not produce disconnected finding");
        FixedReadCommand(runner);
    }

    private static async Task HumanReadableArcSchemaReportsDisconnected()
    {
        var runner = JsonRunner(new Dictionary<string, object> { ["Resource ID"] = ResourceId, ["Subscription ID"] = Subscription, ["Tenant ID"] = Tenant, ["Agent Status"] = "Disconnected", ["Agent Error Details"] = Secret });
        var report = await HybridAgents.CollectAsync(Snapshot(), runner);
        Check(Evidence(report).AzureArc is { ResourceId: ResourceId, ConnectionState: "Disconnected", LocalServiceObserved: false }, "Arc CLI supports its human-readable JSON keys independently of snapshot service coverage");
        Check(report.Findings.Any(f => f.Code == "AZURE_ARC_DISCONNECTED" && f.Severity == FindingSeverity.Warning), "Disconnected Arc is warning without a critical-host policy assumption");
        Check(report.Findings.All(f => f.Severity != FindingSeverity.Critical), "No implicit Arc enrollment requirement exists");
        FixedReadCommand(runner);
    }

    private static async Task InconsistentIdentityDoesNotLink()
    {
        var runner = JsonRunner(new { resourceId = ResourceId, subscriptionId = Tenant, tenantId = Secret, agentStatus = Secret });
        var report = await HybridAgents.CollectAsync(Snapshot(), runner);
        Check(Evidence(report).AzureArc is { ResourceId: null, TenantId: null, ConnectionState: "Unknown" }, "Inconsistent/malformed identity and unknown status cannot establish linkage");
        Check(report.Warnings!.Any(w => w.Contains("inconsistent", StringComparison.Ordinal)), "Inconsistent Arc identity produces coverage warning");
        Check(!JsonSerializer.Serialize(report).Contains(Secret, StringComparison.Ordinal), "Unsupported identity/status values are never echoed");
    }

    private static async Task PlainHostHasCoverageGapWithoutEnrollmentFinding()
    {
        var runner = new FakeRunner(() => throw new InvalidOperationException(Secret));
        var report = await HybridAgents.CollectAsync(Snapshot(new ServiceInfo("unrelated-amazon-ssm-agent", "running", null, "test")), runner);
        var evidence = Evidence(report);
        Check(report.Findings.Count == 0 && !evidence.AzureArc.MetadataAvailable && !evidence.AwsSsm.LocalServiceObserved, "Plain host does not fail or infer enrollment needs or substring service matches");
        Check(report.Warnings is { Count: > 0 } && report.Warnings.Any(w => w.Contains("coverage gap", StringComparison.Ordinal)), "Missing local agent is an explicit coverage gap");
        Check(!JsonSerializer.Serialize(report).Contains(Secret, StringComparison.Ordinal), "Failed agent command does not echo credentials from errors");
        FixedReadCommand(runner);
    }

    private static async Task SsmServiceRunningIsNotOnlineEvidence()
    {
        foreach (var name in new[] { "amazon-ssm-agent.service", "AmazonSSMAgent", "snap.amazon-ssm-agent.amazon-ssm-agent.service" })
        {
            var runner = new FakeRunner(() => throw new InvalidOperationException("not installed"));
            var report = await HybridAgents.CollectAsync(Snapshot(new ServiceInfo(name, "active/running", Secret, "systemctl")), runner);
            Check(Evidence(report).AwsSsm is { LocalServiceObserved: true, LocalServiceState: "Running", CloudConnectionState: "Unknown", ManagedInstanceId: null }, "Running SSM service is not Online or managed-instance identity proof");
            Check(report.Warnings!.Any(w => w.Contains("describe-instance-information", StringComparison.Ordinal)), "SSM explains explicit remote verification needed");
            Check(report.Findings.Count == 0, "Running service causes no unnecessary finding");
            FixedReadCommand(runner);
        }
    }

    private static async Task StoppedSsmHasOnlyLocalServiceEvidence()
    {
        var runner = new FakeRunner(() => throw new InvalidOperationException("not installed"));
        var report = await HybridAgents.CollectAsync(Snapshot(new ServiceInfo("AmazonSSMAgent", "STOPPED", null, "sc.exe")), runner);
        Check(Evidence(report).AwsSsm is { LocalServiceState: "Stopped", CloudConnectionState: "Unknown" }, "Stopped local SSM does not invent cloud state");
        Check(report.Findings.Any(f => f.Code == "AWS_SSM_LOCAL_SERVICE_NOT_RUNNING" && f.Severity == FindingSeverity.Warning), "Stopped SSM service is a local warning");
        FixedReadCommand(runner);
    }

    private static async Task OversizedAgentResponseIsRejected()
    {
        var runner = JsonRunner(new { resourceId = ResourceId, agentStatus = "Connected", agentErrorDetails = new string('x', 64 * 1024) });
        var report = await HybridAgents.CollectAsync(Snapshot(), runner);
        Check(!Evidence(report).AzureArc.MetadataAvailable && report.Findings.Count == 0, "Agent metadata response is bounded before projection");
    }

    private static async Task CancellationDoesNotInvokeCommand()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var runner = JsonRunner(new { agentStatus = "Connected" });
        try { await HybridAgents.CollectAsync(Snapshot(), runner, cancellation.Token); throw new InvalidOperationException("Cancellation was not propagated."); }
        catch (OperationCanceledException) { }
        Check(runner.Calls.Count == 0, "Cancelled hybrid collection cannot invoke a command");
    }

    private static FakeRunner JsonRunner(object value) => new(() => JsonSerializer.Serialize(value));
    private static HybridAgentEvidence Evidence(AnalysisReport report) => (HybridAgentEvidence)report.Data!;
    private static void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private static void FixedReadCommand(FakeRunner runner) => Check(runner.Calls.Count == 1 && runner.Calls[0].Tool == "azcmagent" && runner.Calls[0].Arguments.SequenceEqual(new[] { "show", "--json" }), "Only fixed azcmagent show --json is executed; no registration, cloud API, credential read or agent mutation command exists");
    private static Snapshot Snapshot(params ServiceInfo[] services) => new(DateTimeOffset.UtcNow,
        new("host", "test", "test", "x64", ".NET", "test", DateTimeOffset.UtcNow, TimeSpan.Zero, false, 1, "test"),
        0, new(1, 1, 0, 0, "test"), [], [], [], [], services, new([], false, false, 0), null, [], [], TimeSpan.Zero);

    private sealed class FakeRunner(Func<string> result) : ICloudCommandRunner
    {
        public List<(string Tool, IReadOnlyList<string> Arguments)> Calls { get; } = [];
        public Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls.Add((tool, arguments.ToArray()));
            using var json = JsonDocument.Parse(result());
            return Task.FromResult(json.RootElement.Clone());
        }
    }
}
