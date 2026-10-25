using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Opscope.Cloud;

/// <summary>Local hybrid-agent metadata only. Does not enroll, repair, start or authenticate agents.</summary>
public static class HybridAgents
{
    private static readonly IReadOnlyList<string> ArcArguments = Array.AsReadOnly(new[] { "show", "--json" });

    public static Task<AnalysisReport> CollectAsync(Snapshot snapshot, CancellationToken cancellationToken = default) =>
        CollectAsync(snapshot, new LocalAgentRunner(), cancellationToken);

    /// <summary>Injects the fixed local command for tests without contacting any cloud service.</summary>
    public static async Task<AnalysisReport> CollectAsync(Snapshot snapshot, ICloudCommandRunner runner, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(runner);
        cancellationToken.ThrowIfCancellationRequested();
        var warnings = new List<string>();
        var findings = new List<Finding>();
        var arcServices = snapshot.Services.Where(s => IsArcService(s.Name)).ToArray();
        var ssmServices = snapshot.Services.Where(s => IsSsmService(s.Name)).ToArray();
        var arc = new ArcAgentEvidence(arcServices.Length != 0, ServiceState(arcServices), false, null, null, null, "Unknown", "NotObserved");
        try
        {
            var output = await runner.RunAsync("azcmagent", ArcArguments, cancellationToken);
            if (output.ValueKind != JsonValueKind.Object || Encoding.UTF8.GetByteCount(output.GetRawText()) > 64 * 1024 || output.EnumerateObject().Take(101).Count() > 100)
                throw new InvalidDataException("Unsupported local agent response.");
            var fields = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var property in output.EnumerateObject())
            {
                var key = Normalize(property.Name);
                if (key is not ("resourceid" or "subscriptionid" or "tenantid" or "agentstatus" or "connectionstatus")) continue;
                if (property.Value.ValueKind != JsonValueKind.String || !fields.TryAdd(key, property.Value.GetString() ?? ""))
                    throw new InvalidDataException("Ambiguous local agent response.");
            }
            fields.TryGetValue("resourceid", out var resourceId);
            fields.TryGetValue("subscriptionid", out var subscription);
            fields.TryGetValue("tenantid", out var tenant);
            fields.TryGetValue("agentstatus", out var state);
            if (state is null) fields.TryGetValue("connectionstatus", out state);
            var connection = ArcConnectionState(state);
            var identity = ValidateResourceId(resourceId);
            subscription = Guid.TryParse(subscription, out var subscriptionId) ? subscriptionId.ToString("D") : null;
            tenant = Guid.TryParse(tenant, out var tenantId) ? tenantId.ToString("D") : null;
            if (identity is not null)
            {
                var resourceSubscription = identity.Split('/')[2];
                if (subscription is not null && !subscription.Equals(resourceSubscription, StringComparison.OrdinalIgnoreCase))
                {
                    identity = null;
                    warnings.Add("Local Arc resource and subscription identities were inconsistent; resource linkage was withheld.");
                }
                else subscription = resourceSubscription;
            }
            arc = new(arcServices.Length != 0, ServiceState(arcServices), true, identity, subscription, tenant, connection, "LocalAgentReport");
            if (identity is null) warnings.Add("The local Arc agent did not expose a valid, consistent Azure Arc machine resource ID. Host-to-resource linkage remains unknown.");
            if (connection == "Unknown") warnings.Add("The local Arc connection state was absent or unsupported; no connected/disconnected conclusion was inferred.");
            if (connection is "Disconnected" or "Expired" or "Error")
                findings.Add(new(FindingSeverity.Warning, "AZURE_ARC_DISCONNECTED", "Local Azure Arc agent is not connected",
                    $"The local agent reports {connection}" + (identity is null ? "." : $" for {identity}."),
                    "Verify whether this host is expected to be connected, then review agent connectivity and approved registration status. No agent action was performed."));
            warnings.Add("Arc connection state is reported by the local agent; independent Azure control-plane health was not queried.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is InvalidOperationException or InvalidDataException or IOException or UnauthorizedAccessException or JsonException or ArgumentException or System.ComponentModel.Win32Exception or OperationCanceledException or TimeoutException or NotSupportedException)
        {
            warnings.Add(arcServices.Length == 0
                ? "Azure Arc agent metadata was unavailable or no trusted azcmagent was installed. No Arc service was observed in the supplied snapshot; this is a coverage gap, not an enrollment requirement or proof the agent is absent."
                : "An Arc-related local service was observed, but safe agent metadata could not be read. Resource linkage and cloud connection status remain unknown.");
        }
        var ssmState = ServiceState(ssmServices);
        var ssm = new SsmAgentEvidence(ssmServices.Length != 0, ssmState, "Unknown", null);
        if (ssmServices.Length == 0)
            warnings.Add("No amazon-ssm-agent/AmazonSSMAgent service was observed in the supplied snapshot. Service collection may be incomplete; absence does not establish that this host should be enrolled in Systems Manager.");
        else
        {
            warnings.Add("Local SSM service presence/running state does not prove Systems Manager Online status or managed-instance identity. Verify the explicit managed-instance ID with describe-instance-information in the intended AWS account and region; no registration or credential files were read.");
            if (ssmState is "Stopped" or "Failed")
                findings.Add(new(FindingSeverity.Warning, "AWS_SSM_LOCAL_SERVICE_NOT_RUNNING", "Observed SSM agent service is not running",
                    $"The supplied host snapshot reports the local SSM service as {ssmState}. Cloud connection status is unknown.",
                    "Check whether the agent is expected to run and verify remote Systems Manager status before taking approved service actions."));
        }
        return new("cloud.hybrid.agents", DateTimeOffset.UtcNow, findings, new HybridAgentEvidence(arc, ssm), warnings);
    }

    private static bool IsArcService(string name) => NormalizeService(name) is "himds" or "himdsd" or "gcarcservice";
    private static bool IsSsmService(string name) => NormalizeService(name) is "amazon-ssm-agent" or "amazonssmagent" or "snap.amazon-ssm-agent.amazon-ssm-agent";
    private static string NormalizeService(string value)
    {
        var name = value.Trim().ToLowerInvariant();
        return name.EndsWith(".service", StringComparison.Ordinal) ? name[..^8] : name;
    }
    private static string Normalize(string value) => new(value.Where(char.IsAsciiLetterOrDigit).Select(char.ToLowerInvariant).ToArray());
    private static string ServiceState(IEnumerable<ServiceInfo> services)
    {
        var states = services.Select(s => s.State.Trim().ToLowerInvariant()).ToArray();
        if (states.Length == 0) return "NotObserved";
        if (states.Any(s => s is "running" or "active/running")) return "Running";
        if (states.Any(s => s is "failed" or "failed/failed")) return "Failed";
        if (states.All(s => s is "stopped" or "inactive" or "inactive/dead" or "dead")) return "Stopped";
        return "Unknown";
    }
    private static string ArcConnectionState(string? state) => state?.Trim().ToLowerInvariant() switch
    {
        "connected" => "Connected", "disconnected" or "not connected" or "notconnected" => "Disconnected",
        "expired" => "Expired", "error" => "Error", "connecting" => "Connecting", _ => "Unknown"
    };
    private static string? ValidateResourceId(string? id)
    {
        if (id is null || id.Length > 2048) return null;
        var match = Regex.Match(id, @"^/subscriptions/([0-9a-fA-F-]{36})/resourceGroups/[A-Za-z0-9_.()\-]{1,90}/providers/Microsoft\.HybridCompute/machines/[A-Za-z0-9_.\-]{1,260}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50));
        return match.Success && Guid.TryParseExact(match.Groups[1].Value, "D", out _) ? id : null;
    }
    private sealed class LocalAgentRunner : ICloudCommandRunner
    {
        public async Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
        {
            if (tool != "azcmagent" || !arguments.SequenceEqual(ArcArguments)) throw new InvalidOperationException("Unsupported local agent command.");
            var result = await CommandRunner.RunAsync(tool, arguments, TimeSpan.FromSeconds(5), outputLimit: 64 * 1024, cancellationToken: cancellationToken);
            if (result.ExitCode != 0 || result.TimedOut || result.OutputTruncated || Encoding.UTF8.GetByteCount(result.StandardOutput) > 64 * 1024)
                throw new InvalidOperationException("Local agent metadata was unavailable.");
            using var document = JsonDocument.Parse(result.StandardOutput, new JsonDocumentOptions { MaxDepth = 16 });
            return document.RootElement.Clone();
        }
    }
}

public sealed record HybridAgentEvidence(ArcAgentEvidence AzureArc, SsmAgentEvidence AwsSsm);
public sealed record ArcAgentEvidence(bool LocalServiceObserved, string LocalServiceState, bool MetadataAvailable, string? ResourceId, string? SubscriptionId, string? TenantId, string ConnectionState, string ConnectionEvidenceSource);
public sealed record SsmAgentEvidence(bool LocalServiceObserved, string LocalServiceState, string CloudConnectionState, string? ManagedInstanceId);
