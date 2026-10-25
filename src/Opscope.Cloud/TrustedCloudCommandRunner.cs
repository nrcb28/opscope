using System.Text.Json;

namespace Opscope.Cloud;

public sealed class TrustedCloudCommandRunner : ICloudCommandRunner
{
    private static readonly HashSet<string> AwsReads = new(StringComparer.Ordinal)
    {
        "sts get-caller-identity", "ec2 describe-regions", "ec2 describe-instances", "ec2 describe-volumes",
        "ec2 describe-security-groups", "ec2 describe-vpcs", "ec2 describe-network-interfaces", "ec2 describe-addresses",
        "ec2 describe-instance-status", "ec2 describe-snapshots", "s3api list-buckets", "s3api get-bucket-location",
        "s3api get-public-access-block", "s3api get-bucket-policy-status", "s3api get-bucket-acl", "securityhub get-findings",
        "guardduty list-detectors", "guardduty list-findings", "guardduty get-findings", "health describe-events",
        "cloudwatch describe-alarms", "cloudwatch get-metric-statistics", "cloudtrail lookup-events",
        "cloudformation describe-stacks", "cloudformation list-stack-resources", "cloudformation describe-stack-resource-drifts",
        "ssm describe-instance-information", "ssm describe-instance-patch-states"
    };
    private static readonly string[] AzureReads = ["account show", "graph query", "vm get-instance-view", "vm extension list", "monitor metrics list", "monitor activity-log list"];

    public async Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        if (arguments.Count is < 2 or > 256 || arguments.Any(a => a.Length > 65536 || a.Contains('\0')))
            throw new ArgumentException("Cloud query arguments exceed safety limits.");
        var pair = string.Join(' ', arguments.Take(2));
        var prefix = string.Join(' ', arguments.Take(3));
        if (tool == "aws" ? !AwsReads.Contains(pair) : tool != "az" || !AzureReads.Contains(pair, StringComparer.Ordinal) && !AzureReads.Contains(prefix, StringComparer.Ordinal))
            throw new InvalidOperationException("Cloud command is outside the read-only allowlist.");
        if (arguments.Any(a => a.Split('=', 2)[0] is "--endpoint-url" or "--no-verify-ssl" or "--debug" or "--cli-input-json" or "--cli-input-yaml"))
            throw new InvalidOperationException("Cloud endpoint, credential and debug overrides are not supported.");
        var args = arguments.ToList();
        if (tool == "aws") args.AddRange(["--no-cli-pager", "--no-cli-auto-prompt"]);
        else args.Add("--only-show-errors");
        if (!args.Contains("--output", StringComparer.Ordinal)) args.AddRange(["--output", "json"]);
        var executable = tool;
        if (tool == "az" && OperatingSystem.IsWindows())
        {
            executable = "azure-python";
            args.InsertRange(0, ["-I", "-B", "-m", "azure.cli"]);
        }
        var result = await CommandRunner.RunAsync(executable, args, TimeSpan.FromSeconds(45), 8 * 1024 * 1024, cancellationToken);
        if (result.TimedOut || result.OutputTruncated) throw new IOException("Cloud response exceeded the configured time or output limit.");
        if (result.ExitCode != 0)
            throw new IOException($"{tool} read-only query unavailable (exit {result.ExitCode}). Check installed CLI, selected profile and read permissions.");
        using var document = JsonDocument.Parse(result.StandardOutput, new JsonDocumentOptions { MaxDepth = 48 });
        return document.RootElement.Clone();
    }
}
