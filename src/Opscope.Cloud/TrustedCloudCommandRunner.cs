using System.Text.Json;

namespace Opscope.Cloud;

public sealed class TrustedCloudCommandRunner : ICloudCommandRunner
{
    // EN: Accept exact read verbs and option arity; literal values cannot introduce endpoint or file overrides.
    // ES: Solo se admiten lecturas y opciones con aridad exacta; los valores literales no pueden introducir endpoints o archivos externos.
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
    // Only the argument forms constructed by our collectors are accepted. A
    // blocklist misses abbreviated CLI options and file/URL parameter expansion.
    private static readonly Dictionary<string, int> AwsOptions = new(StringComparer.Ordinal)
    {
        ["--output"] = 1, ["--query"] = 1, ["--profile"] = 1, ["--region"] = 1,
        ["--no-cli-pager"] = 0, ["--no-cli-auto-prompt"] = 0, ["--include-all-instances"] = 0,
        ["--filter"] = 1, ["--filters"] = 1, ["--detector-id"] = 1, ["--finding-criteria"] = 1,
        ["--finding-ids"] = -1, ["--bucket"] = 1, ["--state-value"] = 1, ["--alarm-types"] = -1,
        ["--group-ids"] = -1, ["--instance-ids"] = -1, ["--lookup-attributes"] = 1, ["--start-time"] = 1,
        ["--end-time"] = 1, ["--stack-name"] = 1, ["--owner-ids"] = -1, ["--namespace"] = 1,
        ["--metric-name"] = 1, ["--dimensions"] = -1, ["--statistics"] = -1, ["--period"] = 1
    };
    private static readonly Dictionary<string, int> AzureOptions = new(StringComparer.Ordinal)
    {
        ["--output"] = 1, ["--only-show-errors"] = 0, ["--subscription"] = 1, ["--subscriptions"] = -1,
        ["--graph-query"] = 1, ["--first"] = 1, ["--skip-token"] = 1, ["--ids"] = 1,
        ["--vm-name"] = 1, ["--resource-group"] = 1, ["--resource-id"] = 1, ["--resource"] = 1,
        ["--metric"] = 1, ["--aggregation"] = -1, ["--interval"] = 1, ["--offset"] = 1, ["--max-events"] = 1
    };

    public async Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        var args = PrepareArguments(tool, arguments);
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

    internal static List<string> PrepareArguments(string tool, IReadOnlyList<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (arguments.Count is < 2 or > 256 || arguments.Any(a => a is null || a.Length > 65536 || a.Any(char.IsControl)))
            throw new ArgumentException("Cloud query arguments exceed safety limits.");
        var pair = string.Join(' ', arguments.Take(2));
        var prefix = string.Join(' ', arguments.Take(3));
        if (tool == "aws" ? !AwsReads.Contains(pair) : tool != "az" || !AzureReads.Contains(pair, StringComparer.Ordinal) && !AzureReads.Contains(prefix, StringComparer.Ordinal))
            throw new InvalidOperationException("Cloud command is outside the read-only allowlist.");
        var allowedOptions = tool == "aws" ? AwsOptions : AzureOptions;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var index = tool == "aws" || AzureReads.Contains(pair, StringComparer.Ordinal) ? 2 : 3;
        while (index < arguments.Count)
        {
            var option = arguments[index++];
            if (!allowedOptions.TryGetValue(option, out var arity) || !seen.Add(option))
                throw new InvalidOperationException("Cloud query option is unsupported or repeated.");
            if (arity == 0) continue;
            var start = index;
            while (index < arguments.Count && !arguments[index].StartsWith('-') && (arity < 0 || index == start))
            {
                var value = arguments[index++];
                if (value.Length == 0 || value.StartsWith('@') || value.StartsWith("file://", StringComparison.OrdinalIgnoreCase) ||
                    value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || value.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Cloud query arguments must be literal values; file and URL expansion is unsupported.");
                if (option == "--output" && value != "json") throw new InvalidOperationException("Cloud query output must be JSON.");
            }
            if (index == start) throw new InvalidOperationException("Cloud query option requires a literal value.");
        }
        var args = arguments.ToList();
        foreach (var flag in tool == "aws" ? new[] { "--no-cli-pager", "--no-cli-auto-prompt" } : new[] { "--only-show-errors" })
        {
            if (!seen.Contains(flag)) args.Add(flag);
        }
        if (!seen.Contains("--output")) args.AddRange(["--output", "json"]);
        return args;
    }
}
