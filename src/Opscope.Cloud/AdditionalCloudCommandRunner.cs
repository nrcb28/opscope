using System.Net;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Opscope.Cloud;

/// <summary>Fixed read commands and fixed-host REST queries for opt-in experimental adapters.</summary>
public sealed class AdditionalCloudCommandRunner : ICloudCommandRunner
{
    private const int MaximumBytes = 8 * 1024 * 1024;
    private static readonly HttpClient Http = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(10),
        AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
    }) { Timeout = TimeSpan.FromSeconds(45) };

    private readonly HttpClient client;
    private readonly Func<string, string?> credential;

    public AdditionalCloudCommandRunner() { client = Http; credential = Environment.GetEnvironmentVariable; }
    internal AdditionalCloudCommandRunner(HttpMessageHandler handler, Func<string, string?> credentialSource)
    {
        client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(45) };
        credential = credentialSource;
    }

    public async Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        if (tool.EndsWith("-api", StringComparison.Ordinal)) return await ReadApiAsync(tool, arguments, cancellationToken);
        ValidateArguments(tool, arguments);
        var prepared = arguments.ToList();
        if (tool == "gcloud")
        {
            if (!prepared.Contains("--quiet", StringComparer.Ordinal)) prepared.Add("--quiet");
            if (!prepared.Contains("--verbosity", StringComparer.Ordinal)) prepared.AddRange(["--verbosity", "error"]);
            if (!prepared.Contains("--format", StringComparer.Ordinal)) prepared.AddRange(["--format", "json"]);
        }
        var result = await CommandRunner.RunAsync(tool, prepared, TimeSpan.FromSeconds(45), MaximumBytes, cancellationToken);
        if (result.TimedOut || result.OutputTruncated)
            throw new AdditionalCloudQueryException("partial", "Cloud response exceeded the time or output budget.");
        if (result.ExitCode != 0)
            throw new AdditionalCloudQueryException("failed", "Cloud CLI query unavailable; verify installation, selected identity and read permissions outside the browser.");
        using var document = JsonDocument.Parse(result.StandardOutput, new JsonDocumentOptions { MaxDepth = 48 });
        return document.RootElement.Clone();
    }

    internal static void ValidateArguments(string tool, IReadOnlyList<string> arguments)
    {
        if (arguments.Count is < 2 or > 64 || arguments.Any(a => string.IsNullOrEmpty(a) || a.Length > 1024 || a.Any(char.IsControl)))
            throw new ArgumentException("Invalid read-only cloud arguments.");
        var reads = tool switch
        {
            "oci" => new[] { "compute instance list", "bv volume list", "network vcn list", "network security-list list" },
            "openstack" => new[] { "server list", "volume list", "network list", "security group rule list", "token issue" },
            "aliyun" => new[] { "ecs DescribeInstances", "ecs DescribeDisks", "vpc DescribeVpcs", "sts GetCallerIdentity" },
            "gcloud" => new[] { "asset search-all-resources", "compute instances list", "compute disks list", "compute addresses list", "compute networks list", "compute firewall-rules list", "container clusters list", "sql instances list", "run services list", "storage buckets list" },
            _ => Array.Empty<string>()
        };
        var prefix = reads.OrderByDescending(s => s.Length).FirstOrDefault(s => arguments.Take(s.Split(' ').Length).SequenceEqual(s.Split(' ')));
        if (prefix is null) throw new InvalidOperationException("Cloud command is outside the read-only allowlist.");
        var options = tool switch
        {
            "oci" => new[] { "--compartment-id", "--region", "--profile", "--limit", "--page", "--output" },
            "openstack" => new[] { "--os-cloud", "--os-project-id", "--os-region-name", "--limit", "--long", "-f", "-c" },
            "aliyun" => new[] { "--profile", "--RegionId", "--PageNumber", "--PageSize" },
            "gcloud" => new[] { "--project", "--scope", "--asset-types", "--page-size", "--limit", "--format", "--quiet", "--verbosity" },
            _ => Array.Empty<string>()
        };
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = prefix.Split(' ').Length; i < arguments.Count; i++)
        {
            var option = arguments[i];
            if (!options.Contains(option, StringComparer.Ordinal) || option != "-c" && !seen.Add(option))
                throw new InvalidOperationException("Unsupported or repeated cloud option.");
            if (option is "--quiet" or "--long") continue;
            if (++i == arguments.Count) throw new InvalidOperationException("Cloud option requires a literal value.");
            var value = arguments[i];
            Literal(value);
            if (option is "--format" or "--output" or "-f" or "-o" && !value.Equals("json", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Cloud output must be JSON.");
            if (option == "--verbosity" && value != "error") throw new InvalidOperationException("Cloud verbosity must be error.");
        }
        static void Literal(string value)
        {
            if (value.StartsWith('-') || value.StartsWith('@') || value.Contains("://", StringComparison.Ordinal) || value.Any(char.IsControl))
                throw new InvalidOperationException("Cloud options cannot contain file, endpoint, or option expansion.");
        }
    }

    private async Task<JsonElement> ReadApiAsync(string tool, IReadOnlyList<string> args, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(45));
        var requestToken = deadline.Token;
        if (args.Count != 3) throw new ArgumentException("Invalid bounded cloud query.");
        var ibm = tool == "ibm-api";
        if (!ibm && (!int.TryParse(args[2], out var number) || number is < 1 or > 20) ||
            ibm && (args[2].Length > 1024 || args[2].Any(char.IsControl))) throw new ArgumentException("Invalid bounded cloud query.");
        var page = ibm ? 1 : int.Parse(args[2], CultureInfo.InvariantCulture);
        var scope = args[1];
        var scalewayScope = scope.Split('@', 2);
        var validScalewayScope = scalewayScope.Length == 2 && Guid.TryParseExact(scalewayScope[0], "D", out _) && Regex.IsMatch(scalewayScope[1], "^[a-z]{2}-[a-z]{3}-[0-9]$", RegexOptions.CultureInvariant);
        var ibmScope = scope.Split('@', 2);
        var validIbmScope = ibmScope.Length == 2 && ibmScope.All(part => Regex.IsMatch(part, "^[a-zA-Z0-9]{1,64}$", RegexOptions.CultureInvariant));
        var now = DateTimeOffset.UtcNow;
        var end = now.ToUnixTimeSeconds();
        var ibmState = args[0].StartsWith("resources-", StringComparison.Ordinal) ? args[0][10..] : string.Empty;
        var ibmStates = new[] { "active", "provisioning", "failed", "inactive", "pre_provisioning", "pending_reclamation" };
        var route = (tool, args[0]) switch
        {
            ("digitalocean-api", "cpu-metrics") when Regex.IsMatch(scope, "^[0-9]{1,20}$", RegexOptions.CultureInvariant) => ($"https://api.digitalocean.com/v2/monitoring/metrics/droplet/cpu?host_id={scope}&start={end - 3600}&end={end}", "DIGITALOCEAN_ACCESS_TOKEN"),
            ("digitalocean-api", "project-resources") when Guid.TryParseExact(scope, "D", out _) => ($"https://api.digitalocean.com/v2/projects/{scope}/resources?per_page=200&page={page}", "DIGITALOCEAN_ACCESS_TOKEN"),
            ("digitalocean-api", "droplets") when scope == "configured" => ($"https://api.digitalocean.com/v2/droplets?per_page=200&page={page}", "DIGITALOCEAN_ACCESS_TOKEN"),
            ("digitalocean-api", "volumes") when scope == "configured" => ($"https://api.digitalocean.com/v2/volumes?per_page=200&page={page}", "DIGITALOCEAN_ACCESS_TOKEN"),
            ("digitalocean-api", "firewalls") when scope == "configured" => ($"https://api.digitalocean.com/v2/firewalls?per_page=200&page={page}", "DIGITALOCEAN_ACCESS_TOKEN"),
            ("hetzner-api", "cpu-metrics") when Regex.IsMatch(scope, "^[0-9]{1,20}$", RegexOptions.CultureInvariant) => ($"https://api.hetzner.cloud/v1/servers/{scope}/metrics?type=cpu&start={Uri.EscapeDataString(now.AddHours(-1).ToString("O", CultureInfo.InvariantCulture))}&end={Uri.EscapeDataString(now.ToString("O", CultureInfo.InvariantCulture))}&step=60", "HCLOUD_TOKEN"),
            ("hetzner-api", "servers" or "volumes" or "networks" or "firewalls" or "load_balancers") when scope == "configured" => ($"https://api.hetzner.cloud/v1/{args[0]}?per_page=50&page={page}", "HCLOUD_TOKEN"),
            ("ibm-api", _) when validIbmScope && ibmStates.Contains(ibmState, StringComparer.Ordinal) => ($"https://resource-controller.cloud.ibm.com/v2/resource_instances?resource_group_id={ibmScope[1]}&state={ibmState}&limit=100" + (args[2] == "1" ? string.Empty : "&start=" + Uri.EscapeDataString(args[2])), "IBM_CLOUD_IAM_TOKEN"),
            ("scaleway-api", "servers" or "volumes") when validScalewayScope => ($"https://api.scaleway.com/instance/v1/zones/{scalewayScope[1]}/{args[0]}?project={scalewayScope[0]}&per_page=100&page={page}", "SCW_SECRET_KEY"),
            ("cloudflare-api", "zones") when Regex.IsMatch(scope, "^[a-fA-F0-9]{32}$", RegexOptions.CultureInvariant) => ($"https://api.cloudflare.com/client/v4/zones?account.id={scope}&per_page=50&page={page}", "CLOUDFLARE_API_TOKEN"),
            _ => throw new InvalidOperationException("Cloud API query is outside the fixed-host read-only allowlist.")
        };
        var token = credential(route.Item2);
        if (string.IsNullOrWhiteSpace(token) || token.Length > 16 * 1024 || token.Any(char.IsControl)) throw new AdditionalCloudQueryException("not_configured", "Cloud credential is not configured in the local process.");
        using var request = new HttpRequestMessage(HttpMethod.Get, route.Item1);
        if (tool == "scaleway-api") request.Headers.Add("X-Auth-Token", token);
        else request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, requestToken);
        if (!response.IsSuccessStatusCode)
        {
            var state = response.StatusCode switch
            {
                HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => "permission_denied",
                HttpStatusCode.TooManyRequests => "rate_limited",
                _ => "failed"
            };
            throw new AdditionalCloudQueryException(state, "Cloud read-only API query unavailable; inspect provider configuration outside the browser.");
        }
        if (response.Content.Headers.ContentLength > MaximumBytes) throw new AdditionalCloudQueryException("partial", "Cloud response exceeded its byte budget.");
        await using var stream = await response.Content.ReadAsStreamAsync(requestToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int count;
        while ((count = await stream.ReadAsync(chunk, requestToken)) != 0)
        {
            if (buffer.Length + count > MaximumBytes) throw new AdditionalCloudQueryException("partial", "Cloud response exceeded its byte budget.");
            await buffer.WriteAsync(chunk.AsMemory(0, count), requestToken);
        }
        using var document = JsonDocument.Parse(buffer.ToArray(), new JsonDocumentOptions { MaxDepth = 48 });
        return document.RootElement.Clone();
    }
}

public sealed class AdditionalCloudQueryException(string state, string message) : IOException(message)
{
    public string State { get; } = state;
}
