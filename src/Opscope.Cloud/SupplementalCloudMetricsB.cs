using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text;
using System.Text.RegularExpressions;

namespace Opscope.Cloud;

/// <summary>Optional, bounded CloudMonitor and service-instance PromQL reads. No metric query changes a resource.</summary>
public static class SupplementalCloudMetricsB
{
    public static bool Supports(string provider) => provider is "alibaba" or "ibm" or "scaleway";

    public static async Task<AnalysisReport> CollectAsync(string provider, IReadOnlyDictionary<string, string> options,
        ICloudCommandRunner? runner = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!Supports(provider)) throw new ArgumentException("Unknown supplemental metrics provider.", nameof(provider));
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(60));
        runner ??= new SupplementalCloudMetricsBRunner();
        var now = DateTimeOffset.UtcNow;
        var start = now.AddHours(-1);
        var metrics = new List<SupplementalMetricSeries>();
        var warnings = new List<string>();
        var limited = false;
        var pointsUsed = 0;
        var responseBytes = 0;
        var readCount = 0;
        var state = "complete";
        string Option(string key) => options.TryGetValue(key, out var value) ? value.Trim() : string.Empty;
        var account = Option("account");
        var region = Option("region");
        try
        {
            if (provider == "alibaba")
            {
                if (!Id(account) || !Region(region) || !Literal(Option("profile"), allowEmpty: true))
                    return Result("not_configured", false, "Select an explicit Alibaba account and region with an existing read-only CLI profile.");
                var profile = Option("profile");
                var requested = Option("metric-resources").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.Ordinal).ToArray();
                if (requested.Length > 10 || requested.Any(id => !Regex.IsMatch(id, "^i-[a-zA-Z0-9]{1,64}$", RegexOptions.CultureInvariant)))
                    return Result("not_configured", false, "Select at most ten explicit ECS instance IDs for metrics.");
                var identity = await Read("alibaba-monitor", ["identity", account, region, profile]);
                if (Text(identity, "AccountId") != account) return Result("permission_denied", false, "The authenticated Alibaba account does not match the configured scope.");
                var instances = await Read("alibaba-monitor", ["instances", account, region, profile, JsonSerializer.Serialize(requested)]);
                var returned = RowsAt(instances, "Instances", "Instance");
                if (returned.Any(row => Text(row, "RegionId") != region ||
                    !Regex.IsMatch(Text(row, "InstanceId"), "^i-[a-zA-Z0-9]{1,64}$", RegexOptions.CultureInvariant)))
                    return Result("permission_denied", false, "ECS returned a resource outside the explicitly authorized region or with an invalid identity. No metric query was sent.");
                var selected = returned.Select(row => Text(row, "InstanceId"))
                    .Where(id => requested.Length == 0 || requested.Contains(id, StringComparer.Ordinal)).Distinct(StringComparer.Ordinal).ToArray();
                if (requested.Length != 0 && returned.Any(row => !requested.Contains(Text(row, "InstanceId"), StringComparer.Ordinal)))
                { limited = true; warnings.Add("ECS returned resources outside the explicit metric-resource allowlist; those resources were omitted."); }
                if (requested.Any(id => !selected.Contains(id, StringComparer.Ordinal))) return Result("permission_denied", false, "One or more selected ECS instances were not visible in the authorized account and region. No metrics were queried for them.");
                if (selected.Length > 10 || Number(instances, "TotalCount") > selected.Length) { limited = true; warnings.Add("ECS enumeration or metrics exceeded the ten-resource selection bound; coverage is partial."); }
                foreach (var instance in selected.Take(10))
                {
                    string page = string.Empty;
                    var seen = new HashSet<string>(StringComparer.Ordinal);
                    var values = new List<SupplementalMetricPoint>();
                    var samplingPeriod = 60;
                    var periodObserved = false;
                    for (var number = 0; number < 10; number++)
                    {
                        var response = await Read("alibaba-monitor", ["cpu", account, region, profile, instance, start.ToString("O", CultureInfo.InvariantCulture), now.ToString("O", CultureInfo.InvariantCulture), page]);
                        if (!response.TryGetProperty("Success", out var success) || success.ValueKind != JsonValueKind.True)
                            throw new SupplementalMetricException(Classify(Text(response, "Code")), "CloudMonitor read unavailable.");
                        if (response.TryGetProperty("Period", out _))
                        {
                            if (!TryNumber(response, "Period", out var returnedPeriod) || returnedPeriod is < 1 or > 86400 || returnedPeriod != Math.Truncate(returnedPeriod))
                                throw new JsonException("Invalid CloudMonitor sample period.");
                            if (periodObserved && samplingPeriod != (int)returnedPeriod) { limited = true; break; }
                            samplingPeriod = (int)returnedPeriod; periodObserved = true;
                            if (samplingPeriod != 60) { limited = true; warnings.Add("CloudMonitor returned a period different from the requested sixty seconds; the actual returned period is preserved."); }
                        }
                        var serialized = Text(response, "Datapoints");
                        if (serialized.Length > 4 * 1024 * 1024) throw new SupplementalMetricException("partial", "CloudMonitor response exceeded its bound.");
                        using var document = JsonDocument.Parse(serialized.Length == 0 ? "[]" : serialized, new JsonDocumentOptions { MaxDepth = 16 });
                        if (document.RootElement.ValueKind != JsonValueKind.Array) throw new JsonException("Invalid CloudMonitor sample shape.");
                        foreach (var row in document.RootElement.EnumerateArray())
                        {
                            if (pointsUsed >= 10000) { limited = true; break; }
                            if (Text(row, "instanceId") != instance || !TryUnixMilliseconds(row, "timestamp", out var time) ||
                                time < start || time > now.AddMinutes(2) || !TryNumber(row, "Average", out var value) || value is < 0 or > 100)
                            { limited = true; continue; }
                            values.Add(new(time, value)); pointsUsed++;
                        }
                        page = Text(response, "NextToken");
                        if (page.Length == 0 || page == "Null") break;
                        if (pointsUsed >= 10000 || !Literal(page) || !seen.Add(page) || number == 9) { limited = true; break; }
                    }
                    metrics.Add(new(account, instance, region, "CPUUtilization", "percent", "Average", samplingPeriod, "Alibaba CloudMonitor acs_ecs_dashboard", Ordered(values)));
                    if (pointsUsed >= 10000) break;
                }
                warnings.Add("CloudMonitor CPU means use the provider's timestamps and requested 60-second period over the preceding hour; ECS/CloudMonitor permissions are independent.");
            }
            else if (provider == "ibm")
            {
                var instance = Option("monitoring-instance");
                var group = Option("resource-group");
                if (!Id(account) || !Id(group) || !Guid.TryParseExact(instance, "D", out _) || !SupplementalCloudMetricsBRunner.IbmRegions.Contains(region, StringComparer.Ordinal))
                    return Result("not_configured", false, "Select an explicit IBM account, resource-group ID, supported region and Monitoring service-instance GUID.");
                var resource = await Read("ibm-monitor", ["instance", account, group, region, instance]);
                if (Text(resource, "account_id") != account || Text(resource, "resource_group_id") != group || Text(resource, "region_id") != region ||
                    Text(resource, "guid") != instance || Text(resource, "resource_id") != "sysdig-monitor")
                    return Result("permission_denied", false, "The Monitoring instance identity, service, account, resource group or region does not match the configured scope.");
                var response = await Read("ibm-monitor", ["up", account, group, region, instance, start.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)]);
                AddPrometheus(response, account, instance, region, "IBM Cloud Monitoring PromQL");
                warnings.Add("The up metric describes observed Prometheus scrape-target availability within the explicitly selected Monitoring instance. It is not CPU utilization, application availability or Resource Controller health. No agent or Monitoring instance was provisioned.");
            }
            else
            {
                var project = Option("project");
                var source = Option("cockpit-source");
                var zone = Option("zone");
                if (region.Length == 0 && Regex.IsMatch(zone, "^(fr-par|nl-ams|pl-waw)-[0-9]$", RegexOptions.CultureInvariant)) region = zone[..^2];
                if (!Guid.TryParseExact(project, "D", out _) || !Guid.TryParseExact(source, "D", out _) || !SupplementalCloudMetricsBRunner.ScwRegions.Contains(region, StringComparer.Ordinal))
                    return Result("not_configured", false, "Select an explicit Scaleway project, Cockpit metrics data-source UUID and supported region (or zone).");
                var metadata = await Read("scaleway-cockpit", ["source", project, region, source]);
                if (Text(metadata, "id") != source || Text(metadata, "project_id") != project || Text(metadata, "region") != region || Text(metadata, "type") != "metrics" ||
                    !SupplementalCloudMetricsBRunner.ValidCockpitUrl(Text(metadata, "url"), region, source))
                    return Result("permission_denied", false, "The Cockpit source, project, region, type or endpoint does not match the configured scope.");
                var response = await Read("scaleway-cockpit", ["up", project, region, source, start.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)]);
                AddPrometheus(response, project, source, region, "Scaleway Cockpit PromQL");
                warnings.Add("The up metric describes available scrape-target observations in the selected existing Cockpit data source. An absent up series is no data; it does not establish a running instance or application. No data source, ingestion, token or agent was created.");
            }
            if (limited) { state = "partial"; warnings.Add("Some returned samples or series were outside the authorized time/shape/size bounds and were omitted; coverage is partial."); }
            if (!metrics.Any(series => series.Points.Count != 0)) { if (!limited) state = "no_data"; warnings.Add("No metric samples were observed in these reads. The metric is unavailable, not zero; no healthy state was inferred."); }
            return Result(state, !limited);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return Result("failed", false, "The optional metric read exceeded its total deadline."); }
        catch (SupplementalMetricException error) { return Result(metrics.Count != 0 ? "partial" : error.State, false, "The optional metric source was unavailable. Check its existing credentials, permissions and scope outside the browser; provider error bodies are omitted."); }
        catch (Exception error) when (error is IOException or HttpRequestException or JsonException or ArgumentException or InvalidOperationException or FormatException or OverflowException or System.ComponentModel.Win32Exception)
        { return Result(metrics.Count != 0 ? "partial" : "failed", false, "The optional metric read failed or returned an unsupported response. No credential or raw provider error was exported."); }

        async Task<JsonElement> Read(string tool, string[] arguments)
        {
            if (++readCount > 100) throw new SupplementalMetricException("partial", "Optional metric read budget exceeded.");
            var response = await runner.RunAsync(tool, arguments, deadline.Token);
            responseBytes += Encoding.UTF8.GetByteCount(response.GetRawText());
            if (responseBytes > 16 * 1024 * 1024) throw new SupplementalMetricException("partial", "Optional metric response budget exceeded.");
            return response;
        }

        void AddPrometheus(JsonElement response, string selectedAccount, string sourceId, string selectedRegion, string source)
        {
            if (Text(response, "status") != "success" || TextAt(response, "data", "resultType") != "matrix") throw new JsonException("Unsupported Prometheus response.");
            var rows = RowsAt(response, "data", "result");
            if (rows.Count > 1000) limited = true;
            foreach (var row in rows.Take(1000))
            {
                if (pointsUsed >= 10000) { limited = true; break; }
                if (row.TryGetProperty("metric", out var labels) && Text(labels, "__name__") is not ("" or "up")) { limited = true; continue; }
                var values = new List<SupplementalMetricPoint>();
                var samples = Rows(row, "values");
                if (samples.Count > 720) limited = true;
                foreach (var point in samples.Take(720))
                {
                    if (pointsUsed >= 10000) { limited = true; break; }
                    if (point.ValueKind != JsonValueKind.Array || point.GetArrayLength() != 2 || !double.TryParse(point[0].ToString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var timestamp) ||
                        !double.IsFinite(timestamp) || timestamp < start.ToUnixTimeSeconds() || timestamp > now.AddMinutes(2).ToUnixTimeSeconds() ||
                        !double.TryParse(point[1].ToString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var value) || !double.IsFinite(value) || value is not (0 or 1))
                    { limited = true; continue; }
                    values.Add(new(DateTimeOffset.UnixEpoch.AddSeconds(timestamp), value)); pointsUsed++;
                }
                metrics.Add(new(selectedAccount, sourceId, selectedRegion, "up", "ratio", "provider gauge", 60, source, Ordered(values)));
            }
        }
        AnalysisReport Result(string status, bool succeeded, string? warning = null)
        {
            if (warning is not null) warnings.Add(warning);
            return new($"cloud/{provider}/metrics", now, [], new
            {
                provider, operation = "metrics", metrics,
                coverage = new { state = status, observedAtUtc = now, enumeratedResources = metrics.Count, expectedScopes = 1, completedScopes = succeeded ? 1 : 0 },
                source = "optional provider metrics", schemaVersion = 1
            }, warnings.Distinct(StringComparer.Ordinal).ToArray()) { OperationSucceeded = succeeded };
        }
    }

    private static IReadOnlyList<SupplementalMetricPoint> Ordered(List<SupplementalMetricPoint> points) => points.OrderBy(point => point.TimeUtc).DistinctBy(point => point.TimeUtc).ToArray();
    private static string Classify(string code) => code.Contains("Throttl", StringComparison.OrdinalIgnoreCase) ? "rate_limited" : code.Contains("Forbidden", StringComparison.OrdinalIgnoreCase) || code.Contains("Access", StringComparison.OrdinalIgnoreCase) || code.Contains("Authoriz", StringComparison.OrdinalIgnoreCase) ? "permission_denied" : "failed";
    private static bool Id(string value) => Regex.IsMatch(value, "^[a-zA-Z0-9]{1,64}$", RegexOptions.CultureInvariant);
    private static bool Region(string value) => Regex.IsMatch(value, "^[a-z]{2,10}(?:-[a-z0-9]{1,16}){1,3}$", RegexOptions.CultureInvariant);
    private static bool Literal(string value, bool allowEmpty = false) => (allowEmpty && value.Length == 0) || value.Length is > 0 and <= 1024 && !value.StartsWith('-') && !value.StartsWith('@') && !value.Contains("://", StringComparison.Ordinal) && !value.Any(char.IsControl);
    private static string Text(JsonElement value, string name) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String ? property.GetString() ?? string.Empty : string.Empty;
    private static string TextAt(JsonElement value, string first, string second) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(first, out var child) ? Text(child, second) : string.Empty;
    private static List<JsonElement> Rows(JsonElement value, string key) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var rows) && rows.ValueKind == JsonValueKind.Array ? rows.EnumerateArray().ToList() : [];
    private static List<JsonElement> RowsAt(JsonElement value, string first, string second) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(first, out var child) ? Rows(child, second) : [];
    private static long Number(JsonElement value, string key) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var number) && number.TryGetInt64(out var result) ? result : 0;
    private static bool TryNumber(JsonElement value, string key, out double result) { result = 0; return value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var number) && double.TryParse(number.ToString(), NumberStyles.Float, CultureInfo.InvariantCulture, out result) && double.IsFinite(result); }
    private static bool TryUnixMilliseconds(JsonElement value, string key, out DateTimeOffset time)
    {
        time = default;
        if (!TryNumber(value, key, out var number) || number < 0 || number > 253402300799000) return false;
        time = DateTimeOffset.UnixEpoch.AddMilliseconds(number); return true;
    }
}

public sealed record SupplementalMetricPoint(DateTimeOffset TimeUtc, double Value);
public sealed record SupplementalMetricSeries(string Account, string ResourceId, string Region, string Metric, string Unit, string Aggregation,
    int SamplingPeriodSeconds, string Source, IReadOnlyList<SupplementalMetricPoint> Points);

public sealed class SupplementalMetricException(string state, string message) : IOException(message)
{
    public string State { get; } = state;
}

/// <summary>Closed semantic requests map to exact read-only CLI commands or verified vendor HTTPS routes.</summary>
public sealed class SupplementalCloudMetricsBRunner : ICloudCommandRunner
{
    private const int MaxBytes = 8 * 1024 * 1024;
    public static IReadOnlyList<string> IbmRegions { get; } = Array.AsReadOnly(new[] { "us-south", "us-east", "eu-gb", "eu-de", "jp-tok", "jp-osa", "au-syd", "ca-tor", "br-sao", "eu-es" });
    public static IReadOnlyList<string> ScwRegions { get; } = Array.AsReadOnly(new[] { "fr-par", "nl-ams", "pl-waw" });
    private static readonly HttpClient DefaultClient = new(new SocketsHttpHandler { AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(10) }) { Timeout = TimeSpan.FromSeconds(30) };
    private readonly HttpClient client;
    private readonly Func<string, string?> credential;
    public SupplementalCloudMetricsBRunner() { client = DefaultClient; credential = Environment.GetEnvironmentVariable; }
    public SupplementalCloudMetricsBRunner(HttpMessageHandler handler, Func<string, string?> credentialSource)
    { client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) }; credential = credentialSource; }

    public async Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        cancellationToken.ThrowIfCancellationRequested();
        if (arguments.Count > 10 || arguments.Any(arg => arg is null || arg.Length > 4096 || arg.Any(char.IsControl))) throw new ArgumentException("Invalid optional metric query.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        if (tool == "alibaba-monitor")
        {
            var args = AlibabaArguments(arguments);
            var result = await CommandRunner.RunAsync("aliyun", args, TimeSpan.FromSeconds(30), MaxBytes, timeout.Token);
            if (result.TimedOut || result.OutputTruncated) throw new SupplementalMetricException("partial", "CloudMonitor response exceeded the time or output budget.");
            if (result.ExitCode != 0) throw new SupplementalMetricException("failed", "Read-only CloudMonitor CLI query unavailable.");
            using var parsed = JsonDocument.Parse(result.StandardOutput, new JsonDocumentOptions { MaxDepth = 32 }); return parsed.RootElement.Clone();
        }
        Uri destination;
        string variable, header = "Authorization", instanceHeader = string.Empty;
        var action = arguments.Count > 0 ? arguments[0] : string.Empty;
        if (tool == "ibm-monitor" && arguments.Count is 5 or 7 && Id(arguments[1]) && Id(arguments[2]) && IbmRegions.Contains(arguments[3], StringComparer.Ordinal) && Guid.TryParseExact(arguments[4], "D", out _))
        {
            var instance = arguments[4];
            if (action == "instance" && arguments.Count == 5) destination = new($"https://resource-controller.cloud.ibm.com/v2/resource_instances/{instance}");
            else if (action == "up" && arguments.Count == 7)
            { destination = Prometheus($"https://{arguments[3]}.monitoring.cloud.ibm.com/prometheus/api/v1/query_range", arguments[5], arguments[6]); instanceHeader = instance; }
            else throw new InvalidOperationException("Unsupported IBM metric read.");
            variable = "IBM_CLOUD_IAM_TOKEN";
        }
        else if (tool == "scaleway-cockpit" && arguments.Count is 4 or 6 && Guid.TryParseExact(arguments[1], "D", out _) && ScwRegions.Contains(arguments[2], StringComparer.Ordinal) && Guid.TryParseExact(arguments[3], "D", out _))
        {
            if (action == "source" && arguments.Count == 4)
            { destination = new($"https://api.scaleway.com/cockpit/v1/regions/{arguments[2]}/data-sources/{arguments[3]}"); variable = "SCW_SECRET_KEY"; header = "X-Auth-Token"; }
            else if (action == "up" && arguments.Count == 6)
            { destination = Prometheus($"https://{arguments[3]}.metrics.cockpit.{arguments[2]}.scw.cloud/prometheus/api/v1/query_range", arguments[4], arguments[5]); variable = "SCW_COCKPIT_TOKEN"; header = "X-Token"; }
            else throw new InvalidOperationException("Unsupported Cockpit metric read.");
        }
        else throw new InvalidOperationException("Metric destination is outside the closed allowlist.");
        var token = credential(variable);
        if (string.IsNullOrWhiteSpace(token) || token.Length > 16384 || token.Any(char.IsControl)) throw new SupplementalMetricException("not_configured", "The optional metric credential is not configured.");
        using var request = new HttpRequestMessage(HttpMethod.Get, destination);
        if (header == "Authorization") request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        else request.Headers.Add(header, token);
        if (instanceHeader.Length != 0) request.Headers.Add("IBMInstanceID", instanceHeader);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        if (!response.IsSuccessStatusCode) throw new SupplementalMetricException(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden ? "permission_denied" : response.StatusCode == HttpStatusCode.TooManyRequests ? "rate_limited" : "failed", "The optional metric source rejected the read.");
        if (response.Content.Headers.ContentLength > MaxBytes) throw new SupplementalMetricException("partial", "Metric response exceeds its byte bound.");
        await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
        using var data = new MemoryStream(); var block = new byte[16384]; int count;
        while ((count = await stream.ReadAsync(block, timeout.Token)) > 0) { if (data.Length + count > MaxBytes) throw new SupplementalMetricException("partial", "Metric response exceeds its byte bound."); await data.WriteAsync(block.AsMemory(0, count), timeout.Token); }
        using var document = JsonDocument.Parse(data.ToArray(), new JsonDocumentOptions { MaxDepth = 32 }); return document.RootElement.Clone();
    }

    public static bool ValidCockpitUrl(string url, string region, string source)
    {
        if (!Guid.TryParseExact(source, "D", out _) || !ScwRegions.Contains(region, StringComparer.Ordinal) || !Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
        return uri.Scheme == "https" && uri.Port == 443 && uri.UserInfo.Length == 0 && uri.Host == $"{source}.metrics.cockpit.{region}.scw.cloud" && uri.AbsolutePath is "/" or "/prometheus" or "/prometheus/" && uri.Query.Length == 0 && uri.Fragment.Length == 0;
    }
    public static IReadOnlyList<string> AlibabaArguments(IReadOnlyList<string> input)
    {
        if (input.Count is not (4 or 5 or 8) || !Id(input[1]) || !Regex.IsMatch(input[2], "^[a-z]{2,10}(?:-[a-z0-9]{1,16}){1,3}$", RegexOptions.CultureInvariant) || !Literal(input[3], true)) throw new InvalidOperationException("Unsupported scoped CloudMonitor read.");
        var action = input[0]; var region = input[2];
        var args = action switch
        {
            "identity" when input.Count == 4 => new List<string> { "sts", "GetCallerIdentity" },
            "instances" when input.Count == 5 => new List<string> { "ecs", "DescribeInstances", "--RegionId", region, "--PageSize", "100", "--PageNumber", "1" },
            "cpu" when input.Count == 8 && Regex.IsMatch(input[4], "^i-[a-zA-Z0-9]{1,64}$", RegexOptions.CultureInvariant) => new List<string> { "cms", "DescribeMetricList", "--region", region, "--Namespace", "acs_ecs_dashboard", "--MetricName", "CPUUtilization", "--Dimensions", JsonSerializer.Serialize(new[] { new { instanceId = input[4] } }), "--Period", "60", "--StartTime", ValidDate(input[5]), "--EndTime", ValidDate(input[6]), "--Length", "1000" },
            _ => throw new InvalidOperationException("Unsupported CloudMonitor operation.")
        };
        if (action == "instances")
        {
            using var document = JsonDocument.Parse(input[4]);
            if (document.RootElement.ValueKind != JsonValueKind.Array || document.RootElement.GetArrayLength() > 10 || document.RootElement.EnumerateArray().Any(item => item.ValueKind != JsonValueKind.String || !Regex.IsMatch(item.GetString() ?? "", "^i-[a-zA-Z0-9]{1,64}$", RegexOptions.CultureInvariant))) throw new InvalidOperationException("Invalid ECS metric resource list.");
            if (document.RootElement.GetArrayLength() != 0) args.AddRange(["--InstanceIds", input[4]]);
        }
        if (action == "cpu" && input[7].Length != 0) { if (!Literal(input[7], false)) throw new InvalidOperationException("Invalid CloudMonitor continuation."); args.AddRange(["--NextToken", input[7]]); }
        if (input[3].Length != 0) args.AddRange(["--profile", input[3]]);
        return args;
    }
    private static Uri Prometheus(string endpoint, string start, string end)
    {
        if (!long.TryParse(start, NumberStyles.None, CultureInfo.InvariantCulture, out var from) || !long.TryParse(end, NumberStyles.None, CultureInfo.InvariantCulture, out var until) || from < 0 || until < from || until - from > 3600 || until > DateTimeOffset.UtcNow.AddMinutes(2).ToUnixTimeSeconds() || from < DateTimeOffset.UtcNow.AddHours(-2).ToUnixTimeSeconds()) throw new InvalidOperationException("Invalid bounded metric window.");
        return new(endpoint + $"?query=up&start={from}&end={until}&step=60&timeout=20s&limit=1000");
    }
    private static string ValidDate(string text) => DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var date) && date > DateTimeOffset.UtcNow.AddHours(-2) && date < DateTimeOffset.UtcNow.AddMinutes(2) ? date.ToString("O", CultureInfo.InvariantCulture) : throw new InvalidOperationException("Invalid metric date.");
    private static bool Id(string value) => Regex.IsMatch(value, "^[a-zA-Z0-9]{1,64}$", RegexOptions.CultureInvariant);
    private static bool Literal(string value, bool empty) => empty && value.Length == 0 || value.Length is > 0 and <= 1024 && !value.StartsWith('-') && !value.StartsWith('@') && !value.Contains("://", StringComparison.Ordinal) && !value.Any(char.IsControl);
}
