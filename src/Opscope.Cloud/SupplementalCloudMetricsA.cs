using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

[assembly: InternalsVisibleTo("Opscope.SupplementalMetricsATests")]

namespace Opscope.Cloud;

/// <summary>Optional provider-native metrics; all destination and query shapes are fixed by the backend.</summary>
public static class SupplementalCloudMetricsA
{
    public static bool Supports(string provider) => provider is "oci" or "cloudflare" or "openstack";

    public static Task<AnalysisReport> CollectAsync(string provider, IReadOnlyDictionary<string, string> options,
        ICloudCommandRunner? commandRunner = null, CancellationToken cancellationToken = default) =>
        new Reader(commandRunner ?? new SupplementalCloudMetricsCommandRunnerA(), Client, Environment.GetEnvironmentVariable)
            .CollectAsync(provider, options, cancellationToken);

    internal static Task<AnalysisReport> CollectForTestAsync(string provider, IReadOnlyDictionary<string, string> options,
        ICloudCommandRunner commandRunner, HttpClient http, Func<string, string?> credential, CancellationToken cancellationToken = default) =>
        new Reader(commandRunner, http, credential).CollectAsync(provider, options, cancellationToken);

    private static readonly HttpClient Client = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(10),
        AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
    }) { Timeout = TimeSpan.FromSeconds(30) };

    // Cloudflare documents this read-only dataset and its string/Time scalar names in the Zone Analytics migration guide.
    // Only variables change. No arbitrary GraphQL document or mutation is accepted from callers.
    internal const string EdgeQuery = "query OpscopeEdge($zoneTag: string, $start: Time, $end: Time) { viewer { zones(filter: {zoneTag: $zoneTag}) { zoneTag httpRequests1mGroups(orderBy: [datetimeFiveMinutes_ASC], limit: 13, filter: {datetime_geq: $start, datetime_lt: $end}) { dimensions { datetimeFiveMinutes } sum { requests bytes cachedRequests } } } } }";

    private sealed class Reader(ICloudCommandRunner runner, HttpClient client, Func<string, string?> credential)
    {
        private const int MaximumPoints = 10000;
        private const int MaximumSeries = 1000;
        private readonly List<NativeMetricSeriesA> series = [];
        private readonly List<string> warnings = [];
        private DateTimeOffset now;
        private CoverageState state = CoverageState.Complete;
        private int pointCount, bytes, reads, expected = 1, completed;
        private bool partial;

        public async Task<AnalysisReport> CollectAsync(string provider, IReadOnlyDictionary<string, string> options, CancellationToken ct)
        {
            ArgumentNullException.ThrowIfNull(options);
            if (!Supports(provider)) throw new ArgumentException("Unsupported supplemental metrics provider.", nameof(provider));
            now = DateTimeOffset.UtcNow;
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(TimeSpan.FromSeconds(60));
            try
            {
                if (provider == "oci") await Oci(options, deadline.Token);
                else if (provider == "openstack") await OpenStack(options, deadline.Token);
                else await Cloudflare(options, deadline.Token);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (OperationCanceledException) { Fail(CoverageState.Failed, "Metric collection exceeded its total read deadline."); }
            catch (MetricReadException ex) { Fail(ex.State, "The configured metric source could not be read. Verify its read permissions, service availability and local identity outside Opscope."); }
            catch (Exception ex) when (ex is IOException or JsonException or HttpRequestException or InvalidOperationException or System.ComponentModel.Win32Exception or FormatException or OverflowException)
            { Fail(CoverageState.Failed, "The configured metric source was unavailable or returned an invalid response; provider output and credential details are omitted."); }
            if (series.Count > 0 && state is not (CoverageState.Complete or CoverageState.Partial)) partial = true;
            if (partial) state = CoverageState.Partial;
            if (pointCount == 0) warnings.Add("No metric observations were returned. Missing telemetry is unavailable, not zero, and does not establish resource health.");
            warnings.Add(provider switch
            {
                "oci" => "OCI CPU is the provider's one-minute mean over the preceding hour in the selected compartment and region. Subcompartments and unqueried namespaces are outside coverage.",
                "openstack" => "OpenStack metrics require the Gnocchi CLI plugin and telemetry service. CPU is a cumulative counter and memory retains its provider-declared unit; neither is presented as host CPU utilization. The requested granularity must exist in the archive policy.",
                _ => "Cloudflare Edge analytics contains five-minute request and bandwidth sums over the preceding hour. Plan, ingestion latency and analytics permissions limit coverage; this is not host CPU or a five-second live stream."
            });
            return new AnalysisReport($"cloud/{provider}/metrics", now, [], new
            {
                provider, operation = "metrics", schemaVersion = 1,
                source = provider == "cloudflare" ? "cloudflare-edge-analytics" : provider == "oci" ? "oci-monitoring" : "openstack-gnocchi",
                metrics = series, dataStatus = pointCount == 0 ? "no_data" : "observed",
                coverage = new CloudCoverage(state, now, series.Count, expected, completed, warnings.Distinct(StringComparer.Ordinal).ToArray())
            }, warnings.Distinct(StringComparer.Ordinal).ToArray()) { OperationSucceeded = state == CoverageState.Complete };
        }

        private async Task Oci(IReadOnlyDictionary<string, string> options, CancellationToken ct)
        {
            var compartment = Option(options, "compartment"); var region = Option(options, "region"); var profile = Option(options, "profile");
            if (compartment.Length == 0 || region.Length == 0) { Fail(CoverageState.NotConfigured, "OCI metrics require an explicit compartment and region."); return; }
            if (!Match(compartment, @"^ocid1\.compartment\.[a-zA-Z0-9.]{8,220}$") || !Match(region, @"^[a-z]{2}-[a-z0-9-]+-[0-9]+$") || profile.Length > 0 && !Literal(profile))
                throw new ArgumentException("OCI metrics require literal compartment, region and profile identifiers.");
            var args = new List<string> { "monitoring", "metric-data", "summarize-metrics-data", "--compartment-id", compartment,
                "--namespace", "oci_computeagent", "--query-text", "CpuUtilization[1m].mean()", "--start-time", Time(now.AddHours(-1)),
                "--end-time", Time(now), "--resolution", "1m", "--region", region, "--output", "json" };
            if (profile.Length > 0) args.AddRange(["--profile", profile]);
            var response = await Run("oci", args, ct);
            var rows = Array(response, "data");
            if (rows is null) throw new InvalidDataException("Invalid OCI metric envelope.");
            foreach (var row in rows.Value.EnumerateArray())
            {
                if (series.Count >= MaximumSeries) { Limit(); break; }
                var account = Text(row, "compartment-id");
                if (account != compartment || Text(row, "name") != "CpuUtilization" || Text(row, "namespace") != "oci_computeagent") { Limit(); continue; }
                var resource = Object(row, "dimensions") is { } dimensions ? Text(dimensions, "resourceId") : "";
                if (!Match(resource, @"^ocid1\.instance\.[a-zA-Z0-9.]{8,220}$")) { Limit(); continue; }
                var points = new List<NativeMetricPointA>();
                var values = Array(row, "aggregated-datapoints");
                if (values is null) { Limit(); continue; }
                foreach (var value in values.Value.EnumerateArray())
                    if (Date(value, "timestamp", now.AddHours(-1), now.AddMinutes(2), out var time) && Number(value, "value", out var number) && number is >= 0 and <= 100)
                        AddPoint(points, time, number);
                    else Limit();
                AddSeries(new(compartment, resource, region, "CpuUtilization", "percent", "mean", 60, "oci-monitoring", Ordered(points)));
            }
            completed = 1;
        }

        private async Task OpenStack(IReadOnlyDictionary<string, string> options, CancellationToken ct)
        {
            var project = Option(options, "project"); var cloud = Option(options, "cloud-name"); var region = Option(options, "region");
            if (project.Length == 0 || cloud.Length == 0 || region.Length == 0) { Fail(CoverageState.NotConfigured, "OpenStack metrics require explicit cloud-name, project and region plus a preconfigured telemetry service."); return; }
            if (!Uuid(project) || !Literal(cloud) || !Literal(region)) throw new ArgumentException("OpenStack metrics require literal authorized scope identifiers.");
            string[] Scope() => ["--os-cloud", cloud, "--os-project-id", project, "--os-region-name", region, "-f", "json"];
            var identity = await Run("openstack", new[] { "token", "issue", "-c", "project_id" }.Concat(Scope()).ToArray(), ct);
            if (!SameUuid(Text(identity, "project_id"), project)) throw new MetricReadException(CoverageState.PermissionDenied);
            string? marker = null;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (var page = 0; page < 5; page++)
            {
                var search = new List<string> { "metric", "resource", "search", "project_id=\"" + project + "\"", "--type", "instance", "--limit", "20" };
                if (marker is not null) search.AddRange(["--marker", marker]);
                var response = await Run("openstack", search.Concat(Scope()).ToArray(), ct);
                if (response.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Invalid Gnocchi resource list.");
                var rows = response.EnumerateArray().Take(21).ToArray();
                if (rows.Length > 20) { Limit(); rows = rows.Take(20).ToArray(); }
                foreach (var row in rows)
                {
                    var id = Text(row, "id");
                    if (!Uuid(id) || !SameUuid(Text(row, "project_id"), project) || !seen.Add(id)) { Limit(); continue; }
                    var detail = await Run("openstack", new[] { "metric", "resource", "show", id, "--type", "instance" }.Concat(Scope()).ToArray(), ct);
                    if (!SameUuid(Text(detail, "project_id"), project) || !SameUuid(Text(detail, "id"), id)) { Limit(); continue; }
                    var metrics = Object(detail, "metrics");
                    if (metrics is null) { Limit(); continue; }
                    foreach (var name in new[] { "cpu", "memory.usage" })
                    {
                        var metricId = Text(metrics.Value, name);
                        if (metricId.Length == 0) continue;
                        if (!Uuid(metricId)) { Limit(); continue; }
                        var metadata = await Run("openstack", new[] { "metric", "show", metricId }.Concat(Scope()).ToArray(), ct);
                        var unit = Text(metadata, "unit");
                        if (!SameUuid(Text(metadata, "id"), metricId) || Text(metadata, "name") != name ||
                            !SameUuid(Text(metadata, "resource/id"), id) || !SameUuid(Text(metadata, "resource/project_id"), project) ||
                            name == "cpu" && unit is not ("ns" or "nanoseconds") || name == "memory.usage" && unit is not ("B" or "bytes" or "MB" or "MiB")) { Limit(); continue; }
                        var measures = await Run("openstack", new[] { "metric", "measures", "show", metricId, "--start", Time(now.AddHours(-1)), "--stop", Time(now), "--granularity", "60", "--aggregation", "mean", "--utc" }.Concat(Scope()).ToArray(), ct);
                        if (measures.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Invalid Gnocchi measures.");
                        var points = new List<NativeMetricPointA>();
                        foreach (var value in measures.EnumerateArray())
                            if (Date(value, "timestamp", now.AddHours(-1), now.AddMinutes(2), out var time) && Number(value, "value", out var number) && number >= 0 && Number(value, "granularity", out var period) && period == 60)
                                AddPoint(points, time, number);
                            else Limit();
                        AddSeries(new(project, id, region, name, unit, "mean", 60, "openstack-gnocchi", Ordered(points)));
                    }
                    if (reads >= 55 || pointCount >= MaximumPoints) { Limit(); break; }
                }
                if (rows.Length < 20 || reads >= 55 || pointCount >= MaximumPoints) break;
                marker = Text(rows[^1], "id");
                if (page == 4) Limit();
            }
            completed = 1;
        }

        private async Task Cloudflare(IReadOnlyDictionary<string, string> options, CancellationToken ct)
        {
            var account = Option(options, "account");
            var zones = Option(options, "zones").Split([',', ';'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (account.Length == 0 || zones.Length == 0) { Fail(CoverageState.NotConfigured, "Cloudflare analytics requires an explicit account and authorized --zones allowlist."); return; }
            if (!Match(account, "^[a-fA-F0-9]{32}$") || zones.Length > 20 || zones.Any(zone => !Match(zone, "^[a-fA-F0-9]{32}$")))
                throw new ArgumentException("Cloudflare metrics accept one account and at most twenty explicit zone IDs.");
            expected = zones.Length;
            var token = credential("CLOUDFLARE_API_TOKEN");
            if (string.IsNullOrWhiteSpace(token) || token.Length > 16384 || token.Any(char.IsControl)) { Fail(CoverageState.NotConfigured, "Cloudflare analytics token is not configured in the server process."); return; }
            foreach (var zone in zones)
            {
                try
                {
                    var owned = await Http(HttpMethod.Get, "https://api.cloudflare.com/client/v4/zones/" + zone, token, null, ct);
                    if (!True(owned, "success") || Object(owned, "result") is not { } resource ||
                        !Text(resource, "id").Equals(zone, StringComparison.OrdinalIgnoreCase) || Object(resource, "account") is not { } owner || !Text(owner, "id").Equals(account, StringComparison.OrdinalIgnoreCase))
                        throw new MetricReadException(CoverageState.PermissionDenied);
                    var payload = JsonSerializer.Serialize(new { query = EdgeQuery, variables = new { zoneTag = zone, start = Time(now.AddHours(-1)), end = Time(now) } });
                    var response = await Http(HttpMethod.Post, "https://api.cloudflare.com/client/v4/graphql", token, payload, ct);
                    if (response.ValueKind != JsonValueKind.Object || response.TryGetProperty("errors", out var errors) &&
                        (errors.ValueKind != JsonValueKind.Array || errors.GetArrayLength() > 0)) throw new MetricReadException(CoverageState.Failed);
                    if (Object(response, "data") is not { } data || Object(data, "viewer") is not { } viewer || Array(viewer, "zones") is not { } returned || returned.GetArrayLength() != 1 ||
                        !Text(returned[0], "zoneTag").Equals(zone, StringComparison.OrdinalIgnoreCase) || Array(returned[0], "httpRequests1mGroups") is not { } buckets)
                        throw new InvalidDataException("Invalid scoped analytics response.");
                    foreach (var (field, unit) in new[] { ("requests", "requests"), ("bytes", "bytes"), ("cachedRequests", "requests") })
                    {
                        var points = new List<NativeMetricPointA>();
                        foreach (var bucket in buckets.EnumerateArray().Take(13))
                            if (Object(bucket, "dimensions") is { } dimensions && Date(dimensions, "datetimeFiveMinutes", now.AddHours(-1), now.AddMinutes(2), out var time) &&
                                Object(bucket, "sum") is { } sum && Number(sum, field, out var value) && value >= 0)
                                AddPoint(points, time, value);
                            else Limit();
                        if (buckets.GetArrayLength() >= 13) Limit();
                        AddSeries(new(account, zone, "edge", field, unit, "sum", 300, "cloudflare-edge-analytics", Ordered(points)));
                    }
                    completed++;
                }
                catch (MetricReadException ex)
                {
                    Fail(ex.State, "A configured Cloudflare zone or analytics query was unavailable; no provider errors or token values are exposed.");
                    if (ex.State == CoverageState.RateLimited) break;
                }
            }
        }

        private async Task<JsonElement> Run(string tool, IReadOnlyList<string> args, CancellationToken ct)
        {
            if (++reads > 60) throw new MetricReadException(CoverageState.Partial);
            return await runner.RunAsync(tool, args, ct);
        }
        private async Task<JsonElement> Http(HttpMethod method, string uri, string token, string? payload, CancellationToken ct)
        {
            if (++reads > 60) throw new MetricReadException(CoverageState.Partial);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(30));
            using var request = new HttpRequestMessage(method, uri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            if (payload is not null) request.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (!response.IsSuccessStatusCode) throw new MetricReadException(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden ? CoverageState.PermissionDenied : response.StatusCode == HttpStatusCode.TooManyRequests ? CoverageState.RateLimited : CoverageState.Failed);
            const int pageLimit = 2 * 1024 * 1024;
            if (response.Content.Headers.ContentLength > pageLimit) throw new MetricReadException(CoverageState.Partial);
            await using var input = await response.Content.ReadAsStreamAsync(timeout.Token);
            using var output = new MemoryStream(); var block = new byte[8192]; int count;
            while ((count = await input.ReadAsync(block, timeout.Token)) != 0)
            {
                bytes += count;
                if (bytes > 8 * 1024 * 1024 || output.Length + count > pageLimit) throw new MetricReadException(CoverageState.Partial);
                output.Write(block, 0, count);
            }
            using var document = JsonDocument.Parse(output.ToArray(), new JsonDocumentOptions { MaxDepth = 32 });
            return document.RootElement.Clone();
        }
        private void AddPoint(List<NativeMetricPointA> points, DateTimeOffset time, double value)
        { if (pointCount >= MaximumPoints) { Limit(); return; } points.Add(new(time, value)); pointCount++; }
        private void AddSeries(NativeMetricSeriesA metric)
        { if (series.Count >= MaximumSeries) Limit(); else series.Add(metric); }
        private void Limit() { partial = true; if (!warnings.Contains("Metric bounds, time-window checks or scope validation omitted some observations.", StringComparer.Ordinal)) warnings.Add("Metric bounds, time-window checks or scope validation omitted some observations."); }
        private void Fail(CoverageState failure, string warning) { state = failure; warnings.Add(warning); }
    }

    private static IReadOnlyList<NativeMetricPointA> Ordered(List<NativeMetricPointA> points) => points.OrderBy(point => point.TimeUtc).DistinctBy(point => point.TimeUtc).ToArray();
    private static bool Literal(string value) => value.Length is > 0 and <= 256 && !value.StartsWith('-') && !value.StartsWith('@') && !value.Contains("://", StringComparison.Ordinal) && !value.Any(char.IsControl);
    private static bool Match(string value, string pattern) => Regex.IsMatch(value, pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static bool Uuid(string value) => Guid.TryParseExact(value, "D", out _) || value.Length == 32 && Guid.TryParseExact(value, "N", out _);
    private static bool SameUuid(string value, string expected) => Guid.TryParse(value, out var first) && Guid.TryParse(expected, out var second) && first == second;
    private static string Option(IReadOnlyDictionary<string, string> options, string key) => options.TryGetValue(key, out var value) ? value.Trim() : "";
    private static string Text(JsonElement value, string key) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var text) && text.ValueKind == JsonValueKind.String ? text.GetString() ?? "" : "";
    private static bool True(JsonElement value, string key) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var item) && item.ValueKind == JsonValueKind.True;
    private static JsonElement? Object(JsonElement value, string key) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var item) && item.ValueKind == JsonValueKind.Object ? item : null;
    private static JsonElement? Array(JsonElement value, string key) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var item) && item.ValueKind == JsonValueKind.Array ? item : null;
    private static bool Number(JsonElement value, string key, out double number)
    { number = 0; return value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var item) && item.ValueKind == JsonValueKind.Number && item.TryGetDouble(out number) && double.IsFinite(number); }
    private static bool Date(JsonElement value, string key, DateTimeOffset start, DateTimeOffset end, out DateTimeOffset time) => DateTimeOffset.TryParse(Text(value, key), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out time) && time >= start && time <= end;
    private static string Time(DateTimeOffset time) => time.ToString("O", CultureInfo.InvariantCulture);
    private sealed class MetricReadException(CoverageState state) : IOException { public CoverageState State { get; } = state; }
}

public sealed record NativeMetricPointA(DateTimeOffset TimeUtc, double Value);
public sealed record NativeMetricSeriesA(string Account, string ResourceId, string Region, string Metric, string Unit,
    string Aggregation, int SamplingPeriodSeconds, string Source, IReadOnlyList<NativeMetricPointA> Points);

/// <summary>Separate closed grammar for optional telemetry reads; ordinary cloud command options do not enable it.</summary>
public sealed class SupplementalCloudMetricsCommandRunnerA : ICloudCommandRunner
{
    public async Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        Validate(tool, arguments);
        var result = await CommandRunner.RunAsync(tool, arguments, TimeSpan.FromSeconds(30), 4 * 1024 * 1024, cancellationToken);
        if (result.TimedOut || result.OutputTruncated || result.ExitCode != 0) throw new IOException("Configured telemetry CLI read was unavailable or exceeded its bounded response budget.");
        using var document = JsonDocument.Parse(result.StandardOutput, new JsonDocumentOptions { MaxDepth = 32 }); return document.RootElement.Clone();
    }

    internal static void Validate(string tool, IReadOnlyList<string> args)
    {
        if (args.Count is < 2 or > 64 || args.Any(value => value.Length is 0 or > 2048 || value.Any(char.IsControl))) throw new ArgumentException("Invalid bounded telemetry command.");
        var prefixes = tool == "oci" ? new[] { "monitoring metric-data summarize-metrics-data" } : tool == "openstack" ? new[] { "token issue", "metric resource search", "metric resource show", "metric measures show", "metric show" } : [];
        var prefix = prefixes.FirstOrDefault(value => args.Take(value.Split(' ').Length).SequenceEqual(value.Split(' ')));
        if (prefix is null) throw new InvalidOperationException("Telemetry command is outside the read-only allowlist.");
        var options = tool == "oci" ? new[] { "--compartment-id", "--namespace", "--query-text", "--start-time", "--end-time", "--resolution", "--region", "--profile", "--output" } : new[] { "--os-cloud", "--os-project-id", "--os-region-name", "-f", "-c", "--type", "--limit", "--marker", "--resource-id", "--start", "--stop", "--granularity", "--aggregation", "--utc" };
        var index = prefix.Split(' ').Length;
        if (tool == "openstack" && prefix != "token issue")
        {
            if (index >= args.Count) throw new InvalidOperationException("Telemetry read requires a fixed identifier or scoped search.");
            var argument = args[index++];
            if (prefix == "metric resource search" ? !Regex.IsMatch(argument, "^project_id=\"[a-fA-F0-9-]{32,36}\"$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)) : !Guid.TryParse(argument, out _))
                throw new InvalidOperationException("Telemetry read identifiers must be authorized UUIDs.");
        }
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var supplied = new Dictionary<string, string>(StringComparer.Ordinal);
        while (index < args.Count)
        {
            var option = args[index++];
            if (!options.Contains(option, StringComparer.Ordinal) || !seen.Add(option)) throw new InvalidOperationException("Unsupported or repeated telemetry option.");
            if (option == "--utc") continue;
            if (index == args.Count) throw new InvalidOperationException("Telemetry option needs a literal value.");
            var value = args[index++];
            supplied[option] = value;
            if (value.StartsWith('-') || value.StartsWith('@') || value.Contains("://", StringComparison.Ordinal)) throw new InvalidOperationException("Telemetry option cannot expand files or endpoints.");
            if (option is "--output" or "-f" && value != "json" || option == "--namespace" && value != "oci_computeagent" || option == "--query-text" && value != "CpuUtilization[1m].mean()" || option == "--resolution" && value != "1m" || option == "--aggregation" && value != "mean" || option == "--granularity" && value != "60" || option == "--type" && value != "instance" || option == "-c" && value != "project_id" || option == "--limit" && value != "20")
                throw new InvalidOperationException("Telemetry option differs from the fixed read specification.");
        }
        bool Has(params string[] required) => required.All(supplied.ContainsKey);
        static bool Uuid(string value) => Guid.TryParseExact(value, "D", out _) || Guid.TryParseExact(value, "N", out _);
        if (tool == "oci")
        {
            if (!Has("--compartment-id", "--namespace", "--query-text", "--start-time", "--end-time", "--resolution", "--region", "--output") ||
                !Regex.IsMatch(supplied["--compartment-id"], @"\Aocid1\.compartment\.[a-zA-Z0-9.]{8,220}\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)) ||
                !Regex.IsMatch(supplied["--region"], @"\A[a-z]{2}-[a-z0-9-]+-[0-9]+\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)))
                throw new InvalidOperationException("OCI telemetry requires a complete fixed query and explicit scope.");
            ValidateWindow(supplied["--start-time"], supplied["--end-time"]);
        }
        else
        {
            if (!Has("--os-cloud", "--os-project-id", "--os-region-name", "-f") || !Uuid(supplied["--os-project-id"]))
                throw new InvalidOperationException("OpenStack telemetry requires explicit cloud, project and region.");
            if (prefix == "token issue" && !Has("-c") || prefix is "metric resource show" or "metric resource search" && !Has("--type") ||
                prefix == "metric resource search" && !Has("--limit"))
                throw new InvalidOperationException("Telemetry read is missing its fixed identity projection or resource bounds.");
            if (prefix == "metric resource search")
            {
                var project = args[3]["project_id=\"".Length..^1];
                if (Guid.Parse(project) != Guid.Parse(supplied["--os-project-id"]))
                    throw new InvalidOperationException("Resource search must use the selected project.");
            }
            if (prefix == "metric measures show")
            {
                if (!Has("--start", "--stop", "--granularity", "--aggregation") || !seen.Contains("--utc"))
                    throw new InvalidOperationException("Telemetry measures require a fixed interval, aggregation and UTC timestamps.");
                ValidateWindow(supplied["--start"], supplied["--stop"]);
            }
        }

        static void ValidateWindow(string start, string end)
        {
            if (!DateTimeOffset.TryParse(start, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var from) ||
                !DateTimeOffset.TryParse(end, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var until) ||
                from < DateTimeOffset.UtcNow.AddHours(-2) || until > DateTimeOffset.UtcNow.AddMinutes(2) || until <= from || until - from > TimeSpan.FromHours(1))
                throw new InvalidOperationException("Telemetry dates exceed the bounded read window.");
        }
    }
}
