using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using Google.Apis.Auth.OAuth2;

namespace Opscope.Cloud;

public interface IGcpMonitoringReader
{
    Task<GcpMetricResult> ReadCpuAsync(string project, CancellationToken cancellationToken);
}

public sealed record GcpMetricPoint(DateTimeOffset TimeUtc, double Value);
public sealed record GcpCpuSeries(string Account, string ResourceId, string Region, string Metric, string Unit,
    string Aggregation, int SamplingPeriodSeconds, string Source, IReadOnlyList<GcpMetricPoint> Points);
public sealed record GcpMetricResult(CoverageState State, DateTimeOffset ObservedAtUtc,
    IReadOnlyList<GcpCpuSeries> Series, IReadOnlyList<string> Warnings);

/// <summary>Bounded, read-only Monitoring REST client. Credentials remain inside the local backend.</summary>
public sealed class GcpMonitoringReader : IGcpMonitoringReader
{
    private const int MaxPages = 10;
    private const int MaxSeries = 1000;
    private const int MaxPoints = 10000;
    private const int MaxResponseBytes = 4 * 1024 * 1024;
    private static readonly HttpClient Client = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        ConnectTimeout = TimeSpan.FromSeconds(10)
    }) { Timeout = TimeSpan.FromSeconds(30) };
    private readonly HttpClient client;
    private readonly Func<CancellationToken, Task<string>> accessToken;

    public GcpMonitoringReader() : this(Client, GetToken) { }
    internal GcpMonitoringReader(HttpClient client, Func<CancellationToken, Task<string>> accessToken)
    {
        this.client = client;
        this.accessToken = accessToken;
    }

    public async Task<GcpMetricResult> ReadCpuAsync(string project, CancellationToken cancellationToken)
    {
        if (!Regex.IsMatch(project, @"\A[a-z][a-z0-9-]{4,28}[a-z0-9]\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)))
            throw new ArgumentException("Monitoring requires an explicit Google Cloud project ID.", nameof(project));
        var observed = DateTimeOffset.UtcNow;
        var start = observed.AddMinutes(-15);
        var series = new List<GcpCpuSeries>();
        var warnings = new List<string>();
        var state = CoverageState.Complete;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var ct = timeout.Token;
        try
        {
            string token;
            try { token = await accessToken(ct); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) when (ex is IOException or HttpRequestException or InvalidOperationException or UnauthorizedAccessException or Google.Apis.Auth.OAuth2.Responses.TokenResponseException)
            {
                return Result(CoverageState.NotConfigured, "Application Default Credentials were unavailable for Monitoring. Configure ADC outside OpScope; no login, credential writes or provider error text were exposed.");
            }
            if (string.IsNullOrWhiteSpace(token) || token.Any(char.IsControl))
                return Result(CoverageState.NotConfigured, "Application Default Credentials did not provide a usable access token. Configure ADC outside OpScope; no login was attempted.");
            string? pageToken = null;
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var totalPoints = 0;
            var totalBytes = 0;
            for (var page = 0; page < MaxPages; page++)
            {
                var query = new Dictionary<string, string>
                {
                    ["filter"] = "metric.type=\"compute.googleapis.com/instance/cpu/utilization\" AND resource.type=\"gce_instance\"",
                    ["interval.startTime"] = start.ToString("O", CultureInfo.InvariantCulture),
                    ["interval.endTime"] = observed.ToString("O", CultureInfo.InvariantCulture),
                    ["aggregation.alignmentPeriod"] = "60s", ["aggregation.perSeriesAligner"] = "ALIGN_MEAN",
                    ["view"] = "FULL", ["pageSize"] = "200"
                };
                if (pageToken is not null) query["pageToken"] = pageToken;
                var uri = new Uri($"https://monitoring.googleapis.com/v3/projects/{project}/timeSeries?" + string.Join('&', query.Select(pair => Uri.EscapeDataString(pair.Key) + "=" + Uri.EscapeDataString(pair.Value))));
                if (uri.Scheme != "https" || uri.Host != "monitoring.googleapis.com" || uri.Port != 443 || uri.UserInfo.Length != 0)
                    throw new InvalidOperationException("Monitoring destination is outside the allowlist.");
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
                if (!response.IsSuccessStatusCode)
                {
                    state = response.StatusCode switch
                    {
                        HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => CoverageState.PermissionDenied,
                        HttpStatusCode.TooManyRequests => CoverageState.RateLimited,
                        _ => CoverageState.Failed
                    };
                    warnings.Add("Cloud Monitoring was unavailable for this read (" + (state == CoverageState.PermissionDenied ? "read permission denied" : state == CoverageState.RateLimited ? "provider rate limit" : "provider response") + "). No response body, credential or provider error text was exposed.");
                    break;
                }
                if (response.Content.Headers.ContentLength > MaxResponseBytes)
                    throw new InvalidDataException("Monitoring response exceeds the byte bound.");
                await using var input = await response.Content.ReadAsStreamAsync(ct);
                using var buffer = new MemoryStream();
                var block = new byte[16384];
                int read;
                while ((read = await input.ReadAsync(block, ct)) > 0)
                {
                    if (buffer.Length + read > MaxResponseBytes || totalBytes + read > 8 * 1024 * 1024)
                        throw new InvalidDataException("Monitoring response exceeds the byte bound.");
                    await buffer.WriteAsync(block.AsMemory(0, read), ct);
                    totalBytes += read;
                }
                using var document = JsonDocument.Parse(buffer.ToArray(), new JsonDocumentOptions { MaxDepth = 32 });
                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Invalid Monitoring envelope.");
                if (root.TryGetProperty("timeSeries", out var values))
                {
                    if (values.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Invalid Monitoring series.");
                    foreach (var row in values.EnumerateArray())
                    {
                        if (series.Count >= MaxSeries || totalPoints >= MaxPoints) { state = CoverageState.Partial; break; }
                        if (!TrySeries(row, project, start, observed, MaxPoints - totalPoints, out var parsed))
                        {
                            state = CoverageState.Partial;
                            continue;
                        }
                        totalPoints += parsed.Points.Count;
                        series.Add(parsed);
                    }
                }
                pageToken = String(root, "nextPageToken");
                if (pageToken.Length == 0) break;
                if (pageToken.Length > 4096 || pageToken.Any(char.IsControl) || !seen.Add(pageToken) || page == MaxPages - 1 || series.Count >= MaxSeries || totalPoints >= MaxPoints)
                { state = CoverageState.Partial; break; }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { state = CoverageState.Failed; warnings.Add("Cloud Monitoring timed out within its total read budget."); }
        catch (Exception ex) when (ex is IOException or InvalidDataException or HttpRequestException or JsonException or InvalidOperationException or UnauthorizedAccessException or Google.Apis.Auth.OAuth2.Responses.TokenResponseException)
        {
            state = CoverageState.Failed;
            warnings.Add("Cloud Monitoring or Application Default Credentials were unavailable. Configure ADC and Monitoring read permission outside OpScope; no login or credential writes were attempted.");
        }
        if (series.Count == 0) warnings.Add("No CPU time-series evidence was returned. CPU is unavailable, not zero; missing samples do not establish health.");
        if (state == CoverageState.Partial) warnings.Add("Monitoring coverage is partial because a page, row, time range or point bound was reached or some provider data was invalid.");
        if (series.Count > 0 && state is not (CoverageState.Complete or CoverageState.Partial)) state = CoverageState.Partial;
        warnings.Add("CPU uses provider timestamps and 60-second means over the last 15 minutes. Publication may lag; these samples are not a 1–5 second live host stream.");
        return new(state, observed, series, warnings);

        GcpMetricResult Result(CoverageState resultState, string warning) => new(resultState, observed, [], [warning]);
    }

    private static async Task<string> GetToken(CancellationToken ct)
    {
        var credential = (await GoogleCredential.GetApplicationDefaultAsync(ct)).CreateScoped("https://www.googleapis.com/auth/monitoring.read");
        return await credential.UnderlyingCredential.GetAccessTokenForRequestAsync("https://monitoring.googleapis.com/", ct);
    }

    private static bool TrySeries(JsonElement row, string project, DateTimeOffset start, DateTimeOffset observed,
        int remaining, out GcpCpuSeries result)
    {
        result = null!;
        if (row.ValueKind != JsonValueKind.Object || !row.TryGetProperty("resource", out var resource) ||
            String(resource, "type") != "gce_instance" || !resource.TryGetProperty("labels", out var labels) ||
            String(labels, "project_id") != project || !row.TryGetProperty("metric", out var metric) ||
            String(metric, "type") != "compute.googleapis.com/instance/cpu/utilization" ||
            !row.TryGetProperty("points", out var points) || points.ValueKind != JsonValueKind.Array || points.GetArrayLength() > remaining) return false;
        var id = String(labels, "instance_id");
        var zone = String(labels, "zone");
        if (!Regex.IsMatch(id, @"\A[0-9]{1,30}\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)) ||
            !Regex.IsMatch(zone, @"\A[a-z]+(?:-[a-z0-9]+)+[0-9]-[a-z]\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100))) return false;
        var parsed = new List<GcpMetricPoint>();
        foreach (var point in points.EnumerateArray())
        {
            if (point.ValueKind != JsonValueKind.Object || !point.TryGetProperty("interval", out var interval) ||
                !DateTimeOffset.TryParse(String(interval, "endTime"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var time) ||
                time < start || time > observed.AddMinutes(2) || !point.TryGetProperty("value", out var value) ||
                !value.TryGetProperty("doubleValue", out var raw) || !raw.TryGetDouble(out var number) || !double.IsFinite(number) || number is < 0 or > 1) return false;
            parsed.Add(new(time, number * 100));
        }
        result = new(project, $"//compute.googleapis.com/projects/{project}/zones/{zone}/instances/{id}", zone,
            "compute.googleapis.com/instance/cpu/utilization", "percent", "ALIGN_MEAN", 60, "cloud-monitoring", parsed.OrderBy(point => point.TimeUtc).DistinctBy(point => point.TimeUtc).ToArray());
        return true;
    }

    private static string String(JsonElement row, string key) => row.ValueKind == JsonValueKind.Object && row.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "";
}
