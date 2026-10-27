using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using Google.Apis.Auth.OAuth2;

namespace Opscope.Cloud;

public interface IGcpPatchReader
{
    Task<AnalysisReport> ReadAsync(IReadOnlyList<string> projects, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default);
}

public sealed record GcpPatchJobEvidence(string Account, string ResourceId, string State, bool DryRun,
    DateTimeOffset? CreatedAtUtc, DateTimeOffset? UpdatedAtUtc, bool? IsStale,
    long? SucceededInstanceCount, long? SucceededRebootRequiredInstanceCount, long? FailedInstanceCount,
    long? TimedOutInstanceCount, long? InactiveInstanceCount, long? NoAgentDetectedInstanceCount, long? SkippedInstanceCount);

/// <summary>Reads existing OS Config patch-job metadata only. A past job never establishes current patch compliance.</summary>
public sealed class GcpPatchReader : IGcpPatchReader
{
    private const int MaxPages = 10, MaxJobs = 1000, MaxRequests = 60;
    private const int MaxBodyBytes = 4 * 1024 * 1024, MaxTotalBytes = 8 * 1024 * 1024;
    private const string Projection = "nextPageToken,patchJobs(name,createTime,updateTime,state,dryRun,instanceDetailsSummary(succeededInstanceCount,succeededRebootRequiredInstanceCount,failedInstanceCount,timedOutInstanceCount,inactiveInstanceCount,noAgentDetectedInstanceCount,skippedInstanceCount))";
    private static readonly HttpClient DefaultClient = new(new SocketsHttpHandler { AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(10) }) { Timeout = TimeSpan.FromSeconds(30) };
    private static readonly HashSet<string> JobStates = new(StringComparer.Ordinal)
        { "STATE_UNSPECIFIED", "STARTED", "INSTANCE_LOOKUP", "PATCHING", "SUCCEEDED", "COMPLETED_WITH_INACTIVE_VMS", "COMPLETED_WITH_ERRORS", "CANCELED", "TIMED_OUT" };
    private readonly HttpClient client;
    private readonly Func<CancellationToken, Task<string>> accessToken;

    public GcpPatchReader() : this(DefaultClient, GetToken) { }
    internal GcpPatchReader(HttpClient client, Func<CancellationToken, Task<string>> accessToken)
    { this.client = client; this.accessToken = accessToken; }

    public async Task<AnalysisReport> ReadAsync(IReadOnlyList<string> projects, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(projects); ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        if (projects.Count > 20 || projects.Distinct(StringComparer.Ordinal).Count() != projects.Count || projects.Any(project => !Match(project, @"\A[a-z][a-z0-9-]{4,28}[a-z0-9]\z")))
            throw new ArgumentException("OS Config requires at most twenty distinct literal authorized project IDs.");
        if (Option("region").Length != 0 || Option("resource").Length != 0)
            throw new ArgumentException("Existing OS Config patch jobs are project-scoped; regional and resource filters are unsupported. No provider query was sent.");
        var now = DateTimeOffset.UtcNow;
        var jobs = new List<GcpPatchJobEvidence>();
        var warnings = new List<string>();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var failures = new List<CoverageState>();
        var completedScopes = 0;
        var state = CoverageState.Complete;
        if (projects.Count == 0) return Report(CoverageState.NotConfigured, "Select an existing authorized project with --project or --projects. No project discovery or authentication was attempted.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        string? token;
        try
        {
            token = await accessToken(deadline.Token);
            if (string.IsNullOrWhiteSpace(token) || token.Length > 16384 || token.Any(char.IsControl)) token = null;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error) when (IsFailure(error))
        { return Report(error is OperationCanceledException ? CoverageState.Failed : CoverageState.NotConfigured, "OS Config requires existing ADC and read permission. Authentication did not complete; no login or service activation was attempted."); }
        if (token is null) return Report(CoverageState.NotConfigured, "OS Config requires existing ADC and read permission. No login or service activation was attempted.");
        var session = new ReadSession(client, token);
        foreach (var project in projects)
        {
            var scopeComplete = true;
            try
            {
                deadline.Token.ThrowIfCancellationRequested();
                using var identity = await session.Get(new Uri($"https://cloudresourcemanager.googleapis.com/v3/projects/{project}?fields=name,projectId"), deadline.Token);
                var projectName = Text(identity.RootElement, "name");
                if (Text(identity.RootElement, "projectId") != project || !Match(projectName, @"\Aprojects/[0-9]{1,30}\z"))
                    throw new InvalidDataException("Project identity could not be verified.");
                string? cursor = null;
                var seenCursors = new HashSet<string>(StringComparer.Ordinal);
                for (var page = 0; page < MaxPages; page++)
                {
                    var uri = $"https://osconfig.googleapis.com/v1/{projectName}/patchJobs?pageSize=100&fields=" + Uri.EscapeDataString(Projection);
                    if (cursor is not null) uri += "&pageToken=" + Uri.EscapeDataString(cursor);
                    using var document = await session.Get(new Uri(uri), deadline.Token);
                    var root = document.RootElement;
                    if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Invalid OS Config envelope.");
                    if (root.TryGetProperty("patchJobs", out var rows))
                    {
                        if (rows.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Invalid patch job rows.");
                        foreach (var row in rows.EnumerateArray())
                        {
                            if (jobs.Count >= MaxJobs) { scopeComplete = false; break; }
                            if (!TryJob(row, project, projectName, now, out var job) || !ids.Add(job!.ResourceId))
                            { scopeComplete = false; continue; }
                            jobs.Add(job);
                        }
                    }
                    if (root.TryGetProperty("nextPageToken", out var cursorValue) && cursorValue.ValueKind != JsonValueKind.String)
                        throw new InvalidDataException("Invalid OS Config cursor.");
                    cursor = Text(root, "nextPageToken");
                    if (cursor.Length == 0) break;
                    if (cursor.Length > 4096 || cursor.Any(char.IsControl) || !seenCursors.Add(cursor) || page == MaxPages - 1 || jobs.Count >= MaxJobs)
                    { scopeComplete = false; break; }
                }
                if (scopeComplete) completedScopes++;
                else state = CoverageState.Partial;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception error) when (IsFailure(error))
            {
                var failure = error is ReadException classified ? classified.State : CoverageState.Failed;
                failures.Add(failure);
                warnings.Add("A scoped OS Config read could not complete. Check ADC, project visibility, existing OS Config configuration and osconfig.patchJobs.list permission. Provider bodies and credentials are omitted.");
                if (error is OperationCanceledException || session.Requests >= MaxRequests) break;
            }
            if (jobs.Count >= MaxJobs && completedScopes < projects.Count) { state = CoverageState.Partial; break; }
        }
        if (failures.Count > 0)
            state = jobs.Count > 0 || completedScopes > 0 || state == CoverageState.Partial ? CoverageState.Partial
                : failures.Distinct().Count() == 1 ? failures[0] : CoverageState.Failed;
        if (state == CoverageState.Complete && completedScopes != projects.Count) state = CoverageState.Partial;
        if (state == CoverageState.Partial) warnings.Add("OS Config job coverage is partial because a scope, response, row, page, byte, request or time bound omitted evidence.");
        return Report(state);

        string Option(string name) => options.TryGetValue(name, out var value) ? value.Trim() : string.Empty;
        AnalysisReport Report(CoverageState resultState, string? warning = null)
        {
            if (warning is not null) warnings.Add(warning);
            warnings.Add("Only existing OS Config patch-job metadata and selected counters are observed. Current patch compliance, installed or missing packages, agent coverage and guest vulnerability state remain unknown. No patch jobs, agents or APIs were created, started or enabled.");
            warnings.Add("A SUCCEEDED job is historical execution evidence, not current compliance. Dry-run jobs apply no updates. Missing counters remain unknown; jobs older than the fixed 24-hour freshness threshold are marked stale, not current.");
            if (jobs.Count == 0) warnings.Add("No patch-job observations were available. Empty, denied or unconfigured evidence never means zero missing patches or a compliant project.");
            return new("cloud.gcp.patches", now, [], new
            {
                provider = "gcp", operation = "patches",
                resources = jobs.Select(job => new CloudResource("gcp", job.Account, "global", job.ResourceId, "osconfig.patchJob", job.ResourceId.Split('/')[^1], job)).ToArray(),
                patches = new { source = "osconfig-existing-patch-jobs-v1", jobsRead = jobs.Count, jobs, complianceState = "unknown", freshnessThresholdHours = 24, latestObservedJobUpdateUtc = jobs.Select(job => job.UpdatedAtUtc).Max() },
                scope = new { schemaVersion = 1, accounts = projects },
                coverage = new CloudCoverage(resultState, now, jobs.Count, projects.Count, completedScopes, warnings.Distinct(StringComparer.Ordinal).ToArray()),
                source = "osconfig-fixed-read-only-projection", authentication = "application-default-credentials"
            }, warnings.Distinct(StringComparer.Ordinal).ToArray()) { OperationSucceeded = resultState == CoverageState.Complete };
        }
    }

    private static bool TryJob(JsonElement row, string project, string verifiedProjectName, DateTimeOffset now, out GcpPatchJobEvidence? job)
    {
        job = null;
        if (row.ValueKind != JsonValueKind.Object) return false;
        var id = Text(row, "name");
        if (!(id.StartsWith(verifiedProjectName + "/patchJobs/", StringComparison.Ordinal) || id.StartsWith("projects/" + project + "/patchJobs/", StringComparison.Ordinal)) ||
            !Match(id.Split('/')[^1], @"\A[A-Za-z0-9_-]{1,128}\z") || id.Split('/').Length != 4) return false;
        var state = Text(row, "state");
        if (!JobStates.Contains(state) || !Time(row, "createTime", now, out var created) || !Time(row, "updateTime", now, out var updated) || created > updated) return false;
        var dryRun = false;
        if (row.TryGetProperty("dryRun", out var dry))
        {
            if (dry.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return false;
            dryRun = dry.GetBoolean();
        }
        JsonElement summary = default;
        if (row.TryGetProperty("instanceDetailsSummary", out summary) && summary.ValueKind != JsonValueKind.Object) return false;
        var names = new[] { "succeededInstanceCount", "succeededRebootRequiredInstanceCount", "failedInstanceCount", "timedOutInstanceCount", "inactiveInstanceCount", "noAgentDetectedInstanceCount", "skippedInstanceCount" };
        var counts = new long?[names.Length];
        for (var index = 0; index < names.Length; index++)
        {
            if (summary.ValueKind != JsonValueKind.Object || !summary.TryGetProperty(names[index], out var value)) continue;
            var literal = value.ValueKind == JsonValueKind.String ? value.GetString() : value.ValueKind == JsonValueKind.Number ? value.GetRawText() : null;
            if (!long.TryParse(literal, NumberStyles.None, CultureInfo.InvariantCulture, out var count) || count is < 0 or > 1_000_000_000) return false;
            counts[index] = count;
        }
        var canonicalId = verifiedProjectName + "/patchJobs/" + id.Split('/')[^1];
        job = new(project, canonicalId, state, dryRun, created, updated, updated is null ? null : updated < now.AddHours(-24), counts[0], counts[1], counts[2], counts[3], counts[4], counts[5], counts[6]);
        return true;
    }

    private static bool Time(JsonElement row, string key, DateTimeOffset now, out DateTimeOffset? timestamp)
    {
        timestamp = null;
        if (!row.TryGetProperty(key, out var value)) return true;
        var text = value.ValueKind == JsonValueKind.String ? value.GetString() ?? string.Empty : string.Empty;
        if (!Match(text, @"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})\z") || !DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed) || parsed < DateTimeOffset.UnixEpoch || parsed > now.AddMinutes(2)) return false;
        timestamp = parsed.ToUniversalTime(); return true;
    }
    private static string Text(JsonElement row, string key) => row.ValueKind == JsonValueKind.Object && row.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? string.Empty : string.Empty;
    private static bool Match(string value, string pattern) => Regex.IsMatch(value, pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static bool IsFailure(Exception error) => error is IOException or InvalidDataException or HttpRequestException or JsonException or InvalidOperationException or UnauthorizedAccessException or OperationCanceledException or Google.Apis.Auth.OAuth2.Responses.TokenResponseException;
    private static async Task<string> GetToken(CancellationToken ct)
    {
        var credential = (await GoogleCredential.GetApplicationDefaultAsync(ct)).CreateScoped("https://www.googleapis.com/auth/cloud-platform");
        return await credential.UnderlyingCredential.GetAccessTokenForRequestAsync(null, ct);
    }
    private sealed class ReadException(CoverageState state) : IOException { public CoverageState State { get; } = state; }
    private sealed class ReadSession(HttpClient client, string token)
    {
        private int totalBytes;
        public int Requests { get; private set; }
        public async Task<JsonDocument> Get(Uri uri, CancellationToken ct)
        {
            if (++Requests > MaxRequests || uri.Scheme != "https" || uri.Port != 443 || uri.UserInfo.Length != 0 || uri.Host is not ("cloudresourcemanager.googleapis.com" or "osconfig.googleapis.com"))
                throw new InvalidOperationException("OS Config read budget or destination rejected.");
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode) throw new ReadException(response.StatusCode switch
                { HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized => CoverageState.PermissionDenied, HttpStatusCode.TooManyRequests => CoverageState.RateLimited, _ => CoverageState.Failed });
            if (response.Content.Headers.ContentLength > MaxBodyBytes) throw new InvalidDataException("OS Config response byte limit exceeded.");
            await using var input = await response.Content.ReadAsStreamAsync(ct);
            using var output = new MemoryStream(); var buffer = new byte[16384]; int count;
            while ((count = await input.ReadAsync(buffer, ct)) > 0)
            {
                totalBytes += count;
                if (output.Length + count > MaxBodyBytes || totalBytes > MaxTotalBytes) throw new InvalidDataException("OS Config aggregate byte limit exceeded.");
                await output.WriteAsync(buffer.AsMemory(0, count), ct);
            }
            return JsonDocument.Parse(output.ToArray(), new JsonDocumentOptions { MaxDepth = 24 });
        }
    }
}
