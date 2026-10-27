using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using Google.Apis.Auth.OAuth2;

namespace Opscope.Cloud;

public interface IGcpAdvancedReader
{
    Task<GcpAdvancedResult> ReadSccAsync(string project, CancellationToken cancellationToken);
    Task<GcpAdvancedResult> ReadBillingAsync(IReadOnlyList<string> projects, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken);
}

public sealed record GcpSecurityFinding(string Account, string ResourceId, string Id, string Category, string Severity, string State, DateTimeOffset? EventTimeUtc);
public sealed record GcpSccEvidence(int FindingsCount, string ScopeKind, string Location, string Source, IReadOnlyList<GcpSecurityFinding> Findings);
public sealed record GcpCurrencySubtotal(string Currency, decimal ObservedCost, decimal ObservedCredits, decimal ObservedNetCost, int ObservedRows);
public sealed record GcpBillingEvidence(string ResourceId, string Source, IReadOnlyList<GcpCurrencySubtotal> CurrencySubtotals,
    int RowsRead, int MatchedRows, DateTimeOffset? PeriodStartUtc, DateTimeOffset? PeriodEndUtc, bool IsComplete);
public sealed record GcpAdvancedResult(CoverageState State, DateTimeOffset ObservedAtUtc, IReadOnlyList<Finding> Findings,
    GcpSccEvidence? Scc, GcpBillingEvidence? Billing, IReadOnlyList<string> Warnings);

/// <summary>Explicit advanced reads only. This reader never creates BigQuery jobs or enables provider services.</summary>
public sealed class GcpAdvancedReader : IGcpAdvancedReader
{
    private const int MaxPages = 10, MaxRows = 1000, MaxBodyBytes = 4 * 1024 * 1024, MaxTotalBytes = 8 * 1024 * 1024;
    private static readonly HttpClient DefaultClient = new(new SocketsHttpHandler { AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(10) }) { Timeout = TimeSpan.FromSeconds(30) };
    private readonly HttpClient client;
    private readonly Func<string, CancellationToken, Task<string>> accessToken;
    public GcpAdvancedReader() : this(DefaultClient, GetToken) { }
    internal GcpAdvancedReader(HttpClient client, Func<string, CancellationToken, Task<string>> accessToken)
    { this.client = client; this.accessToken = accessToken; }

    public async Task<GcpAdvancedResult> ReadSccAsync(string project, CancellationToken cancellationToken)
    {
        ValidateProject(project);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        var now = DateTimeOffset.UtcNow;
        var records = new List<GcpSecurityFinding>();
        var findingIds = new HashSet<string>(StringComparer.Ordinal);
        var findings = new List<Finding>();
        var warnings = new List<string>();
        var state = CoverageState.Complete;
        string? token;
        try { token = await Token("scc", deadline.Token); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return Result(CoverageState.Failed, "SCC authentication exceeded its read deadline."); }
        var read = new ReadSession(client, token);
        if (read.Token is null) return Result(CoverageState.NotConfigured, "SCC requires existing Application Default Credentials. No login or service activation was attempted.");
        try
        {
            using var projectDocument = await read.Get(new Uri($"https://cloudresourcemanager.googleapis.com/v3/projects/{project}"), deadline.Token);
            var descriptor = projectDocument.RootElement;
            var projectName = Text(descriptor, "name");
            if (Text(descriptor, "projectId") != project || !Match(projectName, @"\Aprojects/[0-9]{1,30}\z"))
                throw new InvalidDataException("Project identity could not be verified.");
            string? pageToken = null;
            var seen = new HashSet<string>(StringComparer.Ordinal);
            for (var page = 0; page < MaxPages; page++)
            {
                var path = $"https://securitycenter.googleapis.com/v1/{projectName}/sources/-/findings?pageSize=100";
                if (pageToken is not null) path += "&pageToken=" + Uri.EscapeDataString(pageToken);
                using var document = await read.Get(new Uri(path), deadline.Token);
                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Invalid SCC envelope.");
                if (root.TryGetProperty("listFindingsResults", out var rows))
                {
                    if (rows.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Invalid SCC findings.");
                    foreach (var row in rows.EnumerateArray())
                    {
                        if (records.Count >= MaxRows) { state = CoverageState.Partial; break; }
                        if (!row.TryGetProperty("finding", out var finding) || !row.TryGetProperty("resource", out var resource) ||
                            !BoundProject(Text(resource, "projectName"), projectName, project))
                        { state = CoverageState.Partial; continue; }
                        var id = Text(finding, "name");
                        var resourceId = Text(resource, "name");
                        var severity = Text(finding, "severity");
                        var findingState = Text(finding, "state");
                        var category = Text(finding, "category");
                        if (id.Length is < 1 or > 2048 || resourceId.Length is < 1 or > 2048 ||
                            !Match(category, @"\A[A-Za-z0-9_. -]{1,160}\z") ||
                            severity is not ("CRITICAL" or "HIGH" or "MEDIUM" or "LOW" or "SEVERITY_UNSPECIFIED") || findingState is not ("ACTIVE" or "INACTIVE"))
                        { state = CoverageState.Partial; continue; }
                        DateTimeOffset? time = null;
                        var eventTime = Text(finding, "eventTime");
                        if (eventTime.Length != 0)
                        {
                            if (!DateTimeOffset.TryParse(eventTime, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed) || parsed > now.AddMinutes(2))
                            { state = CoverageState.Partial; continue; }
                            time = parsed;
                        }
                        if (!findingIds.Add(id)) { state = CoverageState.Partial; continue; }
                        records.Add(new(project, resourceId, id, category, severity, findingState, time));
                        if (findingState == "ACTIVE") findings.Add(new(severity is "CRITICAL" or "HIGH" ? FindingSeverity.Critical : severity == "MEDIUM" ? FindingSeverity.Warning : FindingSeverity.Info,
                            "GCP_SCC_FINDING", "Security Command Center: " + category,
                            $"{resourceId}: existing {severity} finding in state {findingState}.",
                            "Review the existing finding and its remediation in Security Command Center. Opscope does not activate SCC or change the resource."));
                    }
                }
                pageToken = Text(root, "nextPageToken");
                if (pageToken.Length == 0) break;
                if (!ValidPageToken(pageToken) || !seen.Add(pageToken) || page == MaxPages - 1 || records.Count >= MaxRows)
                { state = CoverageState.Partial; break; }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error) when (IsReadFailure(error))
        { state = records.Count > 0 ? CoverageState.Partial : FailureState(error); warnings.Add("SCC could not complete the scoped read. Verify ADC, project visibility, existing SCC configuration and finding read permission; provider bodies and credentials are omitted."); }
        if (state == CoverageState.Partial) warnings.Add("SCC coverage is partial because a response, scope, page, row, byte or time bound omitted evidence.");
        warnings.Add("SCC reports existing project-scoped global findings only. An empty list does not establish absence of vulnerabilities, complete SCC coverage or a secure project.");
        return Result(state);

        GcpAdvancedResult Result(CoverageState resultState, string? warning = null)
        {
            if (warning is not null) warnings.Add(warning);
            return new(resultState, now, findings, new(records.Count, "project", "global", "security-command-center-v1", records), null, warnings);
        }
    }

    public async Task<GcpAdvancedResult> ReadBillingAsync(IReadOnlyList<string> projects, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(projects); ArgumentNullException.ThrowIfNull(options);
        if (projects.Count is < 1 or > 20) throw new ArgumentException("Billing needs one to twenty authorized project IDs.");
        foreach (var project in projects) ValidateProject(project);
        var exportProject = Option("billing-project"); var dataset = Option("billing-dataset"); var table = Option("billing-table");
        var now = DateTimeOffset.UtcNow;
        var warnings = new List<string>();
        var totals = new Dictionary<string, (decimal Cost, decimal Credits, int Rows)>(StringComparer.Ordinal);
        var rowsRead = 0; var matchedRows = 0;
        DateTimeOffset? periodStart = null, periodEnd = null;
        var sourceId = string.Empty;
        if (exportProject.Length == 0 || dataset.Length == 0 || table.Length == 0)
            return Result(CoverageState.NotConfigured, "Billing is opt-in: configure an existing export with --billing-project, --billing-dataset and --billing-table. No export, dataset or query job was created.");
        ValidateProject(exportProject);
        if (!Match(dataset, @"\A[A-Za-z0-9_]{1,1024}\z") || !Match(table, @"\A[A-Za-z0-9_-]{1,1024}\z"))
            throw new ArgumentException("Billing requires literal existing dataset/table IDs; SQL, decorators, URLs and wildcard expansion are unsupported.");
        sourceId = $"projects/{exportProject}/datasets/{dataset}/tables/{table}";
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        string? token;
        try { token = await Token("billing", deadline.Token); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return Result(CoverageState.Failed, "Billing authentication exceeded its read deadline."); }
        var read = new ReadSession(client, token);
        if (read.Token is null) return Result(CoverageState.NotConfigured, "Billing requires existing ADC with BigQuery table metadata/data read permission. No login or query job was created.");
        var state = CoverageState.Partial;
        try
        {
            var baseUri = $"https://bigquery.googleapis.com/bigquery/v2/projects/{exportProject}/datasets/{dataset}/tables/{table}";
            using var metadata = await read.Get(new Uri(baseUri), deadline.Token);
            var root = metadata.RootElement;
            if (root.ValueKind != JsonValueKind.Object || Text(root, "type") != "TABLE" || !root.TryGetProperty("tableReference", out var reference) ||
                Text(reference, "projectId") != exportProject || Text(reference, "datasetId") != dataset || Text(reference, "tableId") != table)
                throw new InvalidDataException("The existing billing table identity or type could not be verified.");
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("schema", out var schema) ||
                !schema.TryGetProperty("fields", out var schemaFields) || schemaFields.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException("A billing table schema is required.");
            var fields = ParseFields(schemaFields);
            RequireField(fields, "cost", "FLOAT", "FLOAT64", "NUMERIC", "BIGNUMERIC");
            RequireField(fields, "currency", "STRING"); RequireField(fields, "project", "RECORD", "STRUCT");
            RequireField(fields, "usage_start_time", "TIMESTAMP"); RequireField(fields, "usage_end_time", "TIMESTAMP");
            var projectField = fields.Single(field => field.Name == "project"); RequireField(projectField.Fields, "id", "STRING");
            RequireField(fields, "credits", "RECORD", "STRUCT");
            var creditField = fields.Single(field => field.Name == "credits");
            if (creditField.Mode != "REPEATED") throw new InvalidDataException("Billing credits must use the standard repeated-record schema.");
            RequireField(creditField.Fields, "amount", "FLOAT", "FLOAT64", "NUMERIC", "BIGNUMERIC");
            string? pageToken = null;
            var seen = new HashSet<string>(StringComparer.Ordinal);
            for (var page = 0; page < MaxPages; page++)
            {
                var uri = baseUri + "/data?maxResults=100" + (pageToken is null ? string.Empty : "&pageToken=" + Uri.EscapeDataString(pageToken));
                using var document = await read.Get(new Uri(uri), deadline.Token);
                var response = document.RootElement;
                if (response.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Invalid billing table response.");
                var continuation = Text(response, "pageToken");
                if (continuation.Length > 0 && (!ValidPageToken(continuation) || seen.Contains(continuation)))
                { warnings.Add("Billing returned an invalid or repeated continuation; that page was omitted to avoid duplicate amounts."); break; }
                if (response.TryGetProperty("rows", out var rows))
                {
                    if (rows.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Invalid billing table rows.");
                    foreach (var row in rows.EnumerateArray())
                    {
                        if (rowsRead >= MaxRows) { warnings.Add("Billing row retention reached its 1,000-row bound; remaining rows were omitted."); break; }
                        rowsRead++;
                        var cells = Cells(row, fields.Count);
                        var projectCell = Cell(cells, fields, "project");
                        if (projectCell.ValueKind == JsonValueKind.Null) continue;
                        var observedProject = Scalar(projectCell, projectField.Fields, "id");
                        if (!projects.Contains(observedProject, StringComparer.Ordinal)) continue;
                        if (!Money(Cell(cells, fields, "cost"), out var cost) || !Match(Scalar(Cell(cells, fields, "currency")), @"\A[A-Z]{3}\z") ||
                            !Timestamp(Cell(cells, fields, "usage_start_time"), out var from) || !Timestamp(Cell(cells, fields, "usage_end_time"), out var to) || from > to || to > now.AddMinutes(2))
                        { warnings.Add("Some billing rows had invalid monetary/time data and were omitted; no zero was substituted."); continue; }
                        var currency = Scalar(Cell(cells, fields, "currency"));
                        decimal credits = 0;
                        if (!Credits(Cell(cells, fields, "credits"), creditField, out credits))
                        { warnings.Add("A billing row had an unsupported credit structure and was omitted rather than overstating net cost."); continue; }
                        var current = totals.GetValueOrDefault(currency);
                        totals[currency] = (checked(current.Cost + cost), checked(current.Credits + credits), current.Rows + 1);
                        matchedRows++;
                        periodStart = periodStart is null || from < periodStart ? from : periodStart;
                        periodEnd = periodEnd is null || to > periodEnd ? to : periodEnd;
                    }
                }
                pageToken = continuation;
                if (pageToken.Length == 0) break;
                if (!ValidPageToken(pageToken) || !seen.Add(pageToken) || page == MaxPages - 1 || rowsRead >= MaxRows)
                { warnings.Add("Billing pagination was bounded or repeated a cursor; totals cover observed rows only."); break; }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error) when (IsReadFailure(error) || error is OverflowException)
        { state = matchedRows > 0 ? CoverageState.Partial : FailureState(error); warnings.Add("Billing export could not complete the read. Verify existing table/schema, ADC and read permissions; provider response text and credentials are omitted."); }
        warnings.Add("Amounts are observed-row subtotals per currency, not an invoice or complete billing-period total. Reads are unsorted and bounded; export delay, omitted rows and the configured table determine coverage. No BigQuery query/job or export configuration was created.");
        if (matchedRows == 0) warnings.Add("No valid billing rows for the authorized projects were observed. Cost is unavailable, not zero.");
        return Result(state);

        string Option(string key) => options.TryGetValue(key, out var value) ? value.Trim() : string.Empty;
        GcpAdvancedResult Result(CoverageState resultState, string? warning = null)
        {
            if (warning is not null) warnings.Add(warning);
            var subtotals = totals.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new GcpCurrencySubtotal(pair.Key, pair.Value.Cost, pair.Value.Credits, pair.Value.Cost + pair.Value.Credits, pair.Value.Rows)).ToArray();
            return new(resultState, now, [], null, new(sourceId, "bigquery-tabledata-read-only", subtotals, rowsRead, matchedRows, periodStart, periodEnd, false), warnings.Distinct(StringComparer.Ordinal).ToArray());
        }
    }

    private async Task<string?> Token(string kind, CancellationToken ct)
    {
        try
        {
            var token = await accessToken(kind, ct);
            return string.IsNullOrWhiteSpace(token) || token.Length > 16 * 1024 || token.Any(char.IsControl) ? null : token;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception error) when (IsReadFailure(error)) { return null; }
    }
    private static async Task<string> GetToken(string kind, CancellationToken ct)
    {
        var scope = kind == "billing" ? "https://www.googleapis.com/auth/bigquery.readonly" : "https://www.googleapis.com/auth/cloud-platform";
        var credential = (await GoogleCredential.GetApplicationDefaultAsync(ct)).CreateScoped(scope);
        return await credential.UnderlyingCredential.GetAccessTokenForRequestAsync(null, ct);
    }
    private static bool Match(string value, string pattern) => Regex.IsMatch(value, pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static bool BoundProject(string observed, string name, string id) => observed == name || observed == "projects/" + id ||
        observed == "//cloudresourcemanager.googleapis.com/" + name || observed == "//cloudresourcemanager.googleapis.com/projects/" + id;
    private static void ValidateProject(string project) { if (!Match(project, @"\A[a-z][a-z0-9-]{4,28}[a-z0-9]\z")) throw new ArgumentException("A literal authorized project ID is required."); }
    private static string Text(JsonElement row, string key) => row.ValueKind == JsonValueKind.Object && row.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? string.Empty : string.Empty;
    private static bool ValidPageToken(string value) => value.Length <= 4096 && !value.Any(char.IsControl);
    private static bool IsReadFailure(Exception error) => error is IOException or InvalidDataException or HttpRequestException or JsonException or InvalidOperationException or UnauthorizedAccessException or OperationCanceledException or Google.Apis.Auth.OAuth2.Responses.TokenResponseException;
    private static CoverageState FailureState(Exception error) => error is ReadException classified ? classified.State : CoverageState.Failed;

    private sealed record Field(string Name, string Type, string Mode, IReadOnlyList<Field> Fields);
    private static IReadOnlyList<Field> ParseFields(JsonElement fields)
    {
        if (fields.ValueKind != JsonValueKind.Array || fields.GetArrayLength() > 128) throw new InvalidDataException("Invalid billing schema.");
        var parsed = fields.EnumerateArray().Select(field => new Field(Text(field, "name"), Text(field, "type"), Text(field, "mode"),
            field.TryGetProperty("fields", out var nested) ? ParseFields(nested) : [])).ToArray();
        if (parsed.Any(field => !Match(field.Name, @"\A[A-Za-z_][A-Za-z0-9_]{0,299}\z")) || parsed.Select(field => field.Name).Distinct(StringComparer.Ordinal).Count() != parsed.Length)
            throw new InvalidDataException("Invalid or duplicate billing schema fields.");
        return parsed;
    }
    private static void RequireField(IReadOnlyList<Field> fields, string name, params string[] types)
    {
        if (fields.Count(field => field.Name == name && types.Contains(field.Type, StringComparer.Ordinal)) != 1) throw new InvalidDataException("Unsupported billing export schema.");
    }
    private static JsonElement[] Cells(JsonElement row, int count)
    {
        if (row.ValueKind != JsonValueKind.Object || !row.TryGetProperty("f", out var cells) || cells.ValueKind != JsonValueKind.Array || cells.GetArrayLength() != count)
            throw new InvalidDataException("Unsupported billing row structure.");
        return cells.EnumerateArray().Select(cell => cell.ValueKind == JsonValueKind.Object && cell.TryGetProperty("v", out var value) ? value.Clone() : throw new InvalidDataException("Invalid billing cell.")).ToArray();
    }
    private static JsonElement Cell(JsonElement[] cells, IReadOnlyList<Field> fields, string name)
    {
        for (var index = 0; index < fields.Count; index++) if (fields[index].Name == name) return cells[index];
        return default;
    }
    private static string Scalar(JsonElement value) => value.ValueKind == JsonValueKind.String ? value.GetString() ?? string.Empty : value.ValueKind == JsonValueKind.Number ? value.GetRawText() : string.Empty;
    private static string Scalar(JsonElement record, IReadOnlyList<Field> fields, string name) => Scalar(Cell(Cells(record, fields.Count), fields, name));
    private static bool Money(JsonElement value, out decimal amount) => decimal.TryParse(Scalar(value), NumberStyles.Float, CultureInfo.InvariantCulture, out amount) && amount is >= -1_000_000_000_000m and <= 1_000_000_000_000m;
    private static bool Timestamp(JsonElement value, out DateTimeOffset timestamp)
    {
        var text = Scalar(value);
        if (double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds) && double.IsFinite(seconds) && seconds is >= 0 and <= 253402300799)
        { timestamp = DateTimeOffset.UnixEpoch.AddSeconds(seconds); return true; }
        return DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out timestamp);
    }
    private static bool Credits(JsonElement value, Field field, out decimal total)
    {
        total = 0;
        if (field.Type is not ("RECORD" or "STRUCT") || field.Mode != "REPEATED" || value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > 1000) return false;
        foreach (var row in value.EnumerateArray())
        {
            if (row.ValueKind != JsonValueKind.Object || !row.TryGetProperty("v", out var record) || record.ValueKind != JsonValueKind.Object ||
                !record.TryGetProperty("f", out var cells) || cells.ValueKind != JsonValueKind.Array || cells.GetArrayLength() != field.Fields.Count) return false;
            if (!Money(Cell(Cells(record, field.Fields.Count), field.Fields, "amount"), out var amount)) return false;
            total = checked(total + amount);
        }
        return true;
    }

    private sealed class ReadException(CoverageState state) : IOException { public CoverageState State { get; } = state; }
    private sealed class ReadSession(HttpClient client, string? token)
    {
        public string? Token => token;
        private int totalBytes;
        public async Task<JsonDocument> Get(Uri uri, CancellationToken ct)
        {
            if (uri.Scheme != "https" || uri.Port != 443 || uri.UserInfo.Length != 0 || uri.Host is not ("cloudresourcemanager.googleapis.com" or "securitycenter.googleapis.com" or "bigquery.googleapis.com"))
                throw new InvalidOperationException("Advanced Google Cloud destination is outside the fixed allowlist.");
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode) throw new ReadException(response.StatusCode switch
            { HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => CoverageState.PermissionDenied, HttpStatusCode.TooManyRequests => CoverageState.RateLimited, _ => CoverageState.Failed });
            if (response.Content.Headers.ContentLength > MaxBodyBytes) throw new InvalidDataException("Advanced read response exceeds its byte limit.");
            await using var input = await response.Content.ReadAsStreamAsync(ct);
            using var output = new MemoryStream(); var buffer = new byte[16384]; int count;
            while ((count = await input.ReadAsync(buffer, ct)) > 0)
            {
                totalBytes += count;
                if (output.Length + count > MaxBodyBytes || totalBytes > MaxTotalBytes) throw new InvalidDataException("Advanced read response exceeds its byte limit.");
                await output.WriteAsync(buffer.AsMemory(0, count), ct);
            }
            return JsonDocument.Parse(output.ToArray(), new JsonDocumentOptions { MaxDepth = 32 });
        }
    }
}
