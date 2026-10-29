using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Opscope.Cloud;

/// <summary>Fixed regional IBM VPC metadata, with an authoritative resource-group/account scope check.</summary>
public sealed class IbmVpcProvider : ICloudProvider
{
    private const int MaximumPages = 10, PageSize = 100, MaximumResources = 1000, MaximumRequests = 31;
    private const int MaximumBodyBytes = 4 * 1024 * 1024, MaximumTotalBytes = 8 * 1024 * 1024;
    // IBM's official VPC SDK documents this version date with generation 2.
    private const string ApiVersion = "2026-10-06";
    private static readonly string[] Regions = ["us-south", "us-east", "eu-gb", "eu-de", "jp-tok", "jp-osa", "au-syd", "ca-tor", "br-sao", "eu-es"];
    private static readonly string[] Products = ["vpcs", "subnets", "security_groups"];
    private static readonly HttpClient DefaultClient = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(10)
    }) { Timeout = TimeSpan.FromSeconds(30) };
    private readonly HttpClient client;
    private readonly Func<string, string?> credential;

    public IbmVpcProvider() : this(DefaultClient, Environment.GetEnvironmentVariable) { }
    internal IbmVpcProvider(HttpClient client, Func<string, string?> credential)
    { this.client = client; this.credential = credential; }
    public string Name => "ibm";

    public async Task<AnalysisReport> CollectAsync(string operation, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        var now = DateTimeOffset.UtcNow;
        var account = Value("account"); var group = Value("resource-group"); var region = Value("region");
        var resources = new List<CloudResource>();
        var keys = new HashSet<string>(StringComparer.Ordinal);
        var warnings = new List<string>();
        var checks = new List<NetworkCheck>();
        var scopeState = "not_requested";
        if (operation != "networks")
            return Result("unsupported", false, "This reader supports the networks operation only. No provider request was sent.");
        if (!ScopeId(account) || !ScopeId(group) || !Regions.Contains(region, StringComparer.Ordinal) ||
            new[] { "endpoint", "api-url", "resource", "regions", "vpc", "vpcs" }.Any(key => Value(key).Length != 0))
            return Result("not_configured", false, "Select one explicit IBM account ID, resource-group ID and supported region. Account and group IDs must be 32 lowercase hexadecimal characters. Endpoint overrides and resource selectors are unsupported.");
        string? token;
        try { token = credential("IBM_CLOUD_IAM_TOKEN"); }
        catch (Exception error) when (error is InvalidOperationException or ArgumentException or IOException) { token = null; }
        if (string.IsNullOrWhiteSpace(token) || token.Length > 16384 || token.Any(character => character is < '!' or > '~'))
            return Result("not_configured", false, "An existing IBM_CLOUD_IAM_TOKEN is required in the backend. IAM tokens are acquired and refreshed outside Opscope.");
        if (Value("zone").Length != 0)
            warnings.Add("The explicit region controls VPC reads. A zone option does not narrow these regional resources.");

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        var session = new ReadSession(client, token);
        try
        {
            // A successful empty product list alone cannot bind the configured group to its account.
            using var document = await session.Read(new Uri($"https://resource-controller.cloud.ibm.com/v2/resource_groups/{group}"), deadline.Token);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || Text(root, "id") != group || Text(root, "account_id") != account)
                throw new NetworkReadException("permission_denied");
            scopeState = "verified";
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error) when (ReadFailure(error))
        {
            scopeState = FailureState(error);
            foreach (var kind in Products) checks.Add(new(CheckName(kind), "not_requested", now, null));
            return Result(scopeState, false, "The IBM resource group could not be verified in the selected account. Grant Viewer on that resource group and verify the existing IAM token outside Opscope. No VPC product read was sent.");
        }

        var state = "complete";
        var completed = 0;
        for (var product = 0; product < Products.Length; product++)
        {
            var kind = Products[product];
            if (resources.Count >= MaximumResources)
            {
                checks.Add(new(CheckName(kind), "not_requested", now, null));
                state = "partial"; continue;
            }
            var checkState = "complete";
            var observed = 0; var consumed = 0;
            int? expected = null;
            var stop = false;
            var cursor = "";
            var cursors = new HashSet<string>(StringComparer.Ordinal);
            try
            {
                for (var page = 1; page <= MaximumPages; page++)
                {
                    using var document = await session.Read(ProductUri(region, group, kind, cursor), deadline.Token);
                    var root = document.RootElement;
                    var rows = Property(root, kind);
                    var count = Property(root, "total_count");
                    if (root.ValueKind != JsonValueKind.Object || rows.ValueKind != JsonValueKind.Array || rows.GetArrayLength() > PageSize ||
                        count.ValueKind != JsonValueKind.Number || !count.TryGetInt32(out var total) || total < 0)
                        throw new JsonException("Invalid IBM network collection.");
                    if (expected is not null && expected.Value != total) { checkState = "partial"; break; }
                    expected = total;
                    consumed += rows.GetArrayLength();
                    if (consumed > total) checkState = "partial";
                    foreach (var row in rows.EnumerateArray())
                    {
                        if (resources.Count >= MaximumResources) { checkState = "partial"; break; }
                        if (!TryResource(row, kind, account, group, region, out var resource, out var incomplete) || !keys.Add(resource!.Id))
                        { checkState = "partial"; continue; }
                        resources.Add(resource!); observed++;
                        if (incomplete) checkState = "partial";
                    }
                    var next = Property(root, "next");
                    if (next.ValueKind == JsonValueKind.Undefined)
                    {
                        if (consumed != total) checkState = "partial";
                        break;
                    }
                    if (!TryCursor(next, region, group, kind, out cursor) || !cursors.Add(cursor))
                    { checkState = "partial"; break; }
                    if (rows.GetArrayLength() == 0 || consumed >= total || page == MaximumPages || resources.Count >= MaximumResources)
                    { checkState = "partial"; break; }
                }
                if (observed != expected) checkState = "partial";
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception error) when (ReadFailure(error))
            {
                var failure = FailureState(error);
                checkState = observed > 0 ? "partial" : failure;
                stop = failure is "rate_limited" or "timed_out" or "partial" || deadline.IsCancellationRequested;
                warnings.Add("A selected IBM VPC product read was unavailable or invalid. Verify the existing IAM token, VPC read permissions and configured scope outside Opscope. Provider bodies and credentials are omitted.");
            }
            if (checkState == "complete") completed++;
            else state = "partial";
            checks.Add(new(CheckName(kind), checkState, now,
                observed == 0 && checkState != "complete" ? null : new(observed, expected)));
            if (stop || deadline.IsCancellationRequested || resources.Count >= MaximumResources)
            {
                for (var remaining = product + 1; remaining < Products.Length; remaining++)
                    checks.Add(new(CheckName(Products[remaining]), "not_requested", now, null));
                if (product + 1 < Products.Length) state = "partial";
                warnings.Add("Remaining product reads were omitted after a quota, timeout or safety budget was reached. No retry was sent.");
                break;
            }
        }
        if (completed == 0 && resources.Count == 0)
        {
            var failures = checks.Where(check => check.State != "not_requested").Select(check => check.State).Distinct(StringComparer.Ordinal).ToArray();
            state = failures.Length == 1 ? failures[0] : "failed";
        }
        if (state == "partial") warnings.Add("IBM VPC metadata is incomplete because a page, resource, scope, field, response-byte or time bound omitted evidence.");
        if (resources.Count == 0) warnings.Add("No selected network resources were observed. Only verified scope and completed product reads with explicit zero totals establish an empty result; this is not a security or availability verdict.");
        return Result(state, state == "complete");

        string Value(string key) => options.TryGetValue(key, out var value) ? value.Trim() : "";
        AnalysisReport Result(string coverageState, bool succeeded, string? warning = null)
        {
            if (warning is not null) warnings.Add(warning);
            warnings.Add("Evidence covers existing VPC, subnet and security-group metadata only. Names, tags, CRNs, CIDRs, IP addresses, rule contents, targets, routes and gateway configuration are omitted. Counts and lifecycle configuration do not establish effective access, isolation, reachability or application health. No resource or service was created or changed.");
            var reportWarnings = warnings.Distinct(StringComparer.Ordinal).ToArray();
            return new("cloud.ibm.networks", now, [], new
            {
                provider = "ibm", operation = "networks", resources,
                scope = new { schemaVersion = 1, accounts = account.Length == 0 ? Array.Empty<string>() : new[] { account }, resourceGroup = group, region },
                coverage = new { state = coverageState, observedAtUtc = now, enumeratedResources = resources.Count, expectedScopes = 1,
                    completedScopes = checks.Count == 3 && checks.All(check => check.State == "complete") && scopeState == "verified" ? 1 : 0, warnings = reportWarnings },
                configurationEvidence = new { source = "ibm-vpc-fixed-read", scopeVerification = new { source = "ibm-resource-manager-v2", state = scopeState }, checks },
                source = "ibm-fixed-read-only-vpc-v1", authentication = "existing-iam-bearer"
            }, reportWarnings) { OperationSucceeded = succeeded };
        }
    }

    private static bool TryResource(JsonElement row, string kind, string account, string group, string region, out CloudResource? resource, out bool incomplete)
    {
        resource = null; incomplete = false;
        var id = Text(row, "id");
        var location = region;
        var crnKind = kind switch { "vpcs" => "vpc", "subnets" => "subnet", _ => "security-group" };
        if (kind == "subnets")
        {
            location = Text(Property(row, "zone"), "name");
            if (!new[] { region + "-1", region + "-2", region + "-3" }.Contains(location, StringComparer.Ordinal)) return false;
        }
        if (row.ValueKind != JsonValueKind.Object || !ResourceId(id) || Text(Property(row, "resource_group"), "id") != group ||
            !Crn(Text(row, "crn"), account, location, crnKind, id)) return false;
        string? vpc = null;
        if (kind != "vpcs")
        {
            var parent = Property(row, "vpc"); vpc = Text(parent, "id");
            if (!ResourceId(vpc) || !Crn(Text(parent, "crn"), account, region, "vpc", vpc)) return false;
        }
        object properties;
        if (kind == "vpcs")
        {
            var status = EnumValue(row, "status", ["available", "deleting", "failed", "pending"], ref incomplete);
            var classic = Property(row, "classic_access");
            bool? classicAccess = classic.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => null };
            if (classic.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null or JsonValueKind.True or JsonValueKind.False)) incomplete = true;
            properties = new { status, classicAccess };
        }
        else if (kind == "subnets")
            properties = new { status = EnumValue(row, "status", ["available", "deleting", "failed", "pending"], ref incomplete),
                ipVersion = EnumValue(row, "ip_version", ["ipv4"], ref incomplete), vpc };
        else
        {
            var rules = ArrayCount(row, "rules", ref incomplete); var targets = ArrayCount(row, "targets", ref incomplete);
            properties = new { ruleCount = rules, targetCount = targets, vpc };
        }
        resource = new("ibm", account, region, $"vpc/regions/{region}/{kind}/{id}",
            kind switch { "vpcs" => "network.vpc", "subnets" => "network.subnet", _ => "network.securityGroup" }, "", properties);
        return true;
    }

    private static string? EnumValue(JsonElement row, string key, string[] supported, ref bool incomplete)
    {
        var value = Property(row, key);
        if (value.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null) return null;
        if (value.ValueKind == JsonValueKind.String && supported.Contains(value.GetString(), StringComparer.Ordinal)) return value.GetString();
        incomplete = true; return null;
    }
    private static int? ArrayCount(JsonElement row, string key, ref bool incomplete)
    {
        var value = Property(row, key);
        if (value.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null) return null;
        if (value.ValueKind == JsonValueKind.Array) return value.GetArrayLength();
        incomplete = true; return null;
    }
    private static bool ScopeId(string value) => Regex.IsMatch(value, "\\A[0-9a-f]{32}\\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static bool ResourceId(string value) => Regex.IsMatch(value, "\\A(?:[a-z0-9]{4}-)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static bool Crn(string value, string account, string location, string kind, string id) =>
        value == $"crn:v1:bluemix:public:is:{location}:a/{account}::{kind}:{id}";
    private static string CheckName(string kind) => kind == "security_groups" ? "security-groups" : kind;
    private static Uri ProductUri(string region, string group, string kind, string cursor) => new(
        $"https://{region}.iaas.cloud.ibm.com/v1/{kind}?version={ApiVersion}&generation=2&resource_group.id={group}&limit={PageSize.ToString(CultureInfo.InvariantCulture)}" +
        (cursor.Length == 0 ? "" : "&start=" + Uri.EscapeDataString(cursor)));
    private static bool TryCursor(JsonElement next, string region, string group, string kind, out string cursor)
    {
        cursor = "";
        if (next.ValueKind != JsonValueKind.Object || !Uri.TryCreate(Text(next, "href"), UriKind.Absolute, out var link) ||
            link.Scheme != "https" || link.Host != region + ".iaas.cloud.ibm.com" || link.AbsolutePath != "/v1/" + kind ||
            !link.IsDefaultPort || link.UserInfo.Length != 0 || link.Fragment.Length != 0) return false;
        var query = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in link.Query.TrimStart('?').Split('&'))
        {
            var parts = pair.Split('=', 2);
            if (parts.Length != 2 || !query.TryAdd(Uri.UnescapeDataString(parts[0]), Uri.UnescapeDataString(parts[1]))) return false;
        }
        if (query.Count != 5 || !query.TryGetValue("version", out var version) || version != ApiVersion ||
            !query.TryGetValue("generation", out var generation) || generation != "2" ||
            !query.TryGetValue("resource_group.id", out var returnedGroup) || returnedGroup != group ||
            !query.TryGetValue("limit", out var limit) || limit != PageSize.ToString(CultureInfo.InvariantCulture) ||
            !query.TryGetValue("start", out cursor!) || cursor.Length is 0 or > 1024 || cursor.Any(character => character is < '!' or > '~')) return false;
        return true;
    }
    private static JsonElement Property(JsonElement value, string key)
    {
        if (value.ValueKind != JsonValueKind.Object) return default;
        var result = default(JsonElement); var found = 0;
        foreach (var item in value.EnumerateObject()) if (item.Name == key) { result = item.Value; found++; }
        // Duplicate selected keys are invalid, including optional projections.
        if (found > 1) throw new JsonException("Duplicate selected IBM metadata property.");
        return result;
    }
    private static string Text(JsonElement value, string key) => Property(value, key) is { ValueKind: JsonValueKind.String } text ? text.GetString() ?? "" : "";
    private static bool ReadFailure(Exception error) => error is IOException or HttpRequestException or JsonException or InvalidOperationException or ArgumentException or OperationCanceledException;
    private static string FailureState(Exception error) => error is NetworkReadException classified ? classified.State : error is OperationCanceledException ? "timed_out" : "failed";

    private sealed class ReadSession(HttpClient client, string token)
    {
        private int requests, bytesRead;
        public async Task<JsonDocument> Read(Uri uri, CancellationToken cancellationToken)
        {
            if (++requests > MaximumRequests) throw new NetworkReadException("partial");
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.StatusCode != HttpStatusCode.OK) throw new NetworkReadException(response.StatusCode switch
            {
                HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => "permission_denied",
                HttpStatusCode.TooManyRequests => "rate_limited", _ => "failed"
            });
            if (response.Content.Headers.ContentLength is > MaximumBodyBytes || response.Content.Headers.ContentLength > MaximumTotalBytes - bytesRead)
                throw new NetworkReadException("partial");
            await using var source = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var buffer = new MemoryStream();
            var chunk = new byte[8192]; int count;
            while ((count = await source.ReadAsync(chunk, cancellationToken)) > 0)
            {
                if (buffer.Length + count > MaximumBodyBytes || bytesRead + count > MaximumTotalBytes) throw new NetworkReadException("partial");
                bytesRead += count; await buffer.WriteAsync(chunk.AsMemory(0, count), cancellationToken);
            }
            return JsonDocument.Parse(buffer.ToArray(), new JsonDocumentOptions { MaxDepth = 32 });
        }
    }
    private sealed class NetworkReadException(string state) : IOException("A fixed IBM metadata read was unavailable.")
    { public string State { get; } = state; }
    private sealed record NetworkCheck(string Check, string State, DateTimeOffset ObservedAtUtc, NetworkObservations? Observations);
    private sealed record NetworkObservations(int ObservedResources, int? ExpectedResources);
}
