using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Opscope.Cloud;

/// <summary>Explicit regional VPC and Private Network metadata. No network configuration is changed.</summary>
public sealed class ScalewayNetworkProvider : ICloudProvider
{
    private const int MaximumPages = 10, PageSize = 100, MaximumResources = 1000;
    private const int MaximumBodyBytes = 4 * 1024 * 1024, MaximumTotalBytes = 8 * 1024 * 1024;
    private static readonly string[] Regions = ["fr-par", "nl-ams", "pl-waw"];
    private static readonly HttpClient DefaultClient = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(10)
    }) { Timeout = TimeSpan.FromSeconds(30) };
    private readonly HttpClient client;
    private readonly Func<string, string?> credential;

    public ScalewayNetworkProvider() : this(DefaultClient, Environment.GetEnvironmentVariable) { }
    internal ScalewayNetworkProvider(HttpClient client, Func<string, string?> credential)
    { this.client = client; this.credential = credential; }
    public string Name => "scaleway";

    public async Task<AnalysisReport> CollectAsync(string operation, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        var now = DateTimeOffset.UtcNow;
        var resources = new List<CloudResource>();
        var keys = new HashSet<string>(StringComparer.Ordinal);
        var warnings = new List<string>();
        var checks = new List<NetworkCheck>();
        var project = Value("project"); var region = Value("region");
        var completedChecks = 0;
        if (!string.Equals(operation, "networks", StringComparison.Ordinal))
            return Result("unsupported", false, "This regional reader supports the networks operation only. No provider request was sent.");
        if (!Uuid(project, out project) || !Regions.Contains(region, StringComparer.Ordinal) ||
            new[] { "endpoint", "api-url", "resource", "regions" }.Any(key => Value(key).Length != 0))
            return Result("not_configured", false, "Select one explicit Scaleway project UUID and supported region (fr-par, nl-ams or pl-waw). Region is never inferred from a zone; endpoint overrides and resource filters are unsupported.");
        string? token;
        try { token = credential("SCW_SECRET_KEY"); }
        catch (Exception error) when (error is InvalidOperationException or ArgumentException or IOException)
        { token = null; }
        if (string.IsNullOrWhiteSpace(token) || token.Length > 16384 || token.Any(character => character is < '!' or > '~'))
            return Result("not_configured", false, "The regional network read requires an existing SCW_SECRET_KEY in the backend. No login or credential write was attempted.");
        if (Value("zone").Length != 0)
            warnings.Add("The explicit region controls VPC reads. A zone option does not narrow these regional resources.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        var session = new ReadSession(client, token);
        var state = "complete";
        foreach (var kind in new[] { "vpcs", "private-networks" })
        {
            if (resources.Count >= MaximumResources)
            {
                checks.Add(new(kind, "partial", now, null));
                state = "partial";
                continue;
            }
            var checkState = "complete";
            var stopProductReads = false;
            var observedResources = 0;
            int? expectedResources = null;
            var consumedRows = 0;
            try
            {
                for (var page = 1; page <= MaximumPages; page++)
                {
                    deadline.Token.ThrowIfCancellationRequested();
                    using var document = await session.Read(project, region, kind, page, deadline.Token);
                    var root = document.RootElement;
                    var arrayName = kind == "vpcs" ? "vpcs" : "private_networks";
                    var rows = Property(root, arrayName);
                    var count = Property(root, "total_count");
                    if (root.ValueKind != JsonValueKind.Object || rows.ValueKind != JsonValueKind.Array || count.ValueKind != JsonValueKind.Number ||
                        !count.TryGetInt32(out var total) || total < 0 || rows.GetArrayLength() > PageSize)
                        throw new JsonException("Invalid regional network envelope.");
                    if (expectedResources is not null && expectedResources.Value != total)
                    { checkState = "partial"; break; }
                    expectedResources = total;
                    consumedRows += rows.GetArrayLength();
                    if (consumedRows > total) checkState = "partial";
                    foreach (var row in rows.EnumerateArray())
                    {
                        if (resources.Count >= MaximumResources) { checkState = "partial"; break; }
                        if (!TryResource(row, kind, project, region, out var resource, out var incomplete) || !keys.Add(resource!.Id))
                        { checkState = "partial"; continue; }
                        resources.Add(resource!); observedResources++;
                        if (incomplete) checkState = "partial";
                    }
                    if (consumedRows >= total) break;
                    if (rows.GetArrayLength() != PageSize || page == MaximumPages || resources.Count >= MaximumResources)
                    { checkState = "partial"; break; }
                }
                if (observedResources != expectedResources) checkState = "partial";
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception error) when (error is IOException or InvalidDataException or HttpRequestException or JsonException or InvalidOperationException or ArgumentException or OperationCanceledException)
            {
                var failureState = error is NetworkReadException classified ? classified.State : error is OperationCanceledException ? "timed_out" : "failed";
                checkState = observedResources > 0 ? "partial" : failureState;
                stopProductReads = failureState is "rate_limited" or "timed_out" || deadline.IsCancellationRequested;
                warnings.Add("A selected regional network read was unavailable or invalid. Verify existing Scaleway credentials, VPC read permissions and the configured project/region outside Opscope. Provider bodies and credentials are omitted.");
                if (stopProductReads) warnings.Add("Remaining product reads were omitted after a quota or timeout rejection. No retry was sent.");
            }
            if (checkState == "complete") completedChecks++;
            checks.Add(new(kind, checkState, now, observedResources == 0 && checkState != "complete" ? null : new(observedResources, expectedResources)));
            if (checkState != "complete") state = "partial";
            if (stopProductReads || deadline.IsCancellationRequested)
            {
                // No retries, no second product reads after the provider's quota/deadline rejection.
                if (kind == "vpcs") checks.Add(new("private-networks", "not_requested", now, null));
                break;
            }
        }
        if (completedChecks == 0 && resources.Count == 0)
        {
            var failures = checks.Where(check => check.State != "not_requested").Select(check => check.State).Distinct(StringComparer.Ordinal).ToArray();
            state = failures.Length == 1 ? failures[0] : "failed";
        }
        if (state == "partial") warnings.Add("Regional network metadata is incomplete because a page, resource, scope, field, response-byte or time bound omitted evidence.");
        if (resources.Count == 0) warnings.Add("No regional network resources were observed. Only completed product reads with explicit zero total_count establish an empty result for those selected products; this is not a security or availability verdict.");
        return Result(state, state == "complete");

        string Value(string key) => options.TryGetValue(key, out var value) ? value.Trim() : string.Empty;
        AnalysisReport Result(string coverageState, bool succeeded, string? warning = null)
        {
            if (warning is not null) warnings.Add(warning);
            warnings.Add("Regional evidence covers existing VPC and Private Network metadata only. No subnet contents, CIDRs, IP addresses, tags, route definitions, gateways, load balancers or security ACLs are read into the report. Configured routing/DHCP booleans do not establish reachability, isolation or application health; no resource or service was created or changed.");
            return new("cloud.scaleway.networks", now, [], new
            {
                provider = "scaleway", operation = "networks", resources,
                scope = new { schemaVersion = 1, accounts = project.Length == 0 ? Array.Empty<string>() : new[] { project }, region },
                coverage = new { state = coverageState, observedAtUtc = now, enumeratedResources = resources.Count, expectedScopes = 1, completedScopes = completedChecks == 2 ? 1 : 0, warnings = warnings.Distinct(StringComparer.Ordinal).ToArray() },
                configurationEvidence = new { source = "scaleway-vpc-v2", checks },
                source = "scaleway-fixed-read-only-vpc-v2", authentication = "existing-scw-secret-key"
            }, warnings.Distinct(StringComparer.Ordinal).ToArray()) { OperationSucceeded = succeeded };
        }
    }

    private static bool TryResource(JsonElement row, string kind, string project, string region, out CloudResource? resource, out bool incomplete)
    {
        resource = null; incomplete = false;
        if (row.ValueKind != JsonValueKind.Object || !Uuid(Text(row, "id"), out var id) || !Uuid(Text(row, "project_id"), out var returnedProject) ||
            returnedProject != project || Text(row, "region") != region) return false;
        object properties;
        if (kind == "vpcs")
        {
            var isDefault = Boolean(row, "is_default"); var routing = Boolean(row, "routing_enabled"); var propagation = Boolean(row, "custom_routes_propagation_enabled");
            incomplete = isDefault is null || routing is null || propagation is null;
            properties = new { isDefault, routingEnabled = routing, customRoutesPropagationEnabled = propagation };
        }
        else
        {
            var dhcp = Boolean(row, "dhcp_enabled"); var propagation = Boolean(row, "default_route_propagation_enabled");
            var parentValid = Uuid(Text(row, "vpc_id"), out var vpc);
            incomplete = dhcp is null || propagation is null || !parentValid;
            properties = new { dhcpEnabled = dhcp, defaultRoutePropagationEnabled = propagation, vpc = parentValid ? vpc : null };
        }
        resource = new("scaleway", project, region, $"vpc/regions/{region}/{kind}/{id}", kind == "vpcs" ? "network.vpc" : "network.privateNetwork", "", properties);
        return true;
    }

    private static bool Uuid(string value, out string normalized)
    {
        normalized = "";
        if (!Guid.TryParseExact(value, "D", out var id)) return false;
        normalized = id.ToString("D", CultureInfo.InvariantCulture); return true;
    }
    private static JsonElement Property(JsonElement value, string key)
    {
        if (value.ValueKind != JsonValueKind.Object) return default;
        var found = default(JsonElement); var count = 0;
        foreach (var property in value.EnumerateObject())
            if (property.Name == key) { found = property.Value; count++; }
        return count == 1 ? found : default;
    }
    private static string Text(JsonElement value, string key) => Property(value, key) is { ValueKind: JsonValueKind.String } text ? text.GetString() ?? "" : "";
    private static bool? Boolean(JsonElement value, string key) => Property(value, key).ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => null };

    private sealed class ReadSession(HttpClient client, string token)
    {
        private int requests;
        private int bytesRead;
        public async Task<JsonDocument> Read(string project, string region, string kind, int page, CancellationToken cancellationToken)
        {
            if (++requests > MaximumPages * 2) throw new NetworkReadException("partial");
            var uri = new Uri($"https://api.scaleway.com/vpc/v2/regions/{region}/{kind}?project_id={project}&page={page.ToString(CultureInfo.InvariantCulture)}&page_size={PageSize.ToString(CultureInfo.InvariantCulture)}");
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Add("X-Auth-Token", token);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode) throw new NetworkReadException(response.StatusCode switch
            {
                HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => "permission_denied",
                HttpStatusCode.TooManyRequests => "rate_limited",
                _ => "failed"
            });
            if (response.Content.Headers.ContentLength is > MaximumBodyBytes || response.Content.Headers.ContentLength > MaximumTotalBytes - bytesRead)
                throw new NetworkReadException("partial");
            await using var source = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var buffer = new MemoryStream();
            var chunk = new byte[8192];
            int count;
            while ((count = await source.ReadAsync(chunk, cancellationToken)) > 0)
            {
                if (buffer.Length + count > MaximumBodyBytes || bytesRead + count > MaximumTotalBytes) throw new NetworkReadException("partial");
                bytesRead += count; await buffer.WriteAsync(chunk.AsMemory(0, count), cancellationToken);
            }
            return JsonDocument.Parse(buffer.ToArray(), new JsonDocumentOptions { MaxDepth = 32 });
        }
    }
    private sealed class NetworkReadException(string state) : IOException("A fixed regional network read was unavailable.")
    { public string State { get; } = state; }
    private sealed record NetworkCheck(string Check, string State, DateTimeOffset ObservedAtUtc, NetworkObservations? Observations);
    private sealed record NetworkObservations(int ObservedResources, int? ExpectedResources);
}
