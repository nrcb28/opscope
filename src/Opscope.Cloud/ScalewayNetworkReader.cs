using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Opscope.Cloud;

/// <summary>Explicit regional networks and optional, explicitly zoned gateway/load-balancer metadata.</summary>
public sealed class ScalewayNetworkProvider : ICloudProvider
{
    private const int MaximumPages = 10, PageSize = 100, MaximumResources = 1000;
    private const int MaximumBodyBytes = 4 * 1024 * 1024, MaximumTotalBytes = 8 * 1024 * 1024;
    private static readonly string[] Regions = ["fr-par", "nl-ams", "pl-waw"];
    // Both Public Gateway v2 and Load Balancer v1 publish this closed zone set.
    private static readonly string[] Zones = ["fr-par-1", "fr-par-2", "nl-ams-1", "nl-ams-2", "nl-ams-3", "pl-waw-1", "pl-waw-2", "pl-waw-3"];
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
        var project = Value("project"); var region = Value("region"); var zone = Value("zone");
        var products = zone.Length == 0 ? new[] { "vpcs", "private-networks" } : new[] { "vpcs", "private-networks", "gateways", "load-balancers" };
        var completedChecks = 0;
        var sourceRows = 0;
        if (!string.Equals(operation, "networks", StringComparison.Ordinal))
            return Result("unsupported", false, "This network metadata reader supports the networks operation only. No provider request was sent.");
        if (new[] { "project", "region", "zone" }.Any(key => options.TryGetValue(key, out var raw) && raw.Any(char.IsControl)) ||
            !Uuid(project, out project) || !Regions.Contains(region, StringComparer.Ordinal) ||
            zone.Length != 0 && (!Zones.Contains(zone, StringComparer.Ordinal) || !zone.StartsWith(region + "-", StringComparison.Ordinal)) ||
            new[] { "endpoint", "api-url", "resource", "regions", "zones", "projects" }.Any(key => Value(key).Length != 0))
            return Result("not_configured", false, "Select one explicit Scaleway project UUID and supported region (fr-par, nl-ams or pl-waw). An optional zone must be explicitly supported by both selected zonal APIs and belong to that region. Region is never inferred from a zone; endpoint overrides and resource filters are unsupported.");
        string? token;
        try { token = credential("SCW_SECRET_KEY"); }
        catch (Exception error) when (error is InvalidOperationException or ArgumentException or IOException)
        { token = null; }
        if (string.IsNullOrWhiteSpace(token) || token.Length > 16384 || token.Any(character => character is < '!' or > '~'))
            return Result("not_configured", false, "The regional network read requires an existing SCW_SECRET_KEY in the backend. No login or credential write was attempted.");
        warnings.Add(zone.Length == 0
            ? "No zone was selected. This read covers regional VPC and Private Network metadata only; no gateway or load-balancer request was sent."
            : "The selected zone enables Public Gateway and Load Balancer metadata in that zone only. Regional VPC and Private Network reads retain the explicit region; the zone does not narrow their regional scope.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        var session = new ReadSession(client, token, products.Length * MaximumPages);
        var state = "complete";
        for (var productIndex = 0; productIndex < products.Length; productIndex++)
        {
            var kind = products[productIndex];
            if (sourceRows >= MaximumResources)
            {
                checks.Add(new(kind, "not_requested", now, null));
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
                    using var document = await session.Read(project, region, zone, kind, page, deadline.Token);
                    var root = document.RootElement;
                    var arrayName = kind switch { "vpcs" => "vpcs", "private-networks" => "private_networks", "gateways" => "gateways", _ => "lbs" };
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
                        if (sourceRows >= MaximumResources) { checkState = "partial"; stopProductReads = true; break; }
                        sourceRows++;
                        if (!TryResource(row, kind, project, region, zone, out var resource, out var incomplete) || !keys.Add(resource!.Id))
                        { checkState = "partial"; continue; }
                        resources.Add(resource!); observedResources++;
                        if (incomplete) checkState = "partial";
                    }
                    if (consumedRows >= total) break;
                    if (rows.GetArrayLength() != PageSize || page == MaximumPages || sourceRows >= MaximumResources)
                    { checkState = "partial"; break; }
                }
                if (observedResources != expectedResources) checkState = "partial";
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception error) when (error is IOException or InvalidDataException or HttpRequestException or JsonException or InvalidOperationException or ArgumentException or OperationCanceledException)
            {
                var failureState = error is NetworkReadException classified ? classified.State : error is OperationCanceledException ? "timed_out" : "failed";
                checkState = observedResources > 0 ? "partial" : failureState;
                stopProductReads = failureState is "rate_limited" or "timed_out" || session.Exhausted || deadline.IsCancellationRequested;
                warnings.Add("A selected network product read was unavailable or invalid. Verify existing Scaleway credentials, product read permissions and the configured project, region and optional zone outside Opscope. Provider bodies and credentials are omitted.");
                if (stopProductReads) warnings.Add("Remaining product reads were omitted after a quota, timeout or safety bound. No retry was sent.");
            }
            if (checkState == "complete") completedChecks++;
            checks.Add(new(kind, checkState, now, observedResources == 0 && checkState != "complete" ? null : new(observedResources, expectedResources)));
            if (checkState != "complete") state = "partial";
            if (stopProductReads || deadline.IsCancellationRequested)
            {
                for (var remaining = productIndex + 1; remaining < products.Length; remaining++)
                    checks.Add(new(products[remaining], "not_requested", now, null));
                break;
            }
        }
        if (completedChecks == 0 && resources.Count == 0)
        {
            var failures = checks.Where(check => check.State != "not_requested").Select(check => check.State).Distinct(StringComparer.Ordinal).ToArray();
            state = failures.Length == 1 ? failures[0] : "failed";
        }
        if (state == "partial") warnings.Add("Selected network metadata is incomplete because a page, source-row, scope, field, response-byte or time bound omitted evidence.");
        if (resources.Count == 0) warnings.Add("No selected network resources were observed. Only completed product reads with explicit zero total_count establish an empty result for those selected products; this is not a security or availability verdict.");
        return Result(state, state == "complete");

        string Value(string key) => options.TryGetValue(key, out var value) ? value.Trim() : string.Empty;
        AnalysisReport Result(string coverageState, bool succeeded, string? warning = null)
        {
            if (warning is not null) warnings.Add(warning);
            warnings.Add("Evidence covers selected VPC and Private Network metadata, plus Public Gateway and Load Balancer metadata only when a supported zone is selected. Names, tags, IP addresses, CIDRs, subnet contents, certificates, subscriber details, instance details, route definitions, rules and ACL contents are omitted. Selection describes configured request scope; it does not independently verify an account or IAM grants. States, configuration and counts do not establish reachability, isolation or application health; no resource or service was created or changed.");
            return new("cloud.scaleway.networks", now, [], new
            {
                provider = "scaleway", operation = "networks", resources,
                scope = new { schemaVersion = 1, accounts = project.Length == 0 ? Array.Empty<string>() : new[] { project }, region, zone = zone.Length == 0 ? null : zone },
                coverage = new { state = coverageState, observedAtUtc = now, enumeratedResources = resources.Count, expectedScopes = 1, completedScopes = completedChecks == products.Length ? 1 : 0, warnings = warnings.Distinct(StringComparer.Ordinal).ToArray() },
                configurationEvidence = new { source = zone.Length == 0 ? "scaleway-vpc-v2" : "scaleway-network-fixed-read", selection = new { region, zone = zone.Length == 0 ? null : zone, zonalProductsRequested = zone.Length != 0 }, checks },
                source = zone.Length == 0 ? "scaleway-fixed-read-only-vpc-v2" : "scaleway-fixed-read-only-network-metadata", authentication = "existing-scw-secret-key"
            }, warnings.Distinct(StringComparer.Ordinal).ToArray()) { OperationSucceeded = succeeded };
        }
    }

    private static bool TryResource(JsonElement row, string kind, string project, string region, string zone, out CloudResource? resource, out bool incomplete)
    {
        resource = null; incomplete = false;
        if (row.ValueKind != JsonValueKind.Object || !Uuid(Text(row, "id"), out var id) || !Uuid(Text(row, "project_id"), out var returnedProject) ||
            returnedProject != project) return false;
        var zonal = kind is "gateways" or "load-balancers";
        if (zonal)
        {
            if (zone.Length == 0 || Text(row, "zone") != zone) return false;
            var returnedRegion = Property(row, "region");
            if (returnedRegion.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null) &&
                (returnedRegion.ValueKind != JsonValueKind.String || returnedRegion.GetString() != region)) return false;
        }
        else if (Text(row, "region") != region) return false;
        object properties;
        if (kind == "vpcs")
        {
            var isDefault = Boolean(row, "is_default"); var routing = Boolean(row, "routing_enabled"); var propagation = Boolean(row, "custom_routes_propagation_enabled");
            incomplete = isDefault is null || routing is null || propagation is null;
            properties = new { isDefault, routingEnabled = routing, customRoutesPropagationEnabled = propagation };
        }
        else if (kind == "private-networks")
        {
            var dhcp = Boolean(row, "dhcp_enabled"); var propagation = Boolean(row, "default_route_propagation_enabled");
            var parentValid = Uuid(Text(row, "vpc_id"), out var vpc);
            incomplete = dhcp is null || propagation is null || !parentValid;
            properties = new { dhcpEnabled = dhcp, defaultRoutePropagationEnabled = propagation, vpc = parentValid ? vpc : null };
        }
        else if (kind == "gateways")
        {
            var state = Enum(row, "status", ["unknown_status", "stopped", "allocating", "configuring", "running", "stopping", "failed", "deleting", "locked"], ref incomplete);
            properties = new { zone, state, bastionEnabled = OptionalBoolean(row, "bastion_enabled", ref incomplete),
                smtpEnabled = OptionalBoolean(row, "smtp_enabled", ref incomplete), isLegacy = OptionalBoolean(row, "is_legacy", ref incomplete) };
        }
        else
        {
            var state = Enum(row, "status", ["unknown", "ready", "pending", "stopped", "error", "locked", "migrating", "to_create", "creating", "to_delete", "deleting"], ref incomplete);
            properties = new { zone, state, frontendCount = OptionalCount(row, "frontend_count", ref incomplete), backendCount = OptionalCount(row, "backend_count", ref incomplete),
                privateNetworkCount = OptionalCount(row, "private_network_count", ref incomplete), routeCount = OptionalCount(row, "route_count", ref incomplete) };
        }
        var resourceId = kind switch
        {
            "gateways" => $"vpc-gw/zones/{zone}/gateways/{id}",
            "load-balancers" => $"lb/zones/{zone}/lbs/{id}",
            _ => $"vpc/regions/{region}/{kind}/{id}"
        };
        var type = kind switch { "vpcs" => "network.vpc", "private-networks" => "network.privateNetwork", "gateways" => "network.gateway", _ => "network.load-balancer" };
        resource = new("scaleway", project, region, resourceId, type, "", properties);
        return true;
    }

    private static bool Uuid(string value, out string normalized)
    {
        normalized = "";
        if (!Guid.TryParseExact(value, "D", out var id) || id == Guid.Empty) return false;
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
    private static bool? OptionalBoolean(JsonElement row, string key, ref bool incomplete)
    {
        var value = Property(row, key);
        if (value.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null) return null;
        if (value.ValueKind is JsonValueKind.True or JsonValueKind.False) return value.GetBoolean();
        incomplete = true; return null;
    }
    private static int? OptionalCount(JsonElement row, string key, ref bool incomplete)
    {
        var value = Property(row, key);
        if (value.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null) return null;
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var count) && count >= 0) return count;
        incomplete = true; return null;
    }
    private static string? Enum(JsonElement row, string key, string[] allowed, ref bool incomplete)
    {
        var value = Property(row, key);
        if (value.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null) return null;
        if (value.ValueKind == JsonValueKind.String && allowed.Contains(value.GetString(), StringComparer.Ordinal)) return value.GetString();
        incomplete = true; return null;
    }

    private sealed class ReadSession(HttpClient client, string token, int maximumRequests)
    {
        private int requests;
        private int bytesRead;
        public bool Exhausted { get; private set; }
        public async Task<JsonDocument> Read(string project, string region, string zone, string kind, int page, CancellationToken cancellationToken)
        {
            if (++requests > maximumRequests) { Exhausted = true; throw new NetworkReadException("partial"); }
            var path = kind switch
            {
                "gateways" => $"/vpc-gw/v2/zones/{zone}/gateways",
                "load-balancers" => $"/lb/v1/zones/{zone}/lbs",
                _ => $"/vpc/v2/regions/{region}/{kind}"
            };
            var uri = new Uri($"https://api.scaleway.com{path}?project_id={project}&page={page.ToString(CultureInfo.InvariantCulture)}&page_size={PageSize.ToString(CultureInfo.InvariantCulture)}" + (kind == "gateways" ? "&include_legacy=true" : ""));
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Add("X-Auth-Token", token);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.StatusCode != HttpStatusCode.OK) throw new NetworkReadException(response.StatusCode switch
            {
                HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => "permission_denied",
                HttpStatusCode.TooManyRequests => "rate_limited",
                _ => "failed"
            });
            if (response.Content.Headers.ContentLength is > MaximumBodyBytes || response.Content.Headers.ContentLength > MaximumTotalBytes - bytesRead)
            { Exhausted = true; throw new NetworkReadException("partial"); }
            await using var source = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var buffer = new MemoryStream();
            var chunk = new byte[8192];
            int count;
            while ((count = await source.ReadAsync(chunk, cancellationToken)) > 0)
            {
                if (buffer.Length + count > MaximumBodyBytes || bytesRead + count > MaximumTotalBytes) { Exhausted = true; throw new NetworkReadException("partial"); }
                bytesRead += count; await buffer.WriteAsync(chunk.AsMemory(0, count), cancellationToken);
            }
            var document = JsonDocument.Parse(buffer.ToArray(), new JsonDocumentOptions { MaxDepth = 32 });
            try { UniqueProperties(document.RootElement); return document; }
            catch { document.Dispose(); throw; }
        }
    }
    private static void UniqueProperties(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var keys = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!keys.Add(property.Name)) throw new JsonException("Ambiguous provider object.");
                UniqueProperties(property.Value);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var item in value.EnumerateArray()) UniqueProperties(item);
    }
    private sealed class NetworkReadException(string state) : IOException("A fixed network metadata read was unavailable.")
    { public string State { get; } = state; }
    private sealed record NetworkCheck(string Check, string State, DateTimeOffset ObservedAtUtc, NetworkObservations? Observations);
    private sealed record NetworkObservations(int ObservedResources, int? ExpectedResources);
}
