using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Opscope.Cloud;

/// <summary>Visible project resources and their referenced VPCs; never account/team discovery.</summary>
public sealed class DigitalOceanProjectProvider : ICloudProvider
{
    private static readonly HttpClient DefaultClient = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(10)
    }) { Timeout = TimeSpan.FromSeconds(60) };
    private readonly HttpClient client;
    private readonly Func<string, string?> credential;

    public DigitalOceanProjectProvider() : this(DefaultClient, Environment.GetEnvironmentVariable) { }
    internal DigitalOceanProjectProvider(HttpClient client, Func<string, string?> credential)
    { this.client = client; this.credential = credential; }
    public string Name => "digitalocean";

    public async Task<AnalysisReport> CollectAsync(string operation, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        var collection = new Collection(operation, options, client);
        if (operation is not ("inventory" or "posture"))
            return collection.Result("unsupported", "This project reader supports inventory and posture only. No provider request was sent.");
        if (!Uuid(collection.Project) || new[] { "endpoint", "api-url", "projects", "project-id", "resource", "region", "regions", "zone", "vpc", "vpcs" }.Any(collection.HasOption))
            return collection.Result("not_configured", "Select one explicit canonical project UUID. Endpoint overrides, resource selectors and region/zone filters are unsupported. No provider request was sent.");
        string? token;
        try { token = credential("DIGITALOCEAN_ACCESS_TOKEN"); }
        catch (Exception error) when (error is InvalidOperationException or ArgumentException or IOException) { token = null; }
        if (string.IsNullOrWhiteSpace(token) || token.Length > 16384 || token.Any(character => character is < '!' or > '~'))
            return collection.Result("not_configured", "An existing DIGITALOCEAN_ACCESS_TOKEN is required in the backend; acquire and renew it outside Opscope.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(60));
        return await collection.Run(token, cancellationToken, deadline.Token);
    }

    private sealed class Collection(string operation, IReadOnlyDictionary<string, string> options, HttpClient client)
    {
        private readonly DateTimeOffset now = DateTimeOffset.UtcNow;
        private readonly List<CloudResource> resources = [];
        private readonly List<Finding> findings = [];
        private readonly List<string> warnings = [];
        private readonly List<SourceCheck> checks = [];
        private readonly HashSet<string> resourceIds = new(StringComparer.Ordinal);
        private readonly Dictionary<string, Droplet> droplets = new(StringComparer.Ordinal);
        private readonly Dictionary<string, VpcReference> references = new(StringComparer.Ordinal);
        private string scopeState = "not_requested";
        private bool stop;
        private bool incompleteVpcReferences;
        private bool membershipComplete;
        private int sourceRows;
        private Session session = null!;
        public string Project => Option("project");
        public bool HasOption(string key) => Option(key).Length != 0;
        private string Option(string key) => options.TryGetValue(key, out var value) ? value.Trim() : "";

        public async Task<AnalysisReport> Run(string token, CancellationToken caller, CancellationToken deadline)
        {
            session = new(client, token);
            try
            {
                using var document = await session.Read("/v2/projects/" + Project, deadline);
                if (Text(Property(document.RootElement, "project"), "id") != Project)
                    throw new ReadException("permission_denied");
                scopeState = "verified";
            }
            catch (OperationCanceledException) when (caller.IsCancellationRequested) { throw; }
            catch (Exception error) when (ReadFailure(error))
            {
                scopeState = Failure(error); AddUnrequested();
                return Result(scopeState, "The selected DigitalOcean project could not be verified. No project-resource or product read was sent; verify the existing token and project access outside Opscope.");
            }

            var membership = await Pages("/v2/projects/" + Project + "/resources", "resources", "project-resources", caller, deadline);
            var members = new Dictionary<string, Member>(StringComparer.Ordinal);
            var validRows = 0;
            foreach (var row in membership.Rows)
            {
                var urn = Text(row, "urn");
                if (!Regex.IsMatch(urn, "\\Ado:[a-z][a-z0-9-]{0,31}:[^\\s\\x00-\\x1f]{1,200}\\z", RegexOptions.CultureInvariant) || Text(row, "status") != "ok")
                { membership.Incomplete(); continue; }
                validRows++;
                var pieces = urn.Split(':', 3);
                if (pieces[1] is not ("droplet" or "volume" or "loadbalancer")) continue;
                var id = pieces[2];
                if (!(pieces[1] == "droplet" ? NumericId(id) : Uuid(id))) { membership.Incomplete(); continue; }
                var path = ResourcePath(pieces[1], id);
                var self = Property(Property(row, "links"), "self");
                if (self.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null) &&
                    (self.ValueKind != JsonValueKind.String || self.GetString() != "https://api.digitalocean.com" + path))
                { membership.Incomplete(); continue; }
                if (!members.TryAdd(urn, new(pieces[1], id, path))) membership.Incomplete();
            }
            membership.Observed = validRows;
            membershipComplete = membership.State == "complete";
            checks.Add(membership.Check(now));
            if (membership.Rows.Count == 0 && membership.State != "complete")
            {
                AddUnrequested();
                return Result(membership.State, "Project membership is unavailable. Product reads cannot establish project scope and were omitted.");
            }

            await Product("droplet", "droplets", members.Values, caller, deadline);
            if (operation == "inventory")
            {
                await Product("volume", "volumes", members.Values, caller, deadline);
                await Product("loadbalancer", "load-balancers", members.Values, caller, deadline);
                await Vpcs(caller, deadline);
            }
            else await Firewalls(caller, deadline);
            AddUnrequested();
            var failures = checks.Where(check => check.State is not ("complete" or "not_requested")).Select(check => check.State).Distinct(StringComparer.Ordinal).ToArray();
            var overall = checks.All(check => check.State == "complete") ? "complete" : resources.Count > 0 || failures.Length != 1 ? "partial" : failures[0];
            return Result(overall);
        }

        private async Task Product(string kind, string checkName, IEnumerable<Member> memberships, CancellationToken caller, CancellationToken deadline)
        {
            var selected = memberships.Where(item => item.Kind == kind).ToArray();
            if (stop) { checks.Add(new(checkName, "not_requested", now, null)); return; }
            var state = membershipComplete ? "complete" : "partial"; var observed = 0;
            foreach (var member in selected)
            {
                try
                {
                    if (!ConsumeRow()) throw new ReadException("partial");
                    using var document = await session.Read(member.Path, deadline);
                    var row = Property(document.RootElement, kind switch { "droplet" => "droplet", "volume" => "volume", _ => "load_balancer" });
                    if (!TryProduct(row, member, out var resource, out var partial)) { state = "partial"; continue; }
                    if (!resourceIds.Add(resource!.Id)) { state = "partial"; continue; }
                    resources.Add(resource!); observed++;
                    if (partial) state = "partial";
                }
                catch (OperationCanceledException) when (caller.IsCancellationRequested) { throw; }
                catch (Exception error) when (ReadFailure(error))
                {
                    var failure = Failure(error); state = observed > 0 || state != "complete" ? "partial" : failure;
                    if (MustStop(failure, deadline)) { stop = true; break; }
                }
            }
            if (observed > 0 && state != "complete") state = "partial";
            checks.Add(new(checkName, state, now, observed == 0 && state != "complete" ? null : new(observed, membershipComplete ? selected.Length : null)));
        }

        private bool TryProduct(JsonElement row, Member member, out CloudResource? resource, out bool partial)
        {
            resource = null; partial = false;
            if (row.ValueKind != JsonValueKind.Object) return false;
            if (member.Kind == "droplet")
            {
                var id = Property(row, "id");
                if (id.ValueKind != JsonValueKind.Number || !id.TryGetInt64(out var number) || number <= 0 || number.ToString(CultureInfo.InvariantCulture) != member.Id) return false;
            }
            else if (Text(row, "id") != member.Id) return false;
            var loadBalancerType = member.Kind == "loadbalancer" ? Enum(row, "type", ["REGIONAL", "REGIONAL_NETWORK", "GLOBAL"], ref partial) : null;
            var region = Text(Property(row, "region"), "slug");
            if (member.Kind == "loadbalancer" && loadBalancerType == "GLOBAL") region = "global";
            else if (!Region(region)) return false;
            if (member.Kind == "loadbalancer")
            {
                var project = Property(row, "project_id");
                if (project.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null) && (project.ValueKind != JsonValueKind.String || project.GetString() != Project)) return false;
            }
            var urn = "do:" + member.Kind + ":" + member.Id;
            string? vpc = null;
            if (member.Kind is "droplet" or "loadbalancer" && region != "global" && operation == "inventory")
            {
                var parent = Text(row, "vpc_uuid");
                if (Uuid(parent))
                {
                    vpc = "do:vpc:" + parent;
                    if (!references.TryGetValue(parent, out var reference)) references[parent] = new(region, 1, false);
                    else references[parent] = reference with { Count = reference.Count + 1, Ambiguous = reference.Ambiguous || reference.Region != region };
                }
                else { incompleteVpcReferences = true; if (Property(row, "vpc_uuid").ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null)) partial = true; }
            }
            object properties;
            if (member.Kind == "droplet")
            {
                var tags = StringSet(Property(row, "tags"), 100, out var knownTags);
                if (operation == "posture" && !knownTags) partial = true;
                droplets[member.Id] = new(region, knownTags ? tags : null);
                properties = new { state = Enum(row, "status", ["new", "active", "off", "archive"], ref partial),
                    vcpus = Count(row, "vcpus", ref partial), memoryMb = Count(row, "memory", ref partial), diskGb = Count(row, "disk", ref partial), vpc };
            }
            else if (member.Kind == "volume") properties = new { sizeGigabytes = Count(row, "size_gigabytes", ref partial) };
            else properties = new { state = Enum(row, "status", ["new", "active", "errored"], ref partial), type = loadBalancerType,
                network = Enum(row, "network", ["EXTERNAL", "INTERNAL"], ref partial), sizeUnit = Count(row, "size_unit", ref partial, 1, 100),
                redirectHttpToHttps = Boolean(row, "redirect_http_to_https", ref partial), proxyProtocol = Boolean(row, "enable_proxy_protocol", ref partial), vpc };
            resource = new("digitalocean", Project, region, urn,
                member.Kind switch { "droplet" => "compute.vm", "volume" => "storage.volume", _ => "network.load-balancer" }, "", properties);
            return true;
        }

        private async Task Vpcs(CancellationToken caller, CancellationToken deadline)
        {
            if (stop) { checks.Add(new("vpcs", "not_requested", now, null)); return; }
            var completeReferences = !incompleteVpcReferences && membershipComplete && checks.Where(check => check.Check is "droplets" or "load-balancers").All(check => check.State == "complete");
            var state = completeReferences ? "complete" : "partial"; var observed = 0;
            foreach (var (id, reference) in references)
            {
                if (reference.Ambiguous) { state = "partial"; continue; }
                try
                {
                    if (!ConsumeRow()) throw new ReadException("partial");
                    using var document = await session.Read("/v2/vpcs/" + id, deadline);
                    var row = Property(document.RootElement, "vpc");
                    var urn = Property(row, "urn");
                    if (Text(row, "id") != id || Text(row, "region") != reference.Region ||
                        urn.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null) && (urn.ValueKind != JsonValueKind.String || urn.GetString() != "do:vpc:" + id))
                    { state = "partial"; continue; }
                    var partial = false;
                    var properties = new { defaultNetwork = Boolean(row, "default", ref partial), relation = "referenced-by-project-resource", referringResourceCount = reference.Count };
                    if (!resourceIds.Add("do:vpc:" + id)) { state = "partial"; continue; }
                    resources.Add(new("digitalocean", Project, reference.Region, "do:vpc:" + id, "network.vpc", "", properties)); observed++;
                    if (partial) state = "partial";
                }
                catch (OperationCanceledException) when (caller.IsCancellationRequested) { throw; }
                catch (Exception error) when (ReadFailure(error))
                {
                    var failure = Failure(error); state = observed > 0 || state != "complete" ? "partial" : failure;
                    if (MustStop(failure, deadline)) { stop = true; break; }
                }
            }
            if (observed > 0 && state != "complete") state = "partial";
            checks.Add(new("vpcs", state, now, observed == 0 && state != "complete" ? null : new(observed, completeReferences ? references.Count : null)));
        }

        private async Task Firewalls(CancellationToken caller, CancellationToken deadline)
        {
            if (stop) { checks.Add(new("firewalls", "not_requested", now, null)); return; }
            var list = await Pages("/v2/firewalls", "firewalls", "firewalls", caller, deadline);
            var observed = 0;
            if (!membershipComplete || checks.Any(check => check.Check == "droplets" && check.State != "complete") || droplets.Values.Any(droplet => droplet.Tags is null)) list.Incomplete();
            var ids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var row in list.Rows)
            {
                var id = Text(row, "id");
                if (!Uuid(id) || !ids.Add(id)) { list.Incomplete(); continue; }
                var direct = NumericSet(Property(row, "droplet_ids"), out var knownDirect);
                var tags = StringSet(Property(row, "tags"), 100, out var knownTags);
                if (!knownDirect || !knownTags) list.Incomplete();
                var directMatches = knownDirect ? direct.Where(droplets.ContainsKey).ToHashSet(StringComparer.Ordinal) : [];
                var tagMatches = knownTags ? droplets.Where(pair => pair.Value.Tags is not null && pair.Value.Tags.Overlaps(tags)).Select(pair => pair.Key).ToHashSet(StringComparer.Ordinal) : [];
                if (directMatches.Count == 0 && tagMatches.Count == 0) continue;
                var partial = false;
                var state = Enum(row, "status", ["waiting", "succeeded", "failed"], ref partial);
                var rules = Property(row, "inbound_rules");
                int? ruleCount = null, globalRules = null;
                var observedGlobalRules = 0;
                if (rules.ValueKind == JsonValueKind.Array && rules.GetArrayLength() <= 1000)
                {
                    ruleCount = rules.GetArrayLength(); globalRules = 0;
                    foreach (var rule in rules.EnumerateArray())
                    {
                        if (!TryIngress(rule, out var global)) { partial = true; globalRules = null; continue; }
                        if (global) { observedGlobalRules++; if (globalRules is not null) globalRules++; }
                    }
                }
                else { partial = true; }
                var matched = directMatches.Union(tagMatches, StringComparer.Ordinal).Count();
                var properties = new { state, directDropletCount = knownDirect ? (int?)directMatches.Count : null,
                    tagDropletCount = knownTags && droplets.Values.All(droplet => droplet.Tags is not null) ? (int?)tagMatches.Count : null,
                    observedDropletCount = matched, inboundRuleCount = ruleCount, observedGlobalIngressRuleCount = globalRules };
                resources.Add(new("digitalocean", Project, "project-related", "do:firewall:" + id, "network.firewall", "", properties)); observed++;
                if (partial) list.Incomplete();
                if (observedGlobalRules > 0) findings.Add(new(FindingSeverity.Warning, "DIGITALOCEAN_WORLD_INGRESS", "Configured global ingress requires review",
                    "A firewall related to observed project droplets by direct or tag membership contains a global ingress allow rule. This is configuration evidence, not proof of effective reachability.",
                    "Review intended sources, rules, membership and external controls in the provider console. Opscope does not probe service URLs or apply changes."));
            }
            list.Observed = observed;
            // The API total is the visible firewall collection, not a count of project-related firewalls.
            list.Expected = null;
            checks.Add(list.Check(now));
        }

        private async Task<PageResult> Pages(string path, string property, string check, CancellationToken caller, CancellationToken deadline)
        {
            var result = new PageResult(check);
            if (stop) { result.State = "not_requested"; return result; }
            var consumed = 0;
            try
            {
                for (var page = 1; page <= 10; page++)
                {
                    using var document = await session.Read(path + "?per_page=100&page=" + page.ToString(CultureInfo.InvariantCulture), deadline);
                    var root = document.RootElement;
                    var rows = Property(root, property); var total = Property(Property(root, "meta"), "total");
                    if (rows.ValueKind != JsonValueKind.Array || rows.GetArrayLength() > 100 || total.ValueKind != JsonValueKind.Number || !total.TryGetInt32(out var count) || count < 0)
                        throw new JsonException("Invalid bounded collection.");
                    if (result.Expected is not null && result.Expected != count) { result.Incomplete(); break; }
                    result.Expected = count;
                    consumed += rows.GetArrayLength();
                    if (consumed > count) result.Incomplete();
                    foreach (var row in rows.EnumerateArray())
                    {
                        if (!ConsumeRow()) throw new ReadException("partial");
                        result.Rows.Add(row.Clone());
                    }
                    var links = Property(root, "links");
                    if (links.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null or JsonValueKind.Object)) { result.Incomplete(); break; }
                    var pages = Property(links, "pages");
                    if (pages.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null or JsonValueKind.Object)) { result.Incomplete(); break; }
                    var next = Property(pages, "next");
                    if (next.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
                    {
                        if (consumed != count) result.Incomplete();
                        break;
                    }
                    if (page == 10 || rows.GetArrayLength() == 0 || consumed >= count || !Next(next, path, page + 1)) { result.Incomplete(); break; }
                }
            }
            catch (OperationCanceledException) when (caller.IsCancellationRequested) { throw; }
            catch (Exception error) when (ReadFailure(error))
            {
                var failure = Failure(error); result.State = result.Rows.Count == 0 ? failure : "partial";
                if (MustStop(failure, deadline)) stop = true;
            }
            result.Observed = result.Rows.Count;
            return result;
        }

        private bool ConsumeRow()
        {
            if (++sourceRows <= 1000) return true;
            stop = true; return false;
        }
        private static bool MustStop(string failure, CancellationToken deadline) => failure is "rate_limited" or "timed_out" or "partial" || deadline.IsCancellationRequested;
        private void AddUnrequested()
        {
            var selected = operation == "inventory" ? new[] { "project-resources", "droplets", "volumes", "load-balancers", "vpcs" } : new[] { "project-resources", "droplets", "firewalls" };
            foreach (var check in selected) if (checks.All(item => item.Check != check)) checks.Add(new(check, "not_requested", now, null));
        }
        public AnalysisReport Result(string state, string? warning = null)
        {
            if (warning is not null) warnings.Add(warning);
            if (state != "complete") warnings.Add("A source, identity, membership field, page or safety budget is unavailable or incomplete. Unknown observations are not an empty inventory; quota and safety failures stop subsequent reads without retries.");
            warnings.Add("Project verification confirms only the selected project ID. Resource membership includes only resources visible to the existing token and does not prove account/team identity or complete service coverage. VPCs are retained only as verified references from observed project resources, not as exclusive project ownership. Apps, databases and other resource types are outside this reader.");
            warnings.Add("Only allowlisted configuration metadata is retained. Names, tags, IP addresses, CIDRs, raw rules, certificates and service URLs are omitted. State, membership and global-ingress configuration do not establish effective isolation, reachability or application health. No resource or service is changed.");
            warnings.Add("Reads are bounded to sixty seconds, sixty fixed GETs, ten one-hundred-row pages per list, 1,000 source rows, 4 MiB per response and 8 MiB overall. Individual resource GETs can reach the request bound before the row bound. Missing granular permissions may omit provider-visible resources or metadata.");
            var reportWarnings = warnings.Distinct(StringComparer.Ordinal).ToArray();
            return new("cloud.digitalocean." + operation, now, findings, new
            {
                provider = "digitalocean", operation, resources,
                scope = new { schemaVersion = 1, projects = Project.Length == 0 ? Array.Empty<string>() : new[] { Project } },
                coverage = new { state, observedAtUtc = now, enumeratedResources = resources.Count, expectedScopes = 1,
                    completedScopes = scopeState == "verified" && checks.Count > 0 && checks.All(check => check.State == "complete") ? 1 : 0, warnings = reportWarnings },
                configurationEvidence = new { source = "digitalocean-project-fixed-read", scopeVerification = new { source = "digitalocean-project-v2", state = scopeState }, checks },
                source = "digitalocean-project-fixed-read-only-v2", authentication = "existing-bearer-token"
            }, reportWarnings) { OperationSucceeded = state == "complete" };
        }
    }

    private sealed record Member(string Kind, string Id, string Path);
    private sealed record Droplet(string Region, HashSet<string>? Tags);
    private sealed record VpcReference(string Region, int Count, bool Ambiguous);
    private sealed record SourceObservations(int ObservedResources, int? ExpectedResources);
    private sealed record SourceCheck(string Check, string State, DateTimeOffset ObservedAtUtc, SourceObservations? Observations);
    private sealed class PageResult(string name)
    {
        public List<JsonElement> Rows { get; } = [];
        public string State { get; set; } = "complete";
        public int Observed { get; set; }
        public int? Expected { get; set; }
        public void Incomplete() { if (State == "complete") State = "partial"; }
        public SourceCheck Check(DateTimeOffset time) => new(name, State, time, Observed == 0 && State != "complete" ? null : new(Observed, Expected));
    }

    private sealed class Session(HttpClient client, string token)
    {
        private int requests, totalBytes;
        private bool exhausted;
        public async Task<JsonDocument> Read(string path, CancellationToken cancellationToken)
        {
            if (exhausted) throw new ReadException("rate_limited");
            if (++requests > 60) throw new ReadException("partial");
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.digitalocean.com" + path);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.StatusCode != HttpStatusCode.OK) throw new ReadException(response.StatusCode switch
            {
                HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => "permission_denied",
                HttpStatusCode.TooManyRequests => "rate_limited", _ => "failed"
            });
            if (response.Headers.TryGetValues("ratelimit-remaining", out var remaining) && remaining.Any(value => value.Trim() == "0")) exhausted = true;
            if (response.Content.Headers.ContentLength > 4 * 1024 * 1024) throw new ReadException("partial");
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var buffer = new MemoryStream();
            var chunk = new byte[8192]; int count;
            while ((count = await stream.ReadAsync(chunk, cancellationToken)) != 0)
            {
                totalBytes += count;
                if (buffer.Length + count > 4 * 1024 * 1024 || totalBytes > 8 * 1024 * 1024) throw new ReadException("partial");
                await buffer.WriteAsync(chunk.AsMemory(0, count), cancellationToken);
            }
            var document = JsonDocument.Parse(buffer.ToArray(), new JsonDocumentOptions { MaxDepth = 32 });
            try { UniqueProperties(document.RootElement); return document; }
            catch { document.Dispose(); throw; }
        }
    }

    private sealed class ReadException(string state) : IOException { public string State { get; } = state; }
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
        else if (value.ValueKind == JsonValueKind.Array) foreach (var item in value.EnumerateArray()) UniqueProperties(item);
    }
    private static bool ReadFailure(Exception error) => error is JsonException or HttpRequestException or IOException or OperationCanceledException or FormatException or InvalidOperationException;
    private static string Failure(Exception error) => error is ReadException read ? read.State : error is OperationCanceledException ? "timed_out" : "failed";
    private static JsonElement Property(JsonElement value, string key) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var result) ? result : default;
    private static string Text(JsonElement value, string key) => Property(value, key) is var item && item.ValueKind == JsonValueKind.String ? item.GetString() ?? "" : "";
    private static bool Uuid(string value) => Guid.TryParseExact(value, "D", out var parsed) && parsed != Guid.Empty && value == parsed.ToString("D");
    private static bool NumericId(string value) => Regex.IsMatch(value, "\\A[1-9][0-9]{0,18}\\z", RegexOptions.CultureInvariant) && long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out _);
    private static bool Region(string value) => Regex.IsMatch(value, "\\A[a-z]{3}[0-9]{1,2}\\z", RegexOptions.CultureInvariant);
    private static string ResourcePath(string kind, string id) => "/v2/" + (kind switch { "droplet" => "droplets", "volume" => "volumes", _ => "load_balancers" }) + "/" + id;
    private static int? Count(JsonElement row, string key, ref bool partial, int minimum = 0, int maximum = int.MaxValue)
    {
        var value = Property(row, key);
        if (value.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null) return null;
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var count) && count >= minimum && count <= maximum) return count;
        partial = true; return null;
    }
    private static bool? Boolean(JsonElement row, string key, ref bool partial)
    {
        var value = Property(row, key);
        if (value.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null) return null;
        if (value.ValueKind is JsonValueKind.True or JsonValueKind.False) return value.GetBoolean();
        partial = true; return null;
    }
    private static string? Enum(JsonElement row, string key, string[] values, ref bool partial)
    {
        var value = Property(row, key);
        if (value.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null) return null;
        if (value.ValueKind == JsonValueKind.String && values.Contains(value.GetString(), StringComparer.Ordinal)) return value.GetString();
        partial = true; return null;
    }
    private static HashSet<string> StringSet(JsonElement value, int bound, out bool known)
    {
        var values = new HashSet<string>(StringComparer.Ordinal);
        known = value.ValueKind == JsonValueKind.Array && value.GetArrayLength() <= bound;
        if (!known) return values;
        foreach (var item in value.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || item.GetString() is not { Length: > 0 and <= 128 } text || text.Any(char.IsControl) || !values.Add(text)) known = false;
        }
        if (!known) values.Clear();
        return values;
    }
    private static HashSet<string> NumericSet(JsonElement value, out bool known)
    {
        var values = new HashSet<string>(StringComparer.Ordinal);
        known = value.ValueKind == JsonValueKind.Array && value.GetArrayLength() <= 1000;
        if (!known) return values;
        foreach (var item in value.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Number || !item.TryGetInt64(out var id) || id <= 0 || !values.Add(id.ToString(CultureInfo.InvariantCulture))) known = false;
        }
        if (!known) values.Clear();
        return values;
    }
    private static bool TryIngress(JsonElement rule, out bool global)
    {
        global = false;
        var protocol = Text(rule, "protocol"); var ports = Text(rule, "ports");
        if (protocol is not ("tcp" or "udp" or "icmp") || !Ports(ports) || protocol == "icmp" && ports != "0") return false;
        var action = Property(rule, "action");
        if (action.ValueKind is not JsonValueKind.Undefined && (action.ValueKind != JsonValueKind.String || action.GetString() is not ("allow" or "deny"))) return false;
        var addresses = Property(Property(rule, "sources"), "addresses");
        if (addresses.ValueKind != JsonValueKind.Array || addresses.GetArrayLength() > 1000) return false;
        var observedGlobal = false;
        foreach (var address in addresses.EnumerateArray())
        {
            if (address.ValueKind != JsonValueKind.String || address.GetString() is not { Length: > 0 and <= 64 } text) return false;
            var pieces = text.Split('/');
            if (pieces.Length > 2 || !IPAddress.TryParse(pieces[0], out var ip)) return false;
            if (pieces.Length == 2)
            {
                if (!int.TryParse(pieces[1], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix) || prefix < 0 || prefix > (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128)) return false;
                if (prefix == 0) observedGlobal = true;
            }
        }
        global = observedGlobal && (action.ValueKind == JsonValueKind.Undefined || action.GetString() == "allow");
        return true;
    }
    private static bool Ports(string value)
    {
        if (value == "0") return true;
        var pieces = value.Split('-');
        if (pieces.Length is < 1 or > 2 || !int.TryParse(pieces[0], NumberStyles.None, CultureInfo.InvariantCulture, out var first) || first is < 1 or > 65535) return false;
        return pieces.Length == 1 || int.TryParse(pieces[1], NumberStyles.None, CultureInfo.InvariantCulture, out var last) && last >= first && last <= 65535;
    }
    private static bool Next(JsonElement next, string path, int page)
    {
        if (next.ValueKind != JsonValueKind.String || !Uri.TryCreate(next.GetString(), UriKind.Absolute, out var uri) ||
            uri.Scheme != "https" || uri.Host != "api.digitalocean.com" || !uri.IsDefaultPort || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0 || uri.AbsolutePath != path) return false;
        var fields = uri.Query.TrimStart('?').Split('&');
        return fields.Length == 2 && fields.Contains("per_page=100", StringComparer.Ordinal) && fields.Contains("page=" + page.ToString(CultureInfo.InvariantCulture), StringComparer.Ordinal);
    }
}
