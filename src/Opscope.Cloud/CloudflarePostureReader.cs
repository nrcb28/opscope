using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.RegularExpressions;

[assembly: InternalsVisibleTo("Opscope.CloudflarePostureTests")]

namespace Opscope.Cloud;

/// <summary>Fixed, explicitly zone-scoped configuration reads; never evaluates DNS content or WAF expressions.</summary>
public sealed class CloudflarePostureProvider : ICloudProvider
{
    private const int MaximumReads = 60, MaximumRows = 1000, MaximumDnsPages = 10;
    private const int MaximumResponseBytes = 4 * 1024 * 1024, MaximumTotalBytes = 8 * 1024 * 1024;
    private static readonly HttpClient DefaultClient = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(10),
        AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
    }) { Timeout = TimeSpan.FromSeconds(30) };
    private static readonly string[] AvailableChecks = ["tls", "dns", "waf", "routes"];
    private static readonly string[] WafPhases = ["http_request_firewall_managed", "http_request_firewall_custom"];
    private static readonly HashSet<string> DnsTypes = new(StringComparer.Ordinal)
        { "A", "AAAA", "CAA", "CERT", "CNAME", "DNSKEY", "DS", "HTTPS", "LOC", "MX", "NAPTR", "NS", "OPENPGPKEY", "PTR", "SMIMEA", "SRV", "SSHFP", "SVCB", "TLSA", "TXT", "URI" };
    private static readonly HashSet<string> WafActions = new(StringComparer.Ordinal)
        { "block", "challenge", "js_challenge", "managed_challenge", "skip", "log", "execute", "allow" };
    private readonly HttpClient client;
    private readonly Func<string, string?> credential;
    public string Name => "cloudflare";

    public CloudflarePostureProvider() : this(DefaultClient, Environment.GetEnvironmentVariable) { }
    internal CloudflarePostureProvider(HttpClient client, Func<string, string?> credential)
    { this.client = client; this.credential = credential; }

    public async Task<AnalysisReport> CollectAsync(string operation, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        var now = DateTimeOffset.UtcNow;
        var checks = new List<CloudflareConfigurationCheck>();
        var resources = new List<CloudResource>();
        var findings = new List<Finding>();
        var warnings = new List<string>();
        var account = Option("account").ToLowerInvariant();
        var zones = Option("zones").Split(',', StringSplitOptions.TrimEntries).Select(zone => zone.ToLowerInvariant()).ToArray();
        var selected = (options.ContainsKey("cloudflare-checks") ? Option("cloudflare-checks") : "tls").Split(',', StringSplitOptions.TrimEntries);
        var completedScopes = 0;
        var failures = new List<CoverageState>();
        if (!operation.Equals("posture", StringComparison.OrdinalIgnoreCase)) return Report(CoverageState.Unsupported, "This reader supports selected Cloudflare configuration posture only. No provider request was sent.");
        if (!HexId(account) || zones.Length is < 1 or > 20 || zones.Any(zone => !HexId(zone)) || zones.Distinct(StringComparer.Ordinal).Count() != zones.Length ||
            selected.Length is < 1 or > 4 || selected.Distinct(StringComparer.Ordinal).Count() != selected.Length || selected.Any(check => !AvailableChecks.Contains(check, StringComparer.Ordinal)) || Option("resource").Length > 0)
            return Report(CoverageState.NotConfigured, "Cloudflare posture needs an explicit account, one to twenty distinct authorized zones and only tls,dns,waf,routes checks. Resource filters are unsupported; no request was sent.");
        string? token;
        try { token = credential("CLOUDFLARE_API_TOKEN"); }
        catch (Exception error) when (error is IOException or InvalidOperationException or ArgumentException)
        { token = null; }
        if (string.IsNullOrWhiteSpace(token) || token.Length > 16384 || token.Any(char.IsControl))
            return Report(CoverageState.NotConfigured, "Cloudflare posture requires the existing server-side CLOUDFLARE_API_TOKEN. No login or token acquisition was attempted.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        var session = new ReadSession(client, token);
        var stop = false;
        foreach (var zone in zones)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (stop || deadline.IsCancellationRequested)
            {
                foreach (var check in selected) checks.Add(new(check, zone, "not_requested", now, Source(check), null));
                continue;
            }
            try
            {
                using var descriptor = await session.Get($"zones/{zone}", deadline.Token);
                var result = Result(descriptor.RootElement);
                if (!SameId(Text(result, "id"), zone) || !SameId(Text(Property(result, "account"), "id"), account))
                    throw new ReadFailure(CoverageState.PermissionDenied);
                var paused = Boolean(result, "paused");
                resources.Add(new("cloudflare", account, "edge", zone, "edge.zone.configuration", "", new { paused }));
                if (paused == true) findings.Add(new(FindingSeverity.Warning, "CLOUDFLARE_ZONE_PAUSED", "Cloudflare zone is paused",
                    $"{zone}: the verified zone descriptor reports paused=true.", "Review whether the paused configuration is intended. This observation does not establish effective traffic routing or service availability."));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception error) when (ReadError(error))
            {
                var failure = Failure(error); failures.Add(failure);
                foreach (var check in selected) checks.Add(new(check, zone, State(failure), now, Source(check), null));
                warnings.Add("A selected zone could not be verified in the configured account. Its configuration reads were skipped; provider bodies and credentials are omitted.");
                stop = failure is CoverageState.RateLimited or CoverageState.Partial || deadline.IsCancellationRequested;
                continue;
            }
            var zoneComplete = true;
            foreach (var check in selected)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (stop || deadline.IsCancellationRequested)
                { checks.Add(new(check, zone, "not_requested", now, Source(check), null)); zoneComplete = false; continue; }
                var evidence = check switch
                {
                    "tls" => await ReadTls(zone),
                    "dns" => await ReadDns(zone),
                    "waf" => await ReadWaf(zone),
                    _ => await ReadRoutes(zone)
                };
                checks.Add(evidence);
                if (evidence.State != "complete") zoneComplete = false;
                stop = evidence.State == "rate_limited" || session.Throttled || session.Exhausted || deadline.IsCancellationRequested;
            }
            if (zoneComplete) completedScopes++;
        }
        if (deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            warnings.Add("Cloudflare configuration collection reached its thirty-second operation deadline. Remaining reads were omitted.");
        cancellationToken.ThrowIfCancellationRequested();
        var state = completedScopes == zones.Length ? CoverageState.Complete : resources.Count > 0 ? CoverageState.Partial :
            failures.Count > 0 && failures.Distinct().Count() == 1 ? failures[0] : CoverageState.Failed;
        return Report(state);

        string Option(string key) => options.TryGetValue(key, out var value) ? value.Trim() : "";
        AnalysisReport Report(CoverageState state, string? warning = null)
        {
            if (warning is not null) warnings.Add(warning);
            warnings.Add("Cloudflare posture is a bounded observation of explicitly selected zone configuration. Counts describe observed records, rules or routes, not a complete account inventory or effective protection. No DNS contents, WAF expressions, Worker route patterns, script names or credentials are emitted.");
            if (state == CoverageState.Partial) warnings.Add("Some selected checks or zones are incomplete, unavailable or outside a read, row, page, byte or time bound. Missing settings and counters are unknown, not zero or disabled.");
            return new("cloud.cloudflare.posture", now, findings, new
            {
                provider = "cloudflare", operation = "posture", resources,
                scope = new { account = HexId(account) ? account : null, zones = zones.Where(HexId).Select(zone => new { zoneId = zone }).ToArray() },
                configurationEvidence = new { source = "cloudflare-fixed-configuration-get", checks },
                coverage = new CloudCoverage(state, now, resources.Count, zones.All(HexId) ? zones.Length : 0, completedScopes, warnings.Distinct(StringComparer.Ordinal).ToArray()),
                source = "cloudflare-fixed-configuration-get"
            }, warnings.Distinct(StringComparer.Ordinal).ToArray()) { OperationSucceeded = state == CoverageState.Complete };
        }

        async Task<CloudflareConfigurationCheck> ReadTls(string zone)
        {
            var observations = new Dictionary<string, object?> { ["sslMode"] = null, ["minimumTlsVersion"] = null, ["alwaysUseHttps"] = null };
            var errors = new List<CoverageState>(); var observed = 0;
            foreach (var setting in new[] { "ssl", "min_tls_version", "always_use_https" })
            {
                try
                {
                    using var document = await session.Get($"zones/{zone}/settings/{setting}", deadline.Token);
                    var result = Result(document.RootElement);
                    if (Text(result, "id") != setting) throw new InvalidDataException("Setting identity mismatch.");
                    var value = Text(result, "value");
                    if (setting == "ssl" && value is "off" or "flexible" or "full" or "strict" or "origin_pull")
                    {
                        observations["sslMode"] = value;
                        if (value is "off" or "flexible") findings.Add(new(FindingSeverity.Warning, "CLOUDFLARE_WEAK_SSL_MODE", "Cloudflare origin encryption mode needs review",
                            $"{zone}: the observed SSL mode is {value}.", "Review the intended origin encryption policy. This is control-plane configuration evidence, not an origin connectivity test."));
                    }
                    else if (setting == "min_tls_version" && value is "1.0" or "1.1" or "1.2" or "1.3")
                    {
                        observations["minimumTlsVersion"] = value;
                        if (value is "1.0" or "1.1") findings.Add(new(FindingSeverity.Warning, "CLOUDFLARE_LEGACY_TLS_MINIMUM", "Cloudflare permits a legacy TLS minimum",
                            $"{zone}: the observed minimum TLS version is {value}.", "Review client compatibility and the approved minimum TLS policy before changing configuration."));
                    }
                    else if (setting == "always_use_https" && value is "on" or "off") observations["alwaysUseHttps"] = value == "on";
                    else throw new InvalidDataException("Unknown setting value.");
                    observed++;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch (Exception error) when (ReadError(error))
                {
                    var failure = Failure(error); errors.Add(failure);
                    if (failure is CoverageState.RateLimited or CoverageState.Partial || deadline.IsCancellationRequested) break;
                }
            }
            return Check("tls", zone, errors, observed > 0 ? observations : null);
        }

        async Task<CloudflareConfigurationCheck> ReadDns(string zone)
        {
            var types = new Dictionary<string, int>(StringComparer.Ordinal); var ids = new HashSet<string>(StringComparer.Ordinal);
            var observed = 0; var proxied = 0; var unproxied = 0; var unknown = 0; var useful = false; var errors = new List<CoverageState>();
            int? expectedTotal = null, expectedPages = null;
            var consumedRows = 0;
            try
            {
                for (var page = 1; page <= MaximumDnsPages; page++)
                {
                    using var document = await session.Get($"zones/{zone}/dns_records?page={page}&per_page=100", deadline.Token);
                    var root = document.RootElement; var result = Result(root);
                    if (result.ValueKind != JsonValueKind.Array || result.GetArrayLength() > 100) throw new InvalidDataException("Invalid DNS page.");
                    var info = Property(root, "result_info");
                    var pages = Integer(info, "total_pages"); var total = Integer(info, "total_count");
                    if (Integer(info, "page") != page || Integer(info, "per_page") != 100 || Integer(info, "count") != result.GetArrayLength() ||
                        pages is null or < 0 || total is null or < 0 || total < result.GetArrayLength() || pages < page && !(page == 1 && pages == 0 && total == 0 && result.GetArrayLength() == 0))
                        throw new InvalidDataException("DNS pagination is incomplete.");
                    if (expectedTotal is not null && (total != expectedTotal || pages != expectedPages))
                        throw new InvalidDataException("DNS pagination totals changed.");
                    expectedTotal = total; expectedPages = pages;
                    consumedRows += result.GetArrayLength();
                    if (consumedRows > total) throw new InvalidDataException("DNS rows exceed the stated total.");
                    useful = true;
                    foreach (var row in result.EnumerateArray())
                    {
                        session.Row();
                        var id = Text(row, "id").ToLowerInvariant(); var type = Text(row, "type");
                        if (!HexId(id) || !DnsTypes.Contains(type) || !ids.Add(id)) { errors.Add(CoverageState.Partial); continue; }
                        observed++; types[type] = types.GetValueOrDefault(type) + 1;
                        if (Boolean(row, "proxied") is { } proxy) { if (proxy) proxied++; else unproxied++; }
                        else { unknown++; errors.Add(CoverageState.Partial); }
                    }
                    if (page >= pages)
                    {
                        if (consumedRows != total) errors.Add(CoverageState.Partial);
                        break;
                    }
                    if (page == MaximumDnsPages || result.GetArrayLength() == 0) throw new ReadFailure(CoverageState.Partial);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception error) when (ReadError(error)) { errors.Add(Failure(error)); }
            return Check("dns", zone, errors, useful && (errors.Count == 0 || observed > 0) ? new { observedRecords = observed, recordTypes = types.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { type = pair.Key, count = pair.Value }).ToArray(), observedProxiedRecords = proxied, observedUnproxiedRecords = unproxied, unknownProxyRecords = unknown } : null);
        }

        async Task<CloudflareConfigurationCheck> ReadWaf(string zone)
        {
            var observedRulesets = 0; var rules = 0; var enabled = 0; var disabled = 0; var unknown = 0;
            var actions = new Dictionary<string, int>(StringComparer.Ordinal); var errors = new List<CoverageState>();
            foreach (var phase in WafPhases)
            {
                try
                {
                    using var document = await session.Get($"zones/{zone}/rulesets/phases/{phase}/entrypoint", deadline.Token);
                    var result = Result(document.RootElement); var rows = Property(result, "rules");
                    if (!HexId(Text(result, "id")) || Text(result, "phase") != phase || Text(result, "kind") != "zone" || rows.ValueKind != JsonValueKind.Array)
                        throw new InvalidDataException("Invalid WAF entrypoint identity.");
                    observedRulesets++;
                    var ids = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var row in rows.EnumerateArray())
                    {
                        session.Row();
                        var id = Text(row, "id").ToLowerInvariant(); var action = Text(row, "action");
                        if (!HexId(id) || !ids.Add(id)) { errors.Add(CoverageState.Partial); continue; }
                        rules++;
                        if (Boolean(row, "enabled") is { } active) { if (active) enabled++; else disabled++; }
                        else { unknown++; errors.Add(CoverageState.Partial); }
                        if (WafActions.Contains(action)) actions[action] = actions.GetValueOrDefault(action) + 1;
                        else errors.Add(CoverageState.Partial);
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch (Exception error) when (ReadError(error))
                {
                    var failure = Failure(error); errors.Add(failure);
                    if (failure is CoverageState.RateLimited or CoverageState.Partial || deadline.IsCancellationRequested) break;
                }
            }
            return Check("waf", zone, errors, observedRulesets > 0 ? new { observedRulesets, phasesObserved = observedRulesets, observedRules = rules, observedEnabledRules = enabled, observedDisabledRules = disabled, unknownEnabledRules = unknown,
                observedActions = actions.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => new { action = pair.Key, count = pair.Value }).ToArray() } : null);
        }

        async Task<CloudflareConfigurationCheck> ReadRoutes(string zone)
        {
            var useful = false; var observed = 0; var errors = new List<CoverageState>();
            try
            {
                using var document = await session.Get($"zones/{zone}/workers/routes", deadline.Token);
                var result = Result(document.RootElement);
                if (result.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Invalid routes envelope.");
                useful = true;
                var ids = new HashSet<string>(StringComparer.Ordinal);
                foreach (var row in result.EnumerateArray())
                {
                    session.Row(); var id = Text(row, "id").ToLowerInvariant();
                    if (!HexId(id) || !ids.Add(id)) { errors.Add(CoverageState.Partial); continue; }
                    observed++;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception error) when (ReadError(error)) { errors.Add(Failure(error)); }
            return Check("routes", zone, errors, useful ? new { observedRoutes = observed } : null);
        }

        CloudflareConfigurationCheck Check(string check, string zone, List<CoverageState> errors, object? observations)
        {
            foreach (var error in errors) failures.Add(error);
            var state = errors.Count == 0 ? "complete" : observations is not null && !errors.Contains(CoverageState.RateLimited) ? "partial" : State(errors.Contains(CoverageState.RateLimited) ? CoverageState.RateLimited : errors.Distinct().Count() == 1 ? errors[0] : CoverageState.Failed);
            if (errors.Count > 0) warnings.Add("A selected Cloudflare configuration check was unavailable, malformed or incomplete. Read permissions and product availability must be verified outside Opscope; missing configuration is unknown.");
            return new(check, zone, state, now, Source(check), observations);
        }
    }

    private static string Source(string check) => check switch { "tls" => "Cloudflare Zone Settings", "dns" => "Cloudflare DNS metadata", "waf" => "Cloudflare zone WAF entrypoints", _ => "Cloudflare Worker routes" };
    private static string State(CoverageState state) => state switch { CoverageState.Complete => "complete", CoverageState.Partial => "partial", CoverageState.PermissionDenied => "permission_denied", CoverageState.RateLimited => "rate_limited", CoverageState.Unsupported => "unavailable", _ => "failed" };
    private static CoverageState Failure(Exception error) => error is ReadFailure classified ? classified.State : CoverageState.Failed;
    private static bool ReadError(Exception error) => error is IOException or InvalidDataException or JsonException or HttpRequestException or OperationCanceledException or ArgumentException or InvalidOperationException;
    private static bool HexId(string value) => Regex.IsMatch(value, @"\A[a-fA-F0-9]{32}\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static bool SameId(string value, string expected) => HexId(value) && value.Equals(expected, StringComparison.OrdinalIgnoreCase);
    private static JsonElement Property(JsonElement value, string key)
    {
        if (value.ValueKind != JsonValueKind.Object) return default;
        var found = default(JsonElement); var count = 0;
        foreach (var property in value.EnumerateObject()) if (property.Name == key) { found = property.Value; count++; }
        if (count > 1) throw new InvalidDataException("Duplicate provider field.");
        return found;
    }
    private static string Text(JsonElement value, string key) => Property(value, key) is { ValueKind: JsonValueKind.String } text ? text.GetString() ?? "" : "";
    private static bool? Boolean(JsonElement value, string key) => Property(value, key).ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => null };
    private static int? Integer(JsonElement value, string key) => Property(value, key) is { ValueKind: JsonValueKind.Number } number && number.TryGetInt32(out var integer) ? integer : null;
    private static JsonElement Result(JsonElement root)
    {
        var errors = Property(root, "errors");
        if (root.ValueKind != JsonValueKind.Object || Property(root, "success").ValueKind != JsonValueKind.True ||
            errors.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Array) || errors.ValueKind == JsonValueKind.Array && errors.GetArrayLength() > 0)
            throw new InvalidDataException("Cloudflare returned incomplete evidence.");
        var result = Property(root, "result");
        if (result.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array)) throw new InvalidDataException("Missing Cloudflare result.");
        return result;
    }

    private sealed class ReadFailure(CoverageState state) : IOException { public CoverageState State { get; } = state; }
    private sealed class ReadSession(HttpClient client, string token)
    {
        private int reads, rows, bytes;
        public bool Exhausted => reads >= MaximumReads || rows >= MaximumRows || bytes >= MaximumTotalBytes;
        public bool Throttled { get; private set; }
        public void Row() { if (++rows > MaximumRows) throw new ReadFailure(CoverageState.Partial); }
        public async Task<JsonDocument> Get(string path, CancellationToken cancellationToken)
        {
            if (++reads > MaximumReads) throw new ReadFailure(CoverageState.Partial);
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.cloudflare.com/client/v4/" + path);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.StatusCode == HttpStatusCode.TooManyRequests) Throttled = true;
            if (!response.IsSuccessStatusCode) throw new ReadFailure(response.StatusCode switch
            {
                HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => CoverageState.PermissionDenied,
                HttpStatusCode.TooManyRequests => CoverageState.RateLimited,
                HttpStatusCode.NotFound => CoverageState.Unsupported,
                _ => CoverageState.Failed
            });
            if (response.Content.Headers.ContentLength > MaximumResponseBytes || response.Content.Headers.ContentLength + bytes > MaximumTotalBytes)
                throw new ReadFailure(CoverageState.Partial);
            await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var buffer = new MemoryStream();
            var block = new byte[8192]; int count;
            while ((count = await input.ReadAsync(block, cancellationToken)) != 0)
            {
                if (buffer.Length + count > MaximumResponseBytes || bytes + count > MaximumTotalBytes) throw new ReadFailure(CoverageState.Partial);
                bytes += count; await buffer.WriteAsync(block.AsMemory(0, count), cancellationToken);
            }
            return JsonDocument.Parse(buffer.ToArray(), new JsonDocumentOptions { MaxDepth = 32 });
        }
    }
}

public sealed record CloudflareConfigurationCheck(string Check, string ZoneId, string State, DateTimeOffset ObservedAtUtc, string Source, object? Observations);
