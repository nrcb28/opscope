using System.Net;
using System.Text.Json;
using Opscope;
using Opscope.Cloud;

const string Account = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Zone = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Other = "cccccccccccccccccccccccccccccccc";
var assertions = 0;
void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); assertions++; }
static JsonElement Data(AnalysisReport report) => JsonSerializer.SerializeToElement(report.Data, ReportSecurity.JsonOptions);
static string State(AnalysisReport report) => Data(report).GetProperty("coverage").GetProperty("state").GetString()!;
static string Raw(AnalysisReport report) => JsonSerializer.Serialize(report, ReportSecurity.JsonOptions);
static JsonElement Evidence(AnalysisReport report, string check) => Data(report).GetProperty("configurationEvidence").GetProperty("checks").EnumerateArray().Single(item => item.GetProperty("check").GetString() == check);
static Dictionary<string, string> Options(string? checks = null, string? zones = null) => checks is null
    ? new() { ["account"] = Account, ["zones"] = zones ?? Zone }
    : new() { ["account"] = Account, ["zones"] = zones ?? Zone, ["cloudflare-checks"] = checks };
static HttpResponseMessage Json(object value) => new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(value)) };
static object Envelope(object value) => new { success = true, errors = Array.Empty<object>(), result = value };
static object Descriptor(string zone = Zone, string account = Account) => Envelope(new { id = zone, account = new { id = account }, paused = true, name = "private-zone.example", token = "PRIVATE_TOKEN_FIELD" });
static HttpResponseMessage Fixture(HttpRequestMessage request)
{
    var path = request.RequestUri!.AbsolutePath;
    if (path.EndsWith("/settings/ssl", StringComparison.Ordinal)) return Json(Envelope(new { id = "ssl", value = "flexible", secret = "PRIVATE_SETTING" }));
    if (path.EndsWith("/settings/min_tls_version", StringComparison.Ordinal)) return Json(Envelope(new { id = "min_tls_version", value = "1.0" }));
    if (path.EndsWith("/settings/always_use_https", StringComparison.Ordinal)) return Json(Envelope(new { id = "always_use_https", value = "on" }));
    if (path.EndsWith("/dns_records", StringComparison.Ordinal)) return Json(new { success = true, errors = Array.Empty<object>(), result = new object[]
        { new { id = new string('1', 32), type = "A", proxied = true, name = "private-dns.example", content = "203.0.113.99" }, new { id = new string('2', 32), type = "TXT", proxied = false, name = "private-txt.example", content = "PRIVATE_TXT_CONTENT" } }, result_info = new { page = 1, per_page = 100, count = 2, total_count = 2, total_pages = 1 } });
    if (path.EndsWith("/entrypoint", StringComparison.Ordinal)) return Json(Envelope(new { id = new string('3', 32), kind = "zone", phase = path.Contains("firewall_managed", StringComparison.Ordinal) ? "http_request_firewall_managed" : "http_request_firewall_custom", name = "PRIVATE_RULESET", rules = new object[]
        { new { id = new string('4', 32), action = "execute", enabled = true, expression = "PRIVATE_WAF_EXPRESSION", action_parameters = new { id = "PRIVATE_MANAGED_ID" } }, new { id = new string('5', 32), action = "skip", enabled = false, description = "PRIVATE_WAF_DESCRIPTION" } } }));
    if (path.EndsWith("/workers/routes", StringComparison.Ordinal)) return Json(Envelope(new[] { new { id = new string('6', 32), pattern = "private-worker.example/*", script = "PRIVATE_SCRIPT_NAME" } }));
    return Json(Descriptor(path.Split('/')[^1]));
}
async Task<AnalysisReport> Collect(FakeHandler handler, Dictionary<string, string>? options = null, string operation = "posture", string? token = "PRIVATE_TOKEN", CancellationToken cancellationToken = default)
{
    using var http = new HttpClient(handler);
    var provider = new CloudflarePostureProvider(http, name => name == "CLOUDFLARE_API_TOKEN" ? token : throw new Exception("Unexpected credential selector"));
    return await provider.CollectAsync(operation, options ?? Options(), cancellationToken);
}

var normal = new FakeHandler(Fixture);
var tls = await Collect(normal);
Check(tls.OperationSucceeded && State(tls) == "Complete", "Default TLS reads complete only with verified zone and all three settings");
Check(normal.Requests.Count == 4 && normal.Requests.All(r => r.Method == "GET" && r.Host == "api.cloudflare.com" && r.Port == 443), "TLS uses four fixed HTTPS GETs only");
Check(normal.Requests.All(r => r.Authorization == "Bearer PRIVATE_TOKEN" && !r.Uri.Contains("PRIVATE_TOKEN", StringComparison.Ordinal)), "Credential is sent only in the backend authorization header");
Check(normal.Requests[0].Uri.EndsWith("/zones/" + Zone, StringComparison.Ordinal), "Zone verification precedes setting reads");
Check(tls.Findings.Select(f => f.Code).Order().SequenceEqual(new[] { "CLOUDFLARE_LEGACY_TLS_MINIMUM", "CLOUDFLARE_WEAK_SSL_MODE", "CLOUDFLARE_ZONE_PAUSED" }), "Findings are based on explicit paused, SSL and minimum TLS configuration");
Check(Evidence(tls, "tls").GetProperty("observations").GetProperty("alwaysUseHttps").GetBoolean(), "Observed on retains a real boolean");
Check(!Raw(tls).Contains("private-zone.example", StringComparison.Ordinal) && !Raw(tls).Contains("PRIVATE_SETTING", StringComparison.Ordinal), "Arbitrary zone and setting fields never enter evidence");
Check(!ReportSecurity.Serialize(tls).Contains(Account, StringComparison.Ordinal) && !ReportSecurity.Serialize(tls).Contains(Zone, StringComparison.Ordinal), "Account and zone identities redact in exports");

var allHandler = new FakeHandler(Fixture);
var all = await Collect(allHandler, Options("tls,dns,waf,routes"));
Check(all.OperationSucceeded && Data(all).GetProperty("configurationEvidence").GetProperty("checks").GetArrayLength() == 4, "All selected checks are returned separately");
Check(allHandler.Requests.Count == 8, "All-check collection makes only the exact zone, setting, DNS, phase and routes reads");
var dns = Evidence(all, "dns").GetProperty("observations");
Check(dns.GetProperty("observedRecords").GetInt32() == 2 && dns.GetProperty("observedProxiedRecords").GetInt32() == 1 && dns.GetProperty("observedUnproxiedRecords").GetInt32() == 1, "DNS counters reflect observed rows and proxy booleans");
Check(dns.GetProperty("recordTypes").EnumerateArray().Select(item => item.GetProperty("type").GetString()).SequenceEqual(new[] { "A", "TXT" }), "DNS types are sorted safe categories");
var waf = Evidence(all, "waf").GetProperty("observations");
Check(waf.GetProperty("observedRulesets").GetInt32() == 2 && waf.GetProperty("observedRules").GetInt32() == 4 && waf.GetProperty("observedEnabledRules").GetInt32() == 2 && waf.GetProperty("observedDisabledRules").GetInt32() == 2, "WAF reports only observed entrypoints and explicit enabled booleans");
Check(Evidence(all, "routes").GetProperty("observations").GetProperty("observedRoutes").GetInt32() == 1, "Worker routes are counted without patterns or script names");
foreach (var privateText in new[] { "PRIVATE_TOKEN", "PRIVATE_TXT_CONTENT", "203.0.113.99", "private-dns.example", "private-txt.example", "PRIVATE_WAF_EXPRESSION", "PRIVATE_WAF_DESCRIPTION", "PRIVATE_MANAGED_ID", "PRIVATE_RULESET", "private-worker.example", "PRIVATE_SCRIPT_NAME" })
    Check(!Raw(all).Contains(privateText, StringComparison.Ordinal), "Configuration output excludes private data: " + privateText);
Check(all.Findings.All(f => !f.Code.Contains("WAF", StringComparison.Ordinal) && !f.Code.Contains("DNS", StringComparison.Ordinal)), "Observed WAF/DNS metadata is not a protection verdict");

foreach (var invalid in new[]
{
    new Dictionary<string,string>(), Options(zones: ""), Options(zones: Zone + "," + Zone), Options(zones: "https://127.0.0.1"),
    Options("tls,unknown"), Options("tls,tls"), Options(""), Options(" "), Options(zones: string.Join(',', Enumerable.Range(0, 21).Select(i => i.ToString("x32"))))
})
{
    var handler = new FakeHandler(Fixture); var report = await Collect(handler, invalid);
    Check(State(report) == "NotConfigured" && handler.Requests.Count == 0, "Invalid scope/check selection stays offline");
}
foreach (var value in new[] { "https://example.invalid", new string('a', 31), new string('a', 33), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/" })
{
    var options = Options(); options["account"] = value; var handler = new FakeHandler(Fixture);
    var report = await Collect(handler, options); Check(State(report) == "NotConfigured" && handler.Requests.Count == 0, "Account is a literal 32-character identifier");
}
var resourceOptions = Options(); resourceOptions["resource"] = Zone;
var resourceHandler = new FakeHandler(Fixture);
Check(State(await Collect(resourceHandler, resourceOptions)) == "NotConfigured" && resourceHandler.Requests.Count == 0, "Unsupported resource filters never widen the query");
var absentToken = new FakeHandler(Fixture);
Check(State(await Collect(absentToken, token: null)) == "NotConfigured" && absentToken.Requests.Count == 0, "Missing token never starts a request");
var unsafeToken = new FakeHandler(Fixture);
Check(State(await Collect(unsafeToken, token: "value\nheader")) == "NotConfigured" && unsafeToken.Requests.Count == 0, "Control characters in credentials are rejected before request construction");
foreach (var failure in new Exception[] { new IOException("PRIVATE_CREDENTIAL_ERROR"), new InvalidOperationException("PRIVATE_CREDENTIAL_ERROR"), new ArgumentException("PRIVATE_CREDENTIAL_ERROR") })
{
    var handler = new FakeHandler(Fixture);
    using var http = new HttpClient(handler);
    var report = await new CloudflarePostureProvider(http, _ => throw failure).CollectAsync("posture", Options());
    Check(State(report) == "NotConfigured" && handler.Requests.Count == 0 && !Raw(report).Contains("PRIVATE_CREDENTIAL_ERROR", StringComparison.Ordinal), "Unavailable credential selectors stay offline without exposing exception text");
}
var unsupported = new FakeHandler(Fixture);
Check(State(await Collect(unsupported, operation: "delete")) == "Unsupported" && unsupported.Requests.Count == 0, "Unsupported operations stay offline");

foreach (var mismatch in new[] { Descriptor(Other), Descriptor(Zone, Other) })
{
    var handler = new FakeHandler(_ => Json(mismatch)); var report = await Collect(handler, Options("tls,dns,waf,routes"));
    Check(!report.OperationSucceeded && State(report) == "PermissionDenied" && handler.Requests.Count == 1, "Unverified zone or account identity stops follow-up reads");
    Check(Data(report).GetProperty("resources").GetArrayLength() == 0 && report.Findings.Count == 0, "Scope mismatch never retains resources or findings");
}
foreach (var (status, state) in new[] { (HttpStatusCode.Forbidden, "PermissionDenied"), (HttpStatusCode.Unauthorized, "PermissionDenied"), (HttpStatusCode.TooManyRequests, "RateLimited"), (HttpStatusCode.InternalServerError, "Failed"), (HttpStatusCode.Redirect, "Failed") })
{
    var handler = new FakeHandler(_ => new(status) { Content = new StringContent("PRIVATE_PROVIDER_BODY"), Headers = { Location = new Uri("https://untrusted.invalid/") } });
    var report = await Collect(handler, Options(zones: Zone + "," + Other));
    Check(State(report) == state && handler.Requests.All(r => r.Host == "api.cloudflare.com"), "HTTP status preserves explicit coverage and fixed destination");
    Check(!Raw(report).Contains("PRIVATE_PROVIDER_BODY", StringComparison.Ordinal) && !Raw(report).Contains("untrusted.invalid", StringComparison.Ordinal), "Error bodies and redirect destinations are never emitted");
    if (status == HttpStatusCode.TooManyRequests) Check(handler.Requests.Count == 1, "Quota failure stops without retries or additional scopes");
}
var tlsDeniedHandler = new FakeHandler(request => request.RequestUri!.AbsolutePath.Contains("/settings/", StringComparison.Ordinal) ? new(HttpStatusCode.Forbidden) : Fixture(request));
var tlsDenied = await Collect(tlsDeniedHandler);
Check(State(tlsDenied) == "Partial" && Evidence(tlsDenied, "tls").GetProperty("state").GetString() == "permission_denied", "Verified scope with denied settings remains incomplete configuration evidence");
Check(!Evidence(tlsDenied, "tls").TryGetProperty("observations", out _), "Denied settings do not become zero or disabled observations");
var tlsPartial = await Collect(new FakeHandler(request => request.RequestUri!.AbsolutePath.EndsWith("/settings/ssl", StringComparison.Ordinal) ? new(HttpStatusCode.Forbidden) : Fixture(request)));
Check(State(tlsPartial) == "Partial" && Evidence(tlsPartial, "tls").GetProperty("observations").GetProperty("sslMode").ValueKind == JsonValueKind.Null, "A missing SSL setting remains explicit unknown alongside known observations");
Check(!tlsPartial.Findings.Any(f => f.Code == "CLOUDFLARE_WEAK_SSL_MODE"), "An unavailable SSL mode does not invent a weak-mode finding");
var partiallyThrottledHandler = new FakeHandler(request => request.RequestUri!.AbsolutePath.EndsWith("/settings/min_tls_version", StringComparison.Ordinal) ? new(HttpStatusCode.TooManyRequests) : Fixture(request));
var partiallyThrottled = await Collect(partiallyThrottledHandler, Options("tls,dns,waf,routes", Zone + "," + Other));
Check(partiallyThrottledHandler.Requests.Count == 3 && !partiallyThrottled.OperationSucceeded, "A quota rejection after a useful TLS setting stops all subsequent checks and zones");
Check(Data(partiallyThrottled).GetProperty("configurationEvidence").GetProperty("checks").EnumerateArray().Where(item => item.GetProperty("check").GetString() != "tls" || item.GetProperty("zoneId").GetString() == Other).All(item => item.GetProperty("state").GetString() == "not_requested"), "Unqueried checks after partial TLS throttling remain explicitly unrequested");

var wafMissing = await Collect(new FakeHandler(request => request.RequestUri!.AbsolutePath.EndsWith("/entrypoint", StringComparison.Ordinal) ? new(HttpStatusCode.NotFound) : Fixture(request)), Options("waf"));
Check(State(wafMissing) == "Partial" && Evidence(wafMissing, "waf").GetProperty("state").GetString() == "unavailable", "Missing WAF product/entrypoint is unavailable, not disabled");
Check(!Evidence(wafMissing, "waf").TryGetProperty("observations", out _) && wafMissing.Findings.All(f => !f.Code.Contains("WAF", StringComparison.Ordinal)), "Missing WAF never emits invented zero counters or findings");
var wrongPhase = await Collect(new FakeHandler(request => request.RequestUri!.AbsolutePath.EndsWith("/entrypoint", StringComparison.Ordinal) ? Json(Envelope(new { id = new string('4',32), kind = "zone", phase = "other", rules = Array.Empty<object>() })) : Fixture(request)), Options("waf"));
Check(!wrongPhase.OperationSucceeded && !Evidence(wrongPhase, "waf").TryGetProperty("observations", out _), "WAF phase identity is verified before observations");

var empty = await Collect(new FakeHandler(request => request.RequestUri!.AbsolutePath.EndsWith("/dns_records", StringComparison.Ordinal)
    ? Json(new { success = true, result = Array.Empty<object>(), result_info = new { page = 1, per_page = 100, count = 0, total_count = 0, total_pages = 1 } })
    : request.RequestUri.AbsolutePath.EndsWith("/workers/routes", StringComparison.Ordinal) ? Json(Envelope(Array.Empty<object>())) : Fixture(request)), Options("dns,routes"));
Check(empty.OperationSucceeded && Evidence(empty, "dns").GetProperty("observations").GetProperty("observedRecords").GetInt32() == 0 && Evidence(empty, "routes").GetProperty("observations").GetProperty("observedRoutes").GetInt32() == 0, "Explicit empty successful metadata reads retain genuine observed zero counts");
var missingPage = await Collect(new FakeHandler(request => request.RequestUri!.AbsolutePath.EndsWith("/dns_records", StringComparison.Ordinal) ? Json(Envelope(Array.Empty<object>())) : Fixture(request)), Options("dns"));
Check(!missingPage.OperationSucceeded && !Evidence(missingPage, "dns").TryGetProperty("observations", out _), "Missing DNS pagination metadata never establishes an empty complete list");
var unknownProxy = await Collect(new FakeHandler(request => request.RequestUri!.AbsolutePath.EndsWith("/dns_records", StringComparison.Ordinal) ? Json(new { success = true, result = new[] { new { id = new string('2',32), type = "A" } }, result_info = new { page = 1, per_page = 100, count = 1, total_count = 1, total_pages = 1 } }) : Fixture(request)), Options("dns"));
Check(!unknownProxy.OperationSucceeded && Evidence(unknownProxy, "dns").GetProperty("observations").GetProperty("unknownProxyRecords").GetInt32() == 1, "Missing proxy metadata remains unknown instead of false");

var pagedHandler = new FakeHandler(request =>
{
    if (!request.RequestUri!.AbsolutePath.EndsWith("/dns_records", StringComparison.Ordinal)) return Fixture(request);
    var page = request.RequestUri.Query.Contains("page=2&", StringComparison.Ordinal) ? 2 : 1;
    return Json(new { success = true, result = new[] { new { id = page.ToString("x32"), type = "A", proxied = true } }, result_info = new { page, per_page = 100, count = 1, total_count = 2, total_pages = 2 } });
});
var paged = await Collect(pagedHandler, Options("dns"));
Check(paged.OperationSucceeded && pagedHandler.Requests.Count == 3 && Evidence(paged, "dns").GetProperty("observations").GetProperty("observedRecords").GetInt32() == 2, "DNS follows fixed numeric pages with explicit pagination identity");
var repeatedHandler = new FakeHandler(request =>
{
    if (!request.RequestUri!.AbsolutePath.EndsWith("/dns_records", StringComparison.Ordinal)) return Fixture(request);
    var page = request.RequestUri.Query.Contains("page=2&", StringComparison.Ordinal) ? 2 : 1;
    return Json(new { success = true, result = new[] { new { id = new string('1',32), type = "A", proxied = true } }, result_info = new { page, per_page = 100, count = 1, total_count = 2, total_pages = 2 } });
});
var repeated = await Collect(repeatedHandler, Options("dns"));
Check(!repeated.OperationSucceeded && Evidence(repeated, "dns").GetProperty("observations").GetProperty("observedRecords").GetInt32() == 1, "Duplicate DNS rows are not counted twice or reported complete");
var missingRows = await Collect(new FakeHandler(request => request.RequestUri!.AbsolutePath.EndsWith("/dns_records", StringComparison.Ordinal)
    ? Json(new { success = true, result = new[] { new { id = new string('1', 32), type = "A", proxied = true } }, result_info = new { page = 1, per_page = 100, count = 1, total_count = 2, total_pages = 1 } })
    : Fixture(request)), Options("dns"));
Check(!missingRows.OperationSucceeded && Evidence(missingRows, "dns").GetProperty("state").GetString() == "partial", "A last DNS page with fewer rows than the stated total cannot establish complete enumeration");
foreach (var changePages in new[] { false, true })
{
    var handler = new FakeHandler(request =>
    {
        if (!request.RequestUri!.AbsolutePath.EndsWith("/dns_records", StringComparison.Ordinal)) return Fixture(request);
        var page = request.RequestUri.Query.Contains("page=2&", StringComparison.Ordinal) ? 2 : 1;
        return Json(new { success = true, result = new[] { new { id = page.ToString("x32"), type = "A", proxied = true } }, result_info = new { page, per_page = 100, count = 1, total_count = page == 2 && !changePages ? 3 : 2, total_pages = page == 2 && changePages ? 3 : 2 } });
    });
    var changed = await Collect(handler, Options("dns"));
    Check(!changed.OperationSucceeded && Evidence(changed, "dns").GetProperty("observations").GetProperty("observedRecords").GetInt32() == 1, "DNS totals that change between pages preserve only previously observed evidence and remain partial");
}
var uncertainEmpty = await Collect(new FakeHandler(request => request.RequestUri!.AbsolutePath.EndsWith("/dns_records", StringComparison.Ordinal)
    ? Json(new { success = true, result = Array.Empty<object>(), result_info = new { page = 1, per_page = 100, count = 0, total_count = 1, total_pages = 1 } })
    : Fixture(request)), Options("dns"));
Check(!uncertainEmpty.OperationSucceeded && !Evidence(uncertainEmpty, "dns").TryGetProperty("observations", out _), "An empty DNS page with unobserved declared rows does not become an observed zero");

var rowHandler = new FakeHandler(request =>
{
    if (!request.RequestUri!.AbsolutePath.EndsWith("/dns_records", StringComparison.Ordinal)) return Fixture(request);
    var text = request.RequestUri.Query.Split('&')[0].Split('=')[1]; var page = int.Parse(text);
    return Json(new { success = true, result = Enumerable.Range((page-1)*100,100).Select(i=>new { id=i.ToString("x32"),type="A",proxied=true }).ToArray(), result_info = new { page, per_page=100,count=100,total_count=1100,total_pages=11 } });
});
var boundedRows = await Collect(rowHandler, Options("dns,routes"));
Check(!boundedRows.OperationSucceeded && rowHandler.Requests.Count == 11 && Evidence(boundedRows, "dns").GetProperty("observations").GetProperty("observedRecords").GetInt32() == 1000, "DNS pages and aggregate rows are bounded");
Check(Evidence(boundedRows, "routes").GetProperty("state").GetString() == "not_requested", "Exhausted shared row budget omits later checks explicitly");
var zones = string.Join(',', Enumerable.Range(1,20).Select(i=>i.ToString("x32")));
var readHandler = new FakeHandler(Fixture);
var boundedReads = await Collect(readHandler, Options(zones: zones));
Check(!boundedReads.OperationSucceeded && readHandler.Requests.Count == 60, "Aggregate fixed HTTP read budget applies across all zones");
Check(Data(boundedReads).GetProperty("configurationEvidence").GetProperty("checks").EnumerateArray().Any(item=>item.GetProperty("state").GetString()=="not_requested"), "Unqueried scopes are not silently complete");
var huge = await Collect(new FakeHandler(_ => new(HttpStatusCode.OK) { Content = new StringContent(new string('x',4*1024*1024+1)) }));
Check(!huge.OperationSucceeded && State(huge) == "Partial", "Single-response byte limits fail closed before parsing oversized content");
var aggregateHandler = new FakeHandler(request =>
{
    var response=Fixture(request); var json=response.Content.ReadAsStringAsync().GetAwaiter().GetResult(); response.Dispose();
    return new(HttpStatusCode.OK) { Content=new StringContent(json[..^1]+",\"padding\":\""+new string('x',2*1024*1024)+"\"}") };
});
var aggregate = await Collect(aggregateHandler);
Check(!aggregate.OperationSucceeded && aggregateHandler.Requests.Count <= 4, "Aggregate response bytes bound multiple otherwise valid reads");
foreach (var invalidJson in new[] { "[]", "{}", "{\"success\":false,\"result\":{}}", "{\"success\":true,\"errors\":{},\"result\":{}}", "{\"success\":true,\"errors\":[{\"message\":\"PRIVATE_ERROR\"}],\"result\":{}}", "{\"success\":true,\"result\":{\"id\":\""+Zone+"\",\"id\":\""+Zone+"\",\"account\":{\"id\":\""+Account+"\"}}}" })
{
    var malformed=await Collect(new FakeHandler(_=>new(HttpStatusCode.OK){Content=new StringContent(invalidJson)}));
    Check(!malformed.OperationSucceeded && !Raw(malformed).Contains("PRIVATE_ERROR",StringComparison.Ordinal), "Malformed or explicitly errored envelopes cannot be complete observations");
}
using (var canceled=new CancellationTokenSource())
{
    canceled.Cancel(); var handler=new FakeHandler(Fixture);
    try { await Collect(handler,cancellationToken:canceled.Token); throw new Exception("Cancellation ignored"); }
    catch(OperationCanceledException) { Check(handler.Requests.Count==0,"Caller cancellation propagates before credential or network reads"); }
}
using (var cancelOnRead=new CancellationTokenSource())
{
    var handler=new FakeHandler(_=>{cancelOnRead.Cancel();throw new OperationCanceledException(cancelOnRead.Token);});
    try { await Collect(handler,cancellationToken:cancelOnRead.Token); throw new Exception("Cancellation ignored"); }
    catch(OperationCanceledException) { Check(handler.Requests.Count==1,"In-flight caller cancellation is propagated without follow-up queries"); }
}
Console.WriteLine($"PASS: {assertions} Cloudflare scoped configuration checks.");

sealed class FakeHandler(Func<HttpRequestMessage,HttpResponseMessage> response) : HttpMessageHandler
{
    public List<(string Method,string Host,int Port,string Uri,string? Authorization)> Requests { get; }=[];
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var uri=request.RequestUri!; Requests.Add((request.Method.Method,uri.Host,uri.Port,uri.AbsoluteUri,request.Headers.Authorization?.ToString()));
        return Task.FromResult(response(request));
    }
}
