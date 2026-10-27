using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using Opscope;
using Opscope.Cloud;

const string Project = "example-project";
const string Number = "123456789012";
var checks = 0;
var options = new Dictionary<string, string> { ["project"] = Project };
var billingOptions = new Dictionary<string, string> { ["billing-project"] = "billing-project", ["billing-dataset"] = "billing_export", ["billing-table"] = "gcp_billing_export" };
var instant = DateTimeOffset.UtcNow.AddDays(-1);
var schema = new object[]
{
    Field("project", "RECORD", fields: [Field("id", "STRING")]), Field("cost", "FLOAT"), Field("currency", "STRING"),
    Field("usage_start_time", "TIMESTAMP"), Field("usage_end_time", "TIMESTAMP"),
    Field("credits", "RECORD", "REPEATED", [Field("amount", "FLOAT"), Field("name", "STRING")])
};
var metadata = new { type = "TABLE", tableReference = new { projectId = "billing-project", datasetId = "billing_export", tableId = "gcp_billing_export" }, schema = new { fields = schema } };
var tokenCalls = 0;
using (var unusedHttp = new HttpClient(new FixtureHandler(_ => throw new Exception("No request expected"))))
{
    var missing = await new GcpAdvancedReader(unusedHttp, (_, _) => { tokenCalls++; return Task.FromResult("fixture-token"); }).ReadBillingAsync([Project], options, CancellationToken.None);
    Check(missing.State == CoverageState.NotConfigured && missing.Billing!.CurrencySubtotals.Count == 0 && tokenCalls == 0, "Billing requires explicit existing-table configuration before authentication; no zero totals");
}

foreach (var boundProject in new[] { "projects/" + Number, "projects/" + Project, "//cloudresourcemanager.googleapis.com/projects/" + Number, "//cloudresourcemanager.googleapis.com/projects/" + Project })
{
    var handler = new FixtureHandler(request => request.RequestUri!.Host == "cloudresourcemanager.googleapis.com" ? Ok(ProjectDescriptor()) : Ok(new { listFindingsResults = new[] { SecurityFinding("finding-1", boundProject) } }));
    using var client = new HttpClient(handler);
    var result = await Reader(client).ReadSccAsync(Project, CancellationToken.None);
    Check(result.State == CoverageState.Complete && result.Scc!.FindingsCount == 1 && result.Findings.Single().Severity == FindingSeverity.Critical, "SCC binds full and relative resource project identities and retains active severity");
    Check(handler.Requests.All(request => request.Method == HttpMethod.Get && request.Uri.Scheme == "https") && handler.Requests.Count == 2 && handler.Requests[1].Uri.AbsolutePath == "/v1/projects/" + Number + "/sources/-/findings", "SCC uses verified numeric project scope and fixed GET routes");
    var redacted = ReportSecurity.Serialize(new("gcp.scc", DateTimeOffset.UtcNow, result.Findings, result.Scc, result.Warnings));
    Check(!redacted.Contains(Project, StringComparison.Ordinal) && !redacted.Contains("private-instance", StringComparison.Ordinal) && !redacted.Contains("RAW-SECRET", StringComparison.Ordinal), "SCC projections omit raw provider fields and redact project/resource finding text");
}

var crossScope = new FixtureHandler(request => request.RequestUri!.Host == "cloudresourcemanager.googleapis.com" ? Ok(ProjectDescriptor()) : Ok(new { listFindingsResults = new[] { SecurityFinding("finding-1", "//untrusted.invalid/projects/" + Number), SecurityFinding("finding-2", "projects/999999999999") } }));
using (var client = new HttpClient(crossScope))
{
    var result = await Reader(client).ReadSccAsync(Project, CancellationToken.None);
    Check(result.State == CoverageState.Partial && result.Scc!.FindingsCount == 0, "SCC rejects foreign projects and lookalike resource-name hosts");
}
var wrongDescriptor = new FixtureHandler(_ => Ok(new { projectId = "another-project", name = "projects/" + Number }));
using (var client = new HttpClient(wrongDescriptor))
{
    var result = await Reader(client).ReadSccAsync(Project, CancellationToken.None);
    Check(result.State == CoverageState.Failed && wrongDescriptor.Requests.Count == 1, "An unbound Resource Manager identity cannot issue a finding query");
}
var repeated = new FixtureHandler(request => request.RequestUri!.Host == "cloudresourcemanager.googleapis.com" ? Ok(ProjectDescriptor()) : Ok(new { listFindingsResults = new[] { SecurityFinding("same-finding", "projects/" + Number) }, nextPageToken = "repeat" }));
using (var client = new HttpClient(repeated))
{
    var result = await Reader(client).ReadSccAsync(Project, CancellationToken.None);
    Check(result.State == CoverageState.Partial && result.Scc!.FindingsCount == 1 && repeated.Requests.Count == 3, "Repeated SCC cursors stop; duplicate finding IDs are not counted twice");
}
foreach (var status in new[] { HttpStatusCode.Forbidden, HttpStatusCode.TooManyRequests, HttpStatusCode.Redirect })
{
    var handler = new FixtureHandler(_ => new(status) { Content = new StringContent("RAW-SECRET-BODY"), Headers = { Location = new("https://untrusted.invalid/") } });
    using var client = new HttpClient(handler);
    var result = await Reader(client).ReadSccAsync(Project, CancellationToken.None);
    Check(result.State == (status == HttpStatusCode.Forbidden ? CoverageState.PermissionDenied : status == HttpStatusCode.TooManyRequests ? CoverageState.RateLimited : CoverageState.Failed) && handler.Requests.Count == 1, "SCC denial/rate-limit/redirect remain distinct and do not cause request retries");
    Check(!JsonSerializer.Serialize(result).Contains("RAW-SECRET", StringComparison.Ordinal), "Provider error bodies are never exported");
}
using (var client = new HttpClient(new FixtureHandler(_ => new(HttpStatusCode.OK) { Content = new StringContent(new string('x', 4 * 1024 * 1024 + 1)) })))
    Check((await Reader(client).ReadSccAsync(Project, CancellationToken.None)).State == CoverageState.Failed, "SCC rejects oversized response bodies");

var rows = new object[]
{
    BillingRow(Project, "12.50", "EUR", "-2.50"), BillingRow(Project, "4.25", "EUR", null), BillingRow(Project, "7.00", "USD", null),
    BillingRow("other-project", "9000", "EUR", null), BillingRow(Project, "NaN", "EUR", null)
};
var billingHandler = new FixtureHandler(request => request.RequestUri!.AbsolutePath.EndsWith("/data", StringComparison.Ordinal) ? Ok(new { rows }) : Ok(metadata));
using (var client = new HttpClient(billingHandler))
{
    var result = await Reader(client).ReadBillingAsync([Project], billingOptions, CancellationToken.None);
    var evidence = result.Billing!;
    Check(result.State == CoverageState.Partial && !evidence.IsComplete && evidence.RowsRead == 5 && evidence.MatchedRows == 3, "Billing reports bounded observed rows and rejects malformed monetary values");
    Check(evidence.CurrencySubtotals.Count == 2 && evidence.CurrencySubtotals.Single(total => total.Currency == "EUR") is { ObservedCost: 16.75m, ObservedCredits: -2.50m, ObservedNetCost: 14.25m }, "Billing keeps independent currencies and applies observed credits using decimal arithmetic");
    Check(billingHandler.Requests.All(request => request.Method == HttpMethod.Get && request.Uri.Host == "bigquery.googleapis.com" && !request.Uri.AbsolutePath.Contains("jobs", StringComparison.Ordinal) && !request.Uri.AbsolutePath.Contains("queries", StringComparison.Ordinal)), "Billing reads metadata/tabledata only; no BigQuery jobs, SQL or configuration writes");
    Check(evidence.PeriodStartUtc is not null && evidence.PeriodEndUtc is not null, "Billing reports the actual observed usage interval");
    var output = ReportSecurity.Serialize(new("gcp.cost", DateTimeOffset.UtcNow, result.Findings, evidence, result.Warnings));
    Check(!output.Contains("billing-project", StringComparison.Ordinal) && !output.Contains("gcp_billing_export", StringComparison.Ordinal), "Billing table identity is redacted from shared output");
}

var replay = new FixtureHandler(request => request.RequestUri!.AbsolutePath.EndsWith("/data", StringComparison.Ordinal) ? Ok(new { rows = new[] { BillingRow(Project, "5", "EUR", null) }, pageToken = "repeat" }) : Ok(metadata));
using (var client = new HttpClient(replay))
{
    var result = await Reader(client).ReadBillingAsync([Project], billingOptions, CancellationToken.None);
    Check(result.Billing!.MatchedRows == 1 && result.Billing.CurrencySubtotals.Single().ObservedCost == 5 && replay.Requests.Count == 3, "A repeated billing continuation page is omitted before duplicate amounts are counted");
}
var wrongTable = new FixtureHandler(_ => Ok(new { type = "VIEW", tableReference = new { projectId = "billing-project", datasetId = "billing_export", tableId = "gcp_billing_export" }, schema = new { fields = schema } }));
using (var client = new HttpClient(wrongTable))
{
    var result = await Reader(client).ReadBillingAsync([Project], billingOptions, CancellationToken.None);
    Check(result.State == CoverageState.Failed && result.Billing!.CurrencySubtotals.Count == 0 && wrongTable.Requests.Count == 1, "A view or mismatched table cannot trigger a data read or query fallback");
}
var absentCredits = new FixtureHandler(_ => Ok(new { type = "TABLE", tableReference = new { projectId = "billing-project", datasetId = "billing_export", tableId = "gcp_billing_export" }, schema = new { fields = schema.Take(5).ToArray() } }));
using (var client = new HttpClient(absentCredits))
{
    var result = await Reader(client).ReadBillingAsync([Project], billingOptions, CancellationToken.None);
    Check(result.State == CoverageState.Failed && result.Billing!.CurrencySubtotals.Count == 0 && absentCredits.Requests.Count == 1, "Missing credit schema cannot be interpreted as zero credits or a net-cost subtotal");
}
using (var client = new HttpClient(new FixtureHandler(request => request.RequestUri!.AbsolutePath.EndsWith("/data", StringComparison.Ordinal) ? Ok(new { rows = new[] { BillingRow("other-project", "99", "EUR", null) } }) : Ok(metadata))))
{
    var result = await Reader(client).ReadBillingAsync([Project], billingOptions, CancellationToken.None);
    Check(result.Billing!.MatchedRows == 0 && result.Billing.CurrencySubtotals.Count == 0 && result.Warnings.Any(text => text.Contains("not zero", StringComparison.Ordinal)), "No matching authorized billing rows means unavailable amounts, never a zero bill");
}
using (var client = new HttpClient(new FixtureHandler(request => request.RequestUri!.AbsolutePath.EndsWith("/data", StringComparison.Ordinal)
    ? Ok(new { rows = new[] { Row(Row(Project), "11", "EUR", instant.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), instant.AddHours(1).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), new[] { new { v = Row("invalid-credit", "RAW-SECRET") } }) } }) : Ok(metadata))))
{
    var result = await Reader(client).ReadBillingAsync([Project], billingOptions, CancellationToken.None);
    Check(result.Billing!.CurrencySubtotals.Count == 0 && result.Billing.MatchedRows == 0 && result.Warnings.Any(warning => warning.Contains("credit", StringComparison.Ordinal)), "Malformed credit evidence omits the whole row instead of overstating net cost");
}
using (var client = new HttpClient(new FixtureHandler(request => request.RequestUri!.AbsolutePath.EndsWith("/data", StringComparison.Ordinal)
    ? Ok(new { rows = new[] { Row(Row(Project), "11", "EUR", instant.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), instant.AddHours(1).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), null), BillingRow(Project, "3", "EUR", null) } }) : Ok(metadata))))
{
    var result = await Reader(client).ReadBillingAsync([Project], billingOptions, CancellationToken.None);
    Check(result.Billing!.MatchedRows == 1 && result.Billing.CurrencySubtotals.Single().ObservedNetCost == 3, "Null credit evidence is omitted, while an explicit empty repeated-credit array represents observed zero credits");
}
var boundedRows = Enumerable.Range(0, 1001).Select(_ => BillingRow(Project, "1", "EUR", null)).ToArray();
using (var client = new HttpClient(new FixtureHandler(request => request.RequestUri!.AbsolutePath.EndsWith("/data", StringComparison.Ordinal) ? Ok(new { rows = boundedRows }) : Ok(metadata))))
{
    var result = await Reader(client).ReadBillingAsync([Project], billingOptions, CancellationToken.None);
    Check(result.Billing!.RowsRead == 1000 && result.Billing.CurrencySubtotals.Single().ObservedCost == 1000 && !result.Billing.IsComplete, "Billing row caps apply before parsing and summing retained amounts");
}
using (var cancelled = new CancellationTokenSource())
using (var client = new HttpClient(new FixtureHandler(_ => throw new Exception("Cancelled reads must not issue requests"))))
{
    cancelled.Cancel();
    try { await Reader(client).ReadSccAsync(Project, cancelled.Token); throw new Exception("Caller cancellation swallowed"); }
    catch (OperationCanceledException) { Check(true, "Caller cancellation is propagated without converting it to successful empty SCC evidence"); }
}
foreach (var option in new[] { "billing-dataset", "billing-table" })
{
    var invalidOptions = new Dictionary<string, string>(billingOptions) { [option] = "../../other;SELECT*" };
    using var client = new HttpClient(new FixtureHandler(_ => throw new Exception("Invalid identifiers must make no request")));
    try { await Reader(client).ReadBillingAsync([Project], invalidOptions, CancellationToken.None); throw new Exception("Unsafe table identifier accepted"); }
    catch (ArgumentException) { Check(true, "Unsafe dataset/table identifiers are rejected before provider calls"); }
}

var servicesRunner = new ServicesRunner();
var serviceProvider = new GcpProvider(servicesRunner);
var serviceReport = await serviceProvider.CollectAsync("services", options);
var serviceData = JsonSerializer.SerializeToElement(serviceReport.Data, ReportSecurity.JsonOptions);
Check(serviceReport.OperationSucceeded && serviceData.GetProperty("resources").GetArrayLength() == 3 && servicesRunner.Calls.Count == 4, "Default service metadata reads GKE, SQL and Storage after binding the project descriptor");
Check(servicesRunner.Calls.All(args => { var prefix = args[0] == "projects" ? "projects describe" : string.Join(' ', args.Take(3)); return args[args.ToList().IndexOf("--format") + 1] == AdditionalCloudCommandRunner.GcpProjection(prefix); }), "Every service and project descriptor request uses its closed source-field projection");
var serviceOutput = ReportSecurity.Serialize(serviceReport);
Check(!serviceOutput.Contains("RAW-SECRET", StringComparison.Ordinal) && !serviceOutput.Contains("private-bucket", StringComparison.Ordinal) && !serviceOutput.Contains(Project, StringComparison.Ordinal), "Service projections omit pod/env/object data and redact names");
Check(serviceData.GetProperty("resources").EnumerateArray().Single(resource => resource.GetProperty("type").GetString() == "sql.instance").GetProperty("properties").GetProperty("backupsEnabled").GetBoolean(), "SQL backup configuration is reported as configuration evidence");
var runOptions = new Dictionary<string, string>(options) { ["gcp-services"] = "run", ["region"] = "europe-west1" };
var runReport = await serviceProvider.CollectAsync("services", runOptions);
Check(runReport.OperationSucceeded && servicesRunner.Calls.Last().Contains("--region"), "Cloud Run metadata uses only the explicitly configured region");
var priorCalls = servicesRunner.Calls.Count;
try { await serviceProvider.CollectAsync("services", new Dictionary<string, string>(options) { ["gcp-services"] = "run" }); throw new Exception("Unscoped Cloud Run accepted"); }
catch (ArgumentException) { Check(servicesRunner.Calls.Count == priorCalls, "Missing Run region is rejected before any project or service query"); }
var wrongServices = new ServicesRunner { ForeignSql = true };
var partialServices = await new GcpProvider(wrongServices).CollectAsync("services", options);
Check(!partialServices.OperationSucceeded && JsonSerializer.SerializeToElement(partialServices.Data, ReportSecurity.JsonOptions).GetProperty("resources").GetArrayLength() == 2, "Foreign service project rows are omitted with partial coverage");
AdditionalCloudCommandRunner.ValidateArguments("gcloud", ["projects", "describe", Project, "--format", AdditionalCloudCommandRunner.GcpProjection("projects describe")!]);
AdditionalCloudCommandRunner.ValidateArguments("gcloud", ["run", "services", "list", "--project", Project, "--region", "europe-west1", "--format", AdditionalCloudCommandRunner.GcpProjection("run services list")!]);
foreach (var (command, format) in new[] { ("run services list", "json"), ("run services list", "json(spec.template.spec.containers.env)"), ("container clusters list", "json(masterAuth)"), ("sql instances list", "json(rootPassword)"), ("storage buckets list", "json(labels)") })
{
    try { AdditionalCloudCommandRunner.ValidateArguments("gcloud", command.Split(' ').Concat(new[] { "--project", Project, "--format", format }).ToArray()); throw new Exception("Unprojected or secret-bearing service format accepted"); }
    catch (InvalidOperationException) { Check(true, "The runner rejects arbitrary full/specification/credential projection fields"); }
}
try { AdditionalCloudCommandRunner.ValidateArguments("gcloud", ["projects", "describe", "--impersonate-service-account", "private@example.invalid"]); throw new Exception("Project option expansion accepted"); }
catch (InvalidOperationException) { Check(true, "Project identity command grammar accepts only literal project IDs"); }
Console.WriteLine($"PASS: {checks} advanced Google Cloud scope, SCC, billing, service projection and transport assertions.");

void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); checks++; }
GcpAdvancedReader Reader(HttpClient client) => new(client, (_, ct) => { ct.ThrowIfCancellationRequested(); return Task.FromResult("fixture-access-token"); });
object ProjectDescriptor() => new { projectId = Project, name = "projects/" + Number };
object SecurityFinding(string id, string boundProject) => new
{
    finding = new { name = "projects/" + Number + "/sources/42/findings/" + id, resourceName = "private-instance", category = "PUBLIC_IP_ADDRESS", severity = "HIGH", state = "ACTIVE", eventTime = instant.ToString("O"), sourceProperties = new { secret = "RAW-SECRET" } },
    resource = new { projectName = boundProject, name = "//compute.googleapis.com/projects/" + Project + "/zones/europe-west1-b/instances/private-instance" }
};
object BillingRow(string project, string cost, string currency, string? credit) => Row(Row(project), cost, currency, instant.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), instant.AddHours(1).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), credit is null ? System.Array.Empty<object>() : new object[] { new { v = Row(credit, "private-credit-description") } });
static object Row(params object?[] values) => new { f = values.Select(value => new { v = value }).ToArray() };
static object Field(string name, string type, string mode = "NULLABLE", object[]? fields = null) => fields is null ? new Dictionary<string, object> { ["name"] = name, ["type"] = type, ["mode"] = mode } : new Dictionary<string, object> { ["name"] = name, ["type"] = type, ["mode"] = mode, ["fields"] = fields };
static HttpResponseMessage Ok(object value) => new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json") };

sealed class FixtureHandler(Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
{
    public List<(Uri Uri, HttpMethod Method)> Requests { get; } = [];
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    { cancellationToken.ThrowIfCancellationRequested(); Requests.Add((request.RequestUri!, request.Method)); return Task.FromResult(response(request)); }
}
sealed class ServicesRunner : ICloudCommandRunner
{
    public List<IReadOnlyList<string>> Calls { get; } = [];
    public bool ForeignSql { get; init; }
    public Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> args, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); Calls.Add(args.ToArray());
        object result = args[0] switch
        {
            "projects" => new { projectId = "example-project", projectNumber = "123456789012" },
            "container" => new object[] { new { name = "private-cluster", location = "europe-west1-b", selfLink = "https://container.googleapis.com/v1/projects/example-project/locations/europe-west1-b/clusters/private-cluster", status = "RUNNING", currentMasterVersion = "1.33.1", currentNodeCount = 2, nodePools = new object[] { new { config = new { env = "RAW-SECRET" } } } } },
            "sql" => new object[] { new { name = "private-sql", project = ForeignSql ? "other-project" : "example-project", region = "europe-west1", selfLink = "https://sqladmin.googleapis.com/sql/v1beta4/projects/example-project/instances/private-sql", state = "RUNNABLE", settings = new { tier = "db-custom-2", availabilityType = "REGIONAL", backupConfiguration = new { enabled = true }, userLabels = new { secret = "RAW-SECRET" } } } },
            "run" => new object[] { new { metadata = new { name = "private-service", @namespace = "123456789012", annotations = new Dictionary<string, string> { ["run.googleapis.com/ingress"] = "internal" } }, status = new { latestReadyRevisionName = "private-revision", conditions = new[] { new { type = "Ready", status = "True" } }, url = "https://private.invalid/" }, spec = new { env = "RAW-SECRET" } } },
            _ => new object[] { new { name = "private-bucket", project_number = "123456789012", location = "EUROPE-WEST1", uniform_bucket_level_access = true, public_access_prevention = "enforced", secret = "RAW-SECRET" } }
        };
        return Task.FromResult(JsonSerializer.SerializeToElement(result));
    }
}
