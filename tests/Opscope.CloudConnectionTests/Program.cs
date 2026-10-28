using System.Text.Json;
using Opscope;
using Opscope.Api;
using Opscope.Cloud;

var assertions = 0;
void Assert(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); assertions++; }
static string Json(object? value) => JsonSerializer.Serialize(value, ReportSecurity.JsonOptions);
static CloudConnectionProvider Provider(CloudConnectionsView view, string id) => view.Providers.Single(provider => provider.ProviderId == id);
static AnalysisReport Report(string state, bool success = false, object? extra = null) => new("cloud.aws.inventory", DateTimeOffset.UtcNow, [], new { coverage = new { state }, extra }) { OperationSucceeded = success };
var requestedCredentials = new List<string>();
var requestedTools = new List<string>();
var secret = "NEVER_ECHO_CONNECTION_CREDENTIAL_VALUE";
var connections = new CloudConnections([
    "aws-scope-1/inventory", "aws-scope-1/health", "aws-scope-1/metrics", "aws-scope-1/inventory", "aws-scope-2/health",
    "gcp-scope-1/metrics", "scaleway-scope-1/networks", "scaleway-scope-1/metrics", "cloudflare-scope-1/posture",
    "cloudflare-scope-1/inventory", "kubernetes-scope-1/inventory", "alibaba-scope-1/inventory",
    "aws-scope-1/delete", "aws-scope-0/inventory", "aws-scope--1/inventory", "unknown/inventory", "../../aws/inventory", "aws-scope-1/inventory/extra", "aws-scope-1/<script>"
], name => { requestedCredentials.Add(name); return secret; }, tool => { requestedTools.Add(tool); return "available"; });
var view = connections.View();
Assert(view.Version == 1 && view.Mode == "guided-setup", "The readiness schema identifies a guided setup view.");
Assert(!view.RemoteRequestsMade && !view.AuthenticationActionsAvailable, "Readiness never claims to perform cloud requests or authenticate.");
Assert(view.Providers.Count == 12 && view.Providers.Select(provider => provider.ProviderId).Distinct().Count() == 12, "Every registry provider has one guide.");
Assert(view.Providers.All(provider => CloudProviderRegistry.IsKnownProvider(provider.ProviderId)), "Guides only describe registry providers.");
Assert(requestedTools.Order().SequenceEqual(new[] { "az", "aws", "gcloud", "oci", "openstack", "aliyun", "kubectl" }.Order()), "Only fixed cloud tool names are probed.");
Assert(requestedCredentials.Order().SequenceEqual(new[] { "DIGITALOCEAN_ACCESS_TOKEN", "HCLOUD_TOKEN", "CLOUDFLARE_API_TOKEN", "IBM_CLOUD_IAM_TOKEN", "SCW_SECRET_KEY", "SCW_COCKPIT_TOKEN" }.Order()), "Only named backend credentials are checked.");
Assert(!Json(view).Contains(secret, StringComparison.Ordinal), "Credential values never cross readiness boundary.");
Assert(Provider(view, "aws").CredentialStatus == "external-unverified" && Provider(view, "azure").CredentialStatus == "external-unverified", "Existing CLI/workload sessions are unverified without falsely assuming missing credentials.");
Assert(Provider(view, "aws").AccessStatus == "not-tested" && Provider(view, "aws").ScopeStatus == "configured", "Configured scope and credential presence do not establish cloud access.");
Assert(Provider(view, "cloudflare").CredentialStatus == "present" && Provider(view, "cloudflare").AccessStatus == "not-tested", "API token presence does not imply authentication.");
Assert(Provider(view, "cloudflare").ToolStatus == "not-required", "HTTP token adapters do not require a CLI.");
Assert(Provider(view, "azure").ScopeStatus == "missing" && Provider(view, "azure").TestActions.Count == 0, "Unconfigured scopes cannot be tested.");
Assert(Provider(view, "aws").TestActions.Select(action => action.ActionKey).SequenceEqual(new[] { "aws-scope-1/inventory", "aws-scope-2/health" }), "A single existing bounded read is chosen per scope, preferring inventory.");
Assert(Provider(view, "scaleway").TestActions.Single().Operation == "networks", "Networks is a safe configured fallback before metrics.");
Assert(Provider(view, "gcp").TestActions.Single().Operation == "metrics", "Metrics remains available when it is the sole configured safe read.");
Assert(Provider(view, "cloudflare").TestActions.Single().Operation == "inventory", "A posture read is not selected as a connection probe.");
Assert(view.Providers.SelectMany(provider => provider.TestActions).All(action => !action.ActionKey.Contains("delete", StringComparison.Ordinal) && !action.ActionKey.Contains('<')), "Unsupported and unsafe action keys never become test callbacks.");
Assert(Provider(view, "gcp").Requirements.Any(requirement => requirement.Kind == "external-auth" && requirement.Name == "Application Default Credentials" && requirement.Operations.Contains("metrics")), "GCP explicitly describes ADC separately.");
Assert(Provider(view, "gcp").Guide.Steps.Any(step => step.CommandTemplate == "gcloud auth login") && Provider(view, "gcp").Guide.Steps.Any(step => step.CommandTemplate == "gcloud auth application-default login"), "GCP CLI and ADC login templates remain distinct.");
Assert(Provider(view, "scaleway").Requirements.Any(requirement => requirement.Name == "SCW_COCKPIT_TOKEN" && requirement.Operations.SequenceEqual(new[] { "metrics" })), "Cockpit metrics need a separate token from Instance/VPC reads.");
Assert(!new CloudConnections(["scaleway-scope-1/networks"], _ => secret, _ => "available").View().Providers.SelectMany(provider => provider.Requirements).Any(requirement => requirement.Name == "SCW_COCKPIT_TOKEN"), "Cockpit setup is not required for a VPC-only scope.");
foreach (var provider in view.Providers)
{
    Assert(provider.AccessStatus != "connected" && provider.AccessStatus != "authenticated", provider.ProviderId + " cannot imply a universal connection from local setup.");
    Assert(Uri.TryCreate(provider.Guide.DocumentationUrl, UriKind.Absolute, out var docs) && docs.Scheme == "https" && docs.UserInfo.Length == 0, provider.ProviderId + " documentation uses an official fixed HTTPS URL.");
    Assert(provider.Guide.Steps.All(step => !step.Description.Contains(secret, StringComparison.Ordinal) && !(step.CommandTemplate ?? "").Contains(secret, StringComparison.Ordinal)), provider.ProviderId + " setup templates contain no backend credential.");
    if (provider.Guide.SignUpUrl is { } signUp) Assert(Uri.TryCreate(signUp, UriKind.Absolute, out var url) && url.Scheme == "https" && url.UserInfo.Length == 0, provider.ProviderId + " signup is an external HTTPS guide.");
}
Assert(Provider(view, "kubernetes").Guide.SignUpUrl is null && Provider(view, "openstack").Guide.SignUpUrl is null, "Private-cloud and cluster guides do not invent account registration services.");

foreach (var (value, expected) in new (string?, string)[] { (null, "missing"), ("", "missing"), ("   ", "missing"), ("token\nunsafe", "missing"), (new string('x', 16385), "missing"), (secret, "present") })
{
    var result = Provider(new CloudConnections(["cloudflare-scope-1/inventory"], _ => value, _ => "missing").View(), "cloudflare");
    Assert(result.CredentialStatus == expected && result.AccessStatus == "not-tested", "Presence validation never turns a token into verified authentication.");
    Assert(expected == "present" || result.Diagnostics.Any(diagnostic => diagnostic.Code.StartsWith("CREDENTIAL_", StringComparison.Ordinal)), "Missing credentials have a safe remediation.");
}
var broken = new CloudConnections(["aws-scope-1/inventory", "cloudflare-scope-1/inventory"], _ => throw new UnauthorizedAccessException(secret), _ => throw new IOException(secret)).View();
Assert(Provider(broken, "cloudflare").CredentialStatus == "unavailable" && Provider(broken, "aws").ToolStatus == "unknown", "Local setup failures yield unknown/unavailable rather than success.");
Assert(!Json(broken).Contains(secret, StringComparison.Ordinal), "Local probe exception details do not leak.");
foreach (var toolState in new[] { "missing", "untrusted", "available", "UNKNOWN_SECRET_PATH" })
{
    var result = Provider(new CloudConnections(["aws-scope-1/inventory"], _ => null, _ => toolState).View(), "aws");
    Assert(result.ToolStatus == (toolState == "UNKNOWN_SECRET_PATH" ? "unknown" : toolState), "Injected tool status is allowlisted.");
    Assert(result.AccessStatus == "not-tested" && !Json(result).Contains("UNKNOWN_SECRET_PATH", StringComparison.Ordinal), "An installed CLI is not a validated cloud identity or a path leak.");
}

var observed = DateTimeOffset.UtcNow.AddSeconds(-10);
object Coverage(string status, bool success = true, string action = "aws-scope-1/inventory", DateTimeOffset? time = null) => new
{
    actions = new[] { new { actionKey = action, status, lastObservedAtUtc = time ?? observed, operationSucceeded = success } }
};
foreach (var (state, success, expected) in new (string, bool, string)[]
{
    ("succeeded", true, "last-read-succeeded"), ("complete", true, "last-read-succeeded"), ("succeeded", false, "failed"), ("complete", false, "failed"),
    ("partial", true, "partial"), ("partial", false, "partial"), ("no_data", true, "no-data"), ("no-data", false, "failed"),
    ("not_configured", false, "not-configured"), ("permission-denied", false, "permission-denied"), ("rate_limited", false, "rate-limited"),
    ("timed_out", false, "timed-out"), ("unsupported", false, "unsupported"), ("unavailable", false, "failed"), ("not-requested", false, "not-tested")
})
{
    var provider = Provider(connections.View(Coverage(state, success)), "aws");
    Assert(provider.AccessStatus == expected, "Coverage maps " + state + "/" + success + " without claiming globally authenticated state.");
    Assert(expected == "not-tested" || provider.LastObservedAtUtc == observed && provider.LastActionKey == "aws-scope-1/inventory", "Access evidence keeps its exact configured action and timestamp.");
}
Assert(Provider(connections.View(Coverage("permission-denied", false)), "aws").Diagnostics.Any(diagnostic => diagnostic.Code == "PROVIDER_PERMISSION_DENIED"), "Provider denial explains selected scope and read permissions.");
Assert(Provider(connections.View(Coverage("not-configured", false)), "aws").Diagnostics.Any(diagnostic => diagnostic.Code == "PROVIDER_NOT_CONFIGURED"), "Operation-specific setup failure has guidance.");
Assert(Provider(connections.View(Coverage("succeeded", action: "aws-scope-999/inventory")), "aws").AccessStatus == "not-tested", "Unconfigured actions cannot establish access.");
Assert(Provider(connections.View(Coverage("succeeded", time: DateTimeOffset.UtcNow.AddMinutes(5))), "aws").AccessStatus == "not-tested", "Future evidence cannot establish access.");
Assert(Provider(connections.View(Coverage("succeeded", time: DateTimeOffset.UnixEpoch.AddSeconds(-1))), "aws").AccessStatus == "not-tested", "Invalid historical timestamps cannot establish access.");
var ordered = connections.View(new { actions = new[] {
    new { actionKey = "aws-scope-1/inventory", status = "succeeded", operationSucceeded = true, lastObservedAtUtc = observed.AddMinutes(-1) },
    new { actionKey = "aws-scope-2/health", status = "permission-denied", operationSucceeded = false, lastObservedAtUtc = observed }
} });
Assert(Provider(ordered, "aws").AccessStatus == "permission-denied" && Provider(ordered, "aws").LastActionKey == "aws-scope-2/health", "Latest actual read wins across aliases without claiming all scopes work.");
foreach (var malformed in new[] { "null", "42", "[]", "{\"actions\":{}}", "{\"actions\":[{\"actionKey\":\"aws-scope-1/inventory\",\"status\":\"succeeded\",\"operationSucceeded\":true}]}", "{\"actions\":[],\"Actions\":[]}" })
{
    using var document = JsonDocument.Parse(malformed);
    Assert(Provider(connections.View(document.RootElement), "aws").AccessStatus == "not-tested", "Malformed or ambiguous coverage fails closed.");
}
Assert(Provider(connections.View(new { ignored = new string('x', 1024 * 1024 + 1), actions = new[] { new { actionKey = "aws-scope-1/inventory", status = "succeeded", operationSucceeded = true, lastObservedAtUtc = observed } } }), "aws").AccessStatus == "not-tested", "Oversized coverage does not bypass the bounded view.");

foreach (var (state, success, status, code) in new (string, bool, int, string)[]
{
    ("not_configured", false, 409, "PROVIDER_NOT_CONFIGURED"), ("permission_denied", false, 424, "PROVIDER_PERMISSION_DENIED"),
    ("denied", false, 424, "PROVIDER_PERMISSION_DENIED"), ("rate_limited", false, 429, "PROVIDER_RATE_LIMITED"),
    ("timed_out", false, 504, "PROVIDER_TIMED_OUT"), ("unsupported", false, 501, "OPERATION_UNSUPPORTED"),
    ("failed", false, 502, "PROVIDER_UNAVAILABLE"), ("unavailable", false, 502, "PROVIDER_UNAVAILABLE"),
    ("partial", true, 200, "PROVIDER_PARTIAL"), ("partial", false, 200, "PROVIDER_PARTIAL"),
    ("no_data", true, 200, "PROVIDER_NO_DATA"), ("no_data", false, 502, "PROVIDER_UNAVAILABLE"),
    ("complete", true, 200, "PROVIDER_READ_COMPLETED"), ("complete", false, 502, "PROVIDER_UNAVAILABLE"),
    ("unknown", false, 502, "PROVIDER_UNAVAILABLE")
})
{
    var report = Report(state, success, secret);
    var problem = CloudConnections.Describe(report);
    Assert(CloudConnections.DetermineHttpStatus(report) == status && problem.Code == code, "Provider failure mapping is actionable for " + state + "/" + success + ".");
    Assert(problem.ProviderId == "aws" && !Json(problem).Contains(secret, StringComparison.Ordinal), "Problem details retain provider type without raw source errors.");
    Assert(problem.HttpStatus is not 401 and not 403, "Provider failure cannot log the browser out of its Opscope session.");
}
Assert(CloudConnections.DetermineHttpStatus(new AnalysisReport("host", observed, []) { OperationSucceeded = false }) == 502, "Failed report with no structured coverage remains failed.");
Assert(CloudConnections.Describe(new AnalysisReport("unsafe.provider", observed, [])).ProviderId is null, "Arbitrary report kinds do not create provider names.");
Assert(TrustedToolProbe.Inspect("/tmp/untrusted-tool") == "unknown" && TrustedToolProbe.Inspect("sh") == "unknown", "Tool probing rejects paths and non-cloud executables.");
foreach (var tool in requestedTools.Distinct()) Assert(new[] { "available", "missing", "untrusted", "unknown" }.Contains(TrustedToolProbe.Inspect(tool)), "Default tool probe exposes only availability and never a host path.");
Console.WriteLine($"PASS {assertions} cloud connection assertions");
