using System.Text.Json;
using Opscope.Cloud;

namespace Opscope.Api;

/// <summary>Guided connection setup. Presence checks never authenticate, contact a cloud or disclose credentials.</summary>
public sealed class CloudConnections
{
    private readonly IReadOnlyList<CloudConnectionTestAction> configured;
    private readonly Func<string, string?> credentialSource;
    private readonly Func<string, string> toolProbe;
    private static readonly string[] SafeTests = ["inventory", "health", "networks", "metrics"];
    private const int MaximumActions = 512;

    public CloudConnections(IEnumerable<string>? configuredActions = null, Func<string, string?>? credentialSource = null, Func<string, string>? toolProbe = null)
    {
        configured = (configuredActions ?? []).Take(MaximumActions).Select(ParseAction).Where(action => action is not null)
            .Select(action => action!).DistinctBy(action => action.ActionKey, StringComparer.Ordinal).OrderBy(action => action.ActionKey, StringComparer.Ordinal).ToArray();
        this.credentialSource = credentialSource ?? Environment.GetEnvironmentVariable;
        this.toolProbe = toolProbe ?? TrustedToolProbe.Inspect;
    }

    public CloudConnectionsView View(object? coverage = null)
    {
        var now = DateTimeOffset.UtcNow;
        var observations = ReadObservations(coverage, now);
        var providers = new List<CloudConnectionProvider>();
        foreach (var definition in Definitions)
        {
            var descriptor = CloudProviderRegistry.GetDescriptor(definition.Id);
            var actions = configured.Where(action => CloudWorkspace.ProviderId(action.ScopeAlias) == definition.Id).ToArray();
            var operations = actions.Select(action => action.Operation).Distinct(StringComparer.Ordinal).ToArray();
            var requirements = new List<CloudConnectionRequirement>();
            var diagnostics = new List<CloudConnectionDiagnostic>();
            var tool = definition.Tool is null ? "not-required" : Probe(definition.Tool);
            if (definition.Tool is not null)
            {
                requirements.Add(new("tool", definition.Tool, tool, definition.Id == "gcp" ? ["inventory", "posture", "services", "health", "vm", "bundle", "drift"] : operations));
                if (tool is "missing" or "untrusted" or "unknown") diagnostics.Add(new("CLI_" + tool.Replace('-', '_').ToUpperInvariant(), "warning",
                    "The provider CLI is missing, untrusted or could not be checked.", "Install the official CLI in a trusted location on the host running Opscope."));
            }
            var credential = "external-unverified";
            foreach (var slot in definition.Tokens)
            {
                var state = Presence(slot);
                requirements.Add(new("credential", slot, state, operations));
                credential = state;
                if (state != "present") diagnostics.Add(new("CREDENTIAL_" + state.ToUpperInvariant(), "warning",
                    "A required backend credential is missing or could not be checked.", "Configure the named backend environment variable on the host running Opscope. Never paste credentials into reports or share them with support."));
            }
            if (definition.Tokens.Length == 0) requirements.Add(new("external-auth", definition.AuthKind, "external-unverified", operations));
            if (definition.Id == "gcp")
                requirements.Add(new("external-auth", "Application Default Credentials", "external-unverified", ["metrics", "health", "bundle", "scc", "cost", "patches"]));
            if (definition.Id == "scaleway" && operations.Contains("metrics", StringComparer.Ordinal))
            {
                var state = Presence("SCW_COCKPIT_TOKEN");
                requirements.Add(new("credential", "SCW_COCKPIT_TOKEN", state, ["metrics"]));
                if (state != "present") diagnostics.Add(new("METRICS_CREDENTIAL_REQUIRED", "warning", "Cockpit metrics require their own existing read token.", "Configure SCW_COCKPIT_TOKEN for the selected existing Cockpit source; the Instance API key alone does not provide metrics access."));
            }
            if (actions.Length == 0) diagnostics.Add(new("SCOPE_REQUIRED", "info", "No read scope is configured for this provider.", "Start Opscope with the explicit provider and authorized scope shown in this guide."));
            var last = observations.Where(observation => actions.Any(action => action.ActionKey == observation.ActionKey))
                .OrderByDescending(observation => observation.ObservedAtUtc).ThenBy(observation => observation.ActionKey, StringComparer.Ordinal).FirstOrDefault();
            if (last?.Status == "permission-denied") diagnostics.Add(new("PROVIDER_PERMISSION_DENIED", "warning", "The last provider read was denied.", "Check the selected account, scope and operation-specific read permissions. Signing in alone does not grant those permissions."));
            if (last?.Status == "not-configured") diagnostics.Add(new("PROVIDER_NOT_CONFIGURED", "warning", "The last provider read lacked required setup.", "Check the operation-specific scope and authentication requirements, including ADC or optional monitoring configuration."));
            var testActions = actions.GroupBy(action => action.ScopeAlias, StringComparer.Ordinal)
                .Select(group => SafeTests.Select(operation => group.FirstOrDefault(action => action.Operation == operation)).FirstOrDefault(action => action is not null))
                .Where(action => action is not null).Select(action => action!).ToArray();
            providers.Add(new(definition.Id, descriptor.DisplayName, descriptor.Category, definition.AuthKind,
                actions.Length == 0 ? "missing" : "configured", credential, tool, last?.Status ?? "not-tested", last?.ActionKey, last?.ObservedAtUtc,
                requirements, diagnostics, new(definition.SignUp, definition.Console, definition.Docs, definition.ScopeFields, definition.Steps), testActions));
        }
        return new(1, now, false, false, "guided-setup", providers);
    }

    private string Probe(string tool)
    {
        try
        {
            var state = toolProbe(tool);
            return state is "available" or "missing" or "untrusted" ? state : "unknown";
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException or System.Security.SecurityException)
        { return "unknown"; }
    }

    private string Presence(string name)
    {
        try
        {
            var value = credentialSource(name);
            return string.IsNullOrWhiteSpace(value) || value.Length > 16384 || value.Any(char.IsControl) ? "missing" : "present";
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException or System.Security.SecurityException)
        { return "unavailable"; }
    }

    public static int DetermineHttpStatus(AnalysisReport report) => Describe(report).HttpStatus;

    public static CloudConnectionFailure Describe(AnalysisReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var state = "";
        using (var document = Document(report.Data, 8 * 1024 * 1024, 48))
            if (document is not null) state = Normalize(Text(Property(document.RootElement, "coverage"), "state"));
        var (status, code, message, remediation) = state switch
        {
            "notconfigured" => (409, "PROVIDER_NOT_CONFIGURED", "This provider read needs configuration.", "Open Connections and check the provider, authorized scope, host credentials and operation-specific requirements."),
            "permissiondenied" or "denied" => (424, "PROVIDER_PERMISSION_DENIED", "The provider denied this read.", "Check the selected account, scope and read permissions. The Opscope session remains separate from provider authentication."),
            "ratelimited" => (429, "PROVIDER_RATE_LIMITED", "The provider limited this read.", "Wait before retrying. Signing in again does not resolve a provider quota limit."),
            "timedout" => (504, "PROVIDER_TIMED_OUT", "The provider read exceeded its deadline.", "Check provider connectivity and retry a smaller configured scope."),
            "unsupported" => (501, "OPERATION_UNSUPPORTED", "This adapter does not implement the selected read.", "Choose an operation advertised by the provider catalog."),
            "failed" or "unavailable" => (502, "PROVIDER_UNAVAILABLE", "The provider read could not complete.", "Open Connections to check the host CLI, credentials and selected scope. Provider error bodies are omitted."),
            "partial" => (200, "PROVIDER_PARTIAL", "The read returned incomplete evidence.", "Review each source and its coverage. Missing observations do not prove a healthy or empty account."),
            "nodata" when report.OperationSucceeded => (200, "PROVIDER_NO_DATA", "The selected read returned no observations.", "Check source availability, scope and observation window. No observations do not imply zero usage or compliance."),
            _ when report.OperationSucceeded => (200, "PROVIDER_READ_COMPLETED", "The provider read completed.", "Review its stated coverage and observation time; this does not certify the whole account."),
            _ => (502, "PROVIDER_UNAVAILABLE", "The provider read could not complete.", "Open Connections and review the selected operation, host setup and coverage.")
        };
        var parts = report.Kind.Replace('.', '/').Split('/');
        var provider = parts.Length >= 2 && parts[0] == "cloud" && CloudProviderRegistry.IsKnownProvider(parts[1]) ? parts[1] : null;
        return new(status, code, message, remediation, status == 200 ? "review-coverage" : "open-connections", provider);
    }

    private static CloudConnectionTestAction? ParseAction(string key)
    {
        if (key is null || key.Length > 128) return null;
        var parts = key.Split('/');
        return parts.Length == 2 && CloudWorkspace.ProviderId(parts[0]) is { } provider && CloudProviderRegistry.SupportsOperation(provider, parts[1])
            ? new(key, parts[1], parts[0]) : null;
    }

    private IReadOnlyList<AccessObservation> ReadObservations(object? coverage, DateTimeOffset now)
    {
        var results = new List<AccessObservation>();
        using var document = Document(coverage, 1024 * 1024, 16);
        if (document is null) return results;
        var actions = Property(document.RootElement, "actions");
        if (actions.ValueKind != JsonValueKind.Array || actions.GetArrayLength() > MaximumActions) return results;
        foreach (var item in actions.EnumerateArray())
        {
            var action = Text(item, "actionKey");
            var time = Property(item, "lastObservedAtUtc");
            if (!configured.Any(candidate => candidate.ActionKey == action) || time.ValueKind != JsonValueKind.String || !time.TryGetDateTimeOffset(out var observed) || observed < DateTimeOffset.UnixEpoch || observed > now.AddMinutes(2)) continue;
            var success = Property(item, "operationSucceeded").ValueKind == JsonValueKind.True;
            var state = Normalize(Text(item, "status"));
            var mapped = state switch
            {
                "succeeded" or "complete" or "success" => success ? "last-read-succeeded" : "failed",
                "partial" => "partial", "nodata" => success ? "no-data" : "failed", "notconfigured" => "not-configured",
                "permissiondenied" or "denied" => "permission-denied", "ratelimited" => "rate-limited", "timedout" => "timed-out",
                "unsupported" => "unsupported", "failed" or "unavailable" => "failed", _ => "not-tested"
            };
            if (mapped != "not-tested") results.Add(new(action, mapped, observed));
        }
        return results;
    }

    private static string Normalize(string value) => value.Replace("_", "", StringComparison.Ordinal).Replace("-", "", StringComparison.Ordinal).ToLowerInvariant();
    private static JsonElement Property(JsonElement value, string name)
    {
        if (value.ValueKind != JsonValueKind.Object) return default;
        var result = default(JsonElement); var count = 0;
        foreach (var property in value.EnumerateObject()) if (property.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) { result = property.Value; count++; }
        return count == 1 ? result : default;
    }
    private static string Text(JsonElement value, string name) => Property(value, name) is { ValueKind: JsonValueKind.String } text ? text.GetString() ?? "" : "";
    private static JsonDocument? Document(object? value, int limit, int depth)
    {
        try
        {
            using var buffer = new BoundedStream(limit);
            JsonSerializer.Serialize(buffer, value, ReportSecurity.JsonOptions);
            return JsonDocument.Parse(buffer.ToArray(), new JsonDocumentOptions { MaxDepth = depth });
        }
        catch (Exception error) when (error is IOException or JsonException or InvalidOperationException or NotSupportedException or ArgumentException)
        { return null; }
    }
    private sealed class BoundedStream(int limit) : MemoryStream
    {
        public override void Write(byte[] buffer, int offset, int count) { if (Length + count > limit) throw new IOException("Bounded view exceeded."); base.Write(buffer, offset, count); }
        public override void Write(ReadOnlySpan<byte> buffer) { if (Length + buffer.Length > limit) throw new IOException("Bounded view exceeded."); base.Write(buffer); }
    }
    private sealed record AccessObservation(string ActionKey, string Status, DateTimeOffset ObservedAtUtc);

    private static CloudConnectionGuideStep Step(string id, string title, string description, string? command = null) => new(id, title, description, command);
    private static readonly Definition[] Definitions =
    [
        new("azure", "cli-session", "az", [], "https://azure.microsoft.com/free/", "https://portal.azure.com/", "https://learn.microsoft.com/cli/azure/authenticate-azure-cli", ["subscription"],
            [Step("authenticate-cli", "Sign in to Azure CLI", "Run this on the host that runs Opscope; complete Microsoft's device consent in your browser. Existing managed identities may be configured by the server operator instead.", "az login --use-device-code"), Step("scope", "Select authorized subscriptions", "Login and subscription read permission are separate requirements.", "opscope serve --cloud azure --subscription <subscription-id>")]),
        new("aws", "cli-session", "aws", [], "https://portal.aws.amazon.com/billing/signup", "https://console.aws.amazon.com/", "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html", ["profile", "region"],
            [Step("authenticate-cli", "Sign in to an existing SSO profile", "Use a preconfigured AWS CLI v2 IAM Identity Center profile on the Opscope host. Existing instance or workload roles may be configured by its operator instead.", "aws sso login --profile <profile> --use-device-code --no-browser"), Step("scope", "Select profile and region", "The profile must already select the intended account and read role.", "opscope serve --cloud aws --profile <profile> --region <region>")]),
        new("gcp", "cli-session-and-adc", "gcloud", [], "https://cloud.google.com/free", "https://console.cloud.google.com/", "https://cloud.google.com/docs/authentication/provide-credentials-adc", ["project"],
            [Step("authenticate-cli", "Sign in to gcloud", "Configure the intended CLI account on the Opscope host. Complete any required browser or remote-bootstrap interaction in the official CLI.", "gcloud auth login"), Step("adc", "Configure Application Default Credentials separately", "Monitoring, SCC, billing and OS Config use ADC. A gcloud CLI login alone does not configure ADC. Workload identity can be configured by the host operator instead.", "gcloud auth application-default login"), Step("scope", "Select authorized projects", "GCP does not accept --profile as an identity selector.", "opscope serve --cloud gcp --project <project-id>")]),
        new("oci", "cli-session", "oci", [], "https://signup.cloud.oracle.com/", "https://cloud.oracle.com/", "https://docs.oracle.com/iaas/Content/API/SDKDocs/cliinstall.htm", ["compartment", "region", "profile"],
            [Step("authenticate-cli", "Configure the official OCI CLI", "Configure an authorized existing CLI profile on the host. Private keys and security tokens stay outside the browser."), Step("scope", "Select a compartment and region", "The configured principal needs the read permissions for the selected compartment.", "opscope serve --cloud oci --compartment <compartment-ocid> --region <region>")]),
        new("digitalocean", "api-token", null, ["DIGITALOCEAN_ACCESS_TOKEN"], "https://cloud.digitalocean.com/registrations/new", "https://cloud.digitalocean.com/", "https://docs.digitalocean.com/reference/api/create-personal-access-token/", ["project"],
            [Step("backend-token", "Configure a read token on the host", "Create a restricted API token using DigitalOcean's official console and configure DIGITALOCEAN_ACCESS_TOKEN on the Opscope host. The console login alone does not connect this backend."), Step("scope", "Select the authorized project", "Use a project UUID whose resources the token can read.", "opscope serve --cloud digitalocean --project <project-uuid>")]),
        new("hetzner", "api-token", null, ["HCLOUD_TOKEN"], "https://accounts.hetzner.com/signUp", "https://console.hetzner.cloud/", "https://docs.hetzner.cloud/", ["project"],
            [Step("backend-token", "Configure the project's read token", "Create a read-only Cloud API token in the intended project and configure HCLOUD_TOKEN on the Opscope host. The project label alone does not establish account ownership."), Step("scope", "Select the configured project label", "Use separate host sessions for tokens from different projects.", "opscope serve --cloud hetzner --project <project-label>")]),
        new("cloudflare", "api-token", null, ["CLOUDFLARE_API_TOKEN"], "https://dash.cloudflare.com/sign-up", "https://dash.cloudflare.com/", "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/", ["account", "zones"],
            [Step("backend-token", "Configure a restricted Cloudflare API token", "Configure CLOUDFLARE_API_TOKEN on the host. Zone Read and the selected operation's Settings, DNS, WAF, Routes or Analytics read permissions are separate requirements."), Step("scope", "Select the authorized account and zones", "Use explicit account and zone identifiers.", "opscope serve --cloud cloudflare --account <account-id> --zones <zone-id>")]),
        new("openstack", "cli-session", "openstack", [], null, null, "https://docs.openstack.org/python-openstackclient/latest/configuration/index.html", ["cloud-name", "project", "region"],
            [Step("authenticate-cli", "Use the organization's approved cloud profile", "The operator configures clouds.yaml, identity and trusted endpoints on the host. OpenStack has no universal account-registration service."), Step("scope", "Select the private-cloud scope", "Use an administrator-approved cloud profile, project and region.", "opscope serve --cloud openstack --cloud-name <profile> --project <project-id> --region <region>")]),
        new("alibaba", "cli-session", "aliyun", [], "https://account.alibabacloud.com/register/intl_register.htm", "https://home.console.aliyun.com/", "https://www.alibabacloud.com/help/en/cli/", ["account", "region", "profile"],
            [Step("authenticate-cli", "Configure the official Alibaba CLI identity", "Use an authorized RAM/role profile on the host. Opscope checks the account returned by STS against the selected account; login alone does not grant ECS or CloudMonitor permissions."), Step("scope", "Select account and region", "The existing CLI must support the fixed read projections used by the adapter.", "opscope serve --cloud alibaba --account <account-id> --region <region>")]),
        new("ibm", "api-token", null, ["IBM_CLOUD_IAM_TOKEN"], "https://cloud.ibm.com/registration", "https://cloud.ibm.com/", "https://cloud.ibm.com/docs/account?topic=account-iamtoken_from_apikey", ["account", "resource-group", "region"],
            [Step("backend-token", "Supply an existing IAM access token", "Configure IBM_CLOUD_IAM_TOKEN on the host using your approved IAM token workflow. This adapter accepts an access token, not a console password or a raw API key; it does not renew tokens."), Step("scope", "Select account, resource group and region", "Monitoring additionally requires its selected existing instance and read permission.", "opscope serve --cloud ibm --account <account-id> --resource-group <group-id> --region <region>")]),
        new("scaleway", "api-token", null, ["SCW_SECRET_KEY"], "https://console.scaleway.com/register", "https://console.scaleway.com/", "https://www.scaleway.com/en/docs/identity-and-access-management/iam/how-to/create-api-keys/", ["project", "zone", "region"],
            [Step("backend-token", "Configure an existing restricted API key", "Configure SCW_SECRET_KEY on the host. Cockpit metrics additionally need SCW_COCKPIT_TOKEN and an existing source; neither key is exposed here."), Step("scope", "Select the project and product location", "Instance reads use a zone. Network reads require an explicit region; adding a compatible zone also selects Public Gateway and Load Balancer metadata and their separate read permissions.", "opscope serve --cloud scaleway --project <project-uuid> --region fr-par --zone fr-par-1")]),
        new("kubernetes", "kubeconfig", "kubectl", [], null, null, "https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/", ["context", "namespaces"],
            [Step("kubeconfig", "Use an approved existing kubeconfig context", "The administrator supplies context access and namespace-scoped RBAC on the host. Do not upload kubeconfig files or cluster bearer tokens into the browser."), Step("scope", "Select context and namespaces", "Metrics need the existing Metrics Server and its read permissions.", "opscope serve --cloud kubernetes --context <context> --namespaces <namespace>")])
    ];
    private sealed record Definition(string Id, string AuthKind, string? Tool, string[] Tokens, string? SignUp, string? Console, string Docs, string[] ScopeFields, CloudConnectionGuideStep[] Steps);
}

public sealed record CloudConnectionsView(int Version, DateTimeOffset ObservedAtUtc, bool RemoteRequestsMade, bool AuthenticationActionsAvailable, string Mode, IReadOnlyList<CloudConnectionProvider> Providers);
public sealed record CloudConnectionProvider(string ProviderId, string DisplayName, string Category, string AuthenticationKind, string ScopeStatus, string CredentialStatus, string ToolStatus, string AccessStatus, string? LastActionKey, DateTimeOffset? LastObservedAtUtc, IReadOnlyList<CloudConnectionRequirement> Requirements, IReadOnlyList<CloudConnectionDiagnostic> Diagnostics, CloudConnectionGuide Guide, IReadOnlyList<CloudConnectionTestAction> TestActions);
public sealed record CloudConnectionRequirement(string Kind, string Name, string State, IReadOnlyList<string> Operations);
public sealed record CloudConnectionDiagnostic(string Code, string Severity, string Message, string Remediation);
public sealed record CloudConnectionGuide(string? SignUpUrl, string? ConsoleUrl, string DocumentationUrl, IReadOnlyList<string> ScopeFields, IReadOnlyList<CloudConnectionGuideStep> Steps);
public sealed record CloudConnectionGuideStep(string Id, string Title, string Description, string? CommandTemplate);
public sealed record CloudConnectionTestAction(string ActionKey, string Operation, string ScopeAlias);
public sealed record CloudConnectionFailure(int HttpStatus, string Code, string Message, string Remediation, string NextStep, string? ProviderId);
