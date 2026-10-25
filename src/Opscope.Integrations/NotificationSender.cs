using System.Net;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Opscope.Integrations;

public sealed record NotificationOptions(string Target, string? Endpoint = null, bool ConfirmSend = false,
    string? CredentialEnvironmentVariable = null, string? Project = null, string? IssueType = null,
    string? DcrImmutableId = null, string? Stream = null, string? LogGroup = null, string? LogStream = null,
    string? Region = null, string? Profile = null);

public sealed record NotificationResult(string Target, bool Sent, int? StatusCode, string Message, string? PreviewJson = null);

/// <summary>Injectable isolated transport for explicitly requested CloudWatch writes.</summary>
public interface INotificationCommandRunner
{
    Task<CommandResult> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken);
}

/// <summary>Explicit delivery of a bounded redacted summary. Merely collecting a report never sends it.</summary>
public static class NotificationSender
{
    private const int MaximumPayloadBytes = 16 * 1024;
    private const int MaximumResponseBytes = 64 * 1024;
    private static readonly JsonSerializerOptions Json = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    public static Task<NotificationResult> SendAsync(AnalysisReport report, NotificationOptions options, CancellationToken cancellationToken = default) =>
        SendCoreAsync(report, options, null, null, cancellationToken);

    public static Task<NotificationResult> SendAsync(AnalysisReport report, NotificationOptions options, HttpMessageHandler handler, CancellationToken cancellationToken = default) =>
        SendCoreAsync(report, options, handler, null, cancellationToken);

    public static Task<NotificationResult> SendAsync(AnalysisReport report, NotificationOptions options, INotificationCommandRunner commandRunner, CancellationToken cancellationToken = default) =>
        SendCoreAsync(report, options, null, commandRunner, cancellationToken);

    private static async Task<NotificationResult> SendCoreAsync(AnalysisReport report, NotificationOptions options, HttpMessageHandler? handler, INotificationCommandRunner? commandRunner, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var target = options.Target.Trim().ToLowerInvariant().Replace("-", "", StringComparison.Ordinal);
        if (target is "ado" or "azuredevops") target = "ado";
        if (target is not ("slack" or "teams" or "jira" or "ado" or "azuremonitor" or "cloudwatch"))
            return new(target, false, null, "Unsupported delivery target. Use slack, teams, jira, ado, azuremonitor or cloudwatch.");
        var safe = ReportSecurity.Redact(report);
        var summary = Summary(safe);
        var title = Clip($"Opscope {Reporter.RedactEvidenceText(safe.Kind)}: {safe.Findings.Count} findings", 160);
        var body = Payload(target, safe, summary, title, options);
        if (Encoding.UTF8.GetByteCount(body) > MaximumPayloadBytes) return new(target, false, null, "Redacted delivery payload exceeds the 16 KiB limit.");
        if (!options.ConfirmSend) return new(target, false, null, "Preview only. Sending requires explicit --confirm-send. Payload contains a bounded redacted summary; report data is excluded.", body);
        if (target == "cloudwatch") return await SendCloudWatch(body, options, commandRunner, ct);
        if (!TryEndpoint(target, options, out var endpoint, out var error)) return new(target, false, null, error);
        var credential = "";
        if (target is "jira" or "ado" or "azuremonitor" && !TryCredential(options.CredentialEnvironmentVariable, out credential))
            return new(target, false, null, "Set --credential-env to an environment variable containing the target credential. Credential values are never included in output.");
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Content = new StringContent(body, Encoding.UTF8, target == "ado" ? "application/json-patch+json" : "application/json");
        if (target == "jira") request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(credential)));
        if (target == "ado") request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(":" + credential)));
        if (target == "azuremonitor") request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential);
        handler ??= new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false, ConnectTimeout = TimeSpan.FromSeconds(3), MaxResponseHeadersLength = 16 };
        using var client = new HttpClient(handler, disposeHandler: true) { Timeout = TimeSpan.FromSeconds(10) };
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            var truncated = await ReadBoundedResponse(response, deadline.Token);
            return new(target, response.IsSuccessStatusCode, (int)response.StatusCode,
                response.IsSuccessStatusCode ? "Endpoint accepted the redacted notification." + (truncated ? " Response body exceeded the collection limit and was discarded." : "")
                : (int)response.StatusCode is >= 300 and < 400 ? "Endpoint returned a redirect. It was not followed; verify the configured endpoint before retrying."
                : "Endpoint rejected the notification. Response contents were discarded to avoid exposing credentials or service details.");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is HttpRequestException or IOException or OperationCanceledException)
        { return new(target, false, null, "Delivery response was unavailable. Delivery status is unknown; verify the target before retrying. No automatic retry was attempted."); }
    }

    private static string Summary(AnalysisReport report)
    {
        var text = new StringBuilder();
        text.AppendLine(CultureInfo.InvariantCulture, $"Opscope {Clip(Reporter.RedactEvidenceText(report.Kind), 120)}; collected {report.CollectedAtUtc:O}.");
        text.AppendLine(CultureInfo.InvariantCulture, $"Findings: {report.Findings.Count}; critical: {report.Findings.Count(f => f.Severity == FindingSeverity.Critical)}; warnings: {report.Findings.Count(f => f.Severity == FindingSeverity.Warning)}.");
        foreach (var f in report.Findings.Take(10))
            text.AppendLine(CultureInfo.InvariantCulture, $"[{f.Severity}] {Clip(Reporter.RedactEvidenceText(f.Code), 80)}: {Clip(f.Title, 100)}. {Clip(f.Detail, 180)} {Clip(f.Recommendation, 180)}");
        if (report.Findings.Count > 10) text.AppendLine("Additional findings omitted from this bounded summary; review the local report.");
        return Clip(text.ToString(), 2500);
    }

    private static string Payload(string target, AnalysisReport report, string summary, string title, NotificationOptions options)
    {
        object payload = target switch
        {
            "slack" => new { text = summary.Replace("&", "&amp;", StringComparison.Ordinal).Replace("<", "&lt;", StringComparison.Ordinal).Replace(">", "&gt;", StringComparison.Ordinal), mrkdwn = false, parse = "none", link_names = false, unfurl_links = false, unfurl_media = false },
            "teams" => new { type = "message", attachments = new[] { new { contentType = "application/vnd.microsoft.card.adaptive", content = new { type = "AdaptiveCard", version = "1.2", body = new[] { new { type = "TextBlock", text = summary, wrap = true } } } } } },
            "jira" => new { fields = new { project = new { key = options.Project ?? "[project required]" }, summary = title, issuetype = new { name = options.IssueType ?? "Task" }, description = new { type = "doc", version = 1, content = new[] { new { type = "paragraph", content = new[] { new { type = "text", text = summary } } } } } } },
            "ado" => new[] { new { op = "add", path = "/fields/System.Title", value = title }, new { op = "add", path = "/fields/System.Description", value = WebUtility.HtmlEncode(summary) } },
            "azuremonitor" => new[] { new { TimeGenerated = report.CollectedAtUtc, Kind = Clip(Reporter.RedactEvidenceText(report.Kind), 120), FindingCount = report.Findings.Count, Summary = summary } },
            _ => new[] { new { timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), message = summary } }
        };
        return JsonSerializer.Serialize(payload, Json);
    }

    private static bool TryEndpoint(string target, NotificationOptions options, out Uri endpoint, out string error)
    {
        endpoint = null!;
        error = "A valid HTTPS --endpoint without user information or fragment is required.";
        var endpointText = options.Endpoint;
        if (target is "slack" or "teams" && options.CredentialEnvironmentVariable is not null)
        {
            if (!TryCredential(options.CredentialEnvironmentVariable, out var webhook)) { error = "The configured webhook environment variable was missing or invalid."; return false; }
            endpointText = webhook;
        }
        if (!Uri.TryCreate(endpointText, UriKind.Absolute, out var configured) || configured.Scheme != Uri.UriSchemeHttps || configured.UserInfo.Length != 0 || configured.Fragment.Length != 0 || configured.OriginalString.Length > 4096) return false;
        var url = configured.AbsoluteUri.TrimEnd('/');
        if (target == "jira")
        {
            if (string.IsNullOrWhiteSpace(options.Project) || options.Project.Length > 128) { error = "Jira delivery requires --project with the intended project key."; return false; }
            if (configured.Query.Length != 0) { error = "Jira endpoint must not contain a query string."; return false; }
            if (configured.AbsolutePath == "/") url += "/rest/api/3/issue";
            else if (!configured.AbsolutePath.EndsWith("/rest/api/3/issue", StringComparison.Ordinal)) { error = "Jira endpoint must be an HTTPS site root or its /rest/api/3/issue endpoint."; return false; }
        }
        else if (target == "ado")
        {
            if (string.IsNullOrWhiteSpace(options.Project) || options.Project.Length > 128) { error = "Azure DevOps delivery requires --project."; return false; }
            if (!configured.Host.Equals("dev.azure.com", StringComparison.OrdinalIgnoreCase) && !configured.Host.EndsWith(".visualstudio.com", StringComparison.OrdinalIgnoreCase)) { error = "Azure DevOps endpoint must use dev.azure.com or an organization.visualstudio.com HTTPS host."; return false; }
            if (configured.Query.Length != 0) { error = "Azure DevOps base endpoint must not contain a query string."; return false; }
            url += "/" + Uri.EscapeDataString(options.Project) + "/_apis/wit/workitems/$" + Uri.EscapeDataString(options.IssueType ?? "Issue") + "?api-version=7.1";
        }
        else if (target == "azuremonitor")
        {
            if (!configured.Host.EndsWith(".ingest.monitor.azure.com", StringComparison.OrdinalIgnoreCase) && !configured.Host.EndsWith(".ingest.monitor.azure.us", StringComparison.OrdinalIgnoreCase) && !configured.Host.EndsWith(".ingest.monitor.azure.cn", StringComparison.OrdinalIgnoreCase)) { error = "Azure Monitor endpoint must be an HTTPS Data Collection Endpoint ingest host."; return false; }
            if (configured.AbsolutePath != "/" || configured.Query.Length != 0 || !Regex.IsMatch(options.DcrImmutableId ?? "", "^dcr-[a-fA-F0-9]{32}$", RegexOptions.CultureInvariant) || !Regex.IsMatch(options.Stream ?? "", "^Custom-[A-Za-z0-9_]{1,128}$", RegexOptions.CultureInvariant)) { error = "Azure Monitor requires a DCE root endpoint, --dcr dcr-<32hex> and --stream Custom-<name>. The destination table and DCR must already exist."; return false; }
            url += "/dataCollectionRules/" + options.DcrImmutableId + "/streams/" + options.Stream + "?api-version=2023-01-01";
        }
        if (!Uri.TryCreate(url, UriKind.Absolute, out var resolved)) return false;
        endpoint = resolved;
        return true;
    }

    private static bool TryCredential(string? variable, out string credential)
    {
        credential = "";
        if (variable is null || variable.Length > 128 || !Regex.IsMatch(variable, "^[A-Za-z_][A-Za-z0-9_]*$", RegexOptions.CultureInvariant)) return false;
        var value = Environment.GetEnvironmentVariable(variable);
        if (string.IsNullOrEmpty(value) || value.Length > 16 * 1024 || value.Any(char.IsControl)) return false;
        credential = value;
        return true;
    }

    private static async Task<NotificationResult> SendCloudWatch(string body, NotificationOptions options, INotificationCommandRunner? runner, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(options.LogGroup) || string.IsNullOrWhiteSpace(options.LogStream) || string.IsNullOrWhiteSpace(options.Region)
            || !Regex.IsMatch(options.LogGroup, @"^[A-Za-z0-9_./#-]{1,512}$", RegexOptions.CultureInvariant)
            || options.LogStream.Length > 512 || options.LogStream.Any(char.IsControl) || options.LogStream.Contains(':') || options.LogStream.Contains('*')
            || !Regex.IsMatch(options.Region, "^[a-z]{2}(-[a-z]+){1,3}-[0-9]$", RegexOptions.CultureInvariant)
            || options.Profile is { Length: > 128 } || (options.Profile?.Any(char.IsControl) ?? false))
            return new("cloudwatch", false, null, "CloudWatch delivery requires a valid existing --log-group, --log-stream and --region; --profile optionally selects an existing AWS CLI profile.");
        var args = new List<string> { "logs", "put-log-events", "--log-group-name", options.LogGroup, "--log-stream-name", options.LogStream, "--log-events", body, "--region", options.Region, "--output", "json", "--no-cli-pager", "--no-cli-auto-prompt" };
        if (!string.IsNullOrWhiteSpace(options.Profile)) args.AddRange(["--profile", options.Profile]);
        var result = runner is null ? await CommandRunner.RunAsync("aws", args, TimeSpan.FromSeconds(15), outputLimit: 64 * 1024, cancellationToken: ct) : await runner.RunAsync("aws", args, ct);
        if (result.ExitCode != 0 || result.TimedOut || result.OutputTruncated) return new("cloudwatch", false, null, "AWS CLI did not confirm CloudWatch delivery. Verify the existing log group, log stream, authentication, region and logs:PutLogEvents permission before retrying; command output was discarded.");
        try
        {
            using var response = JsonDocument.Parse(result.StandardOutput);
            if (response.RootElement.TryGetProperty("rejectedLogEventsInfo", out _) || response.RootElement.TryGetProperty("rejectedEntityInfo", out _))
                return new("cloudwatch", false, null, "CloudWatch rejected some log events; verify event age, destination and permissions before retrying.");
        }
        catch (JsonException) { return new("cloudwatch", false, null, "AWS CLI response was invalid; delivery status is unknown. Verify the destination before retrying."); }
        return new("cloudwatch", true, 200, "CloudWatch accepted the redacted summary. No log group or stream was created.");
    }

    private static async Task<bool> ReadBoundedResponse(HttpResponseMessage response, CancellationToken ct)
    {
        if (response.Content.Headers.ContentLength > MaximumResponseBytes) return true;
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        var buffer = new byte[4096];
        var total = 0;
        while (true) { var read = await stream.ReadAsync(buffer, ct); if (read == 0) return false; total += read; if (total > MaximumResponseBytes) return true; }
    }
    private static string Clip(string value, int length) => value.Length <= length ? value : value[..length] + "…";
}
