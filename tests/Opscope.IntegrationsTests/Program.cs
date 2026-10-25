using System.Net;
using System.Text;
using System.Text.Json;
using Opscope;
using Opscope.Integrations;

internal static class Program
{
    private const string Secret = "DO-NOT-SEND-raw-data-secret";
    private const string Variable = "OPSCOPE_INTEGRATION_TEST_CREDENTIAL";
    private static readonly AnalysisReport Report = new("test", DateTimeOffset.UtcNow, [new(FindingSeverity.Warning, "EXAMPLE", "Review authentication", "password=secret-value host 10.2.3.4", "Review the local evidence.")], new { password = Secret, raw = Secret });

    private static async Task Main()
    {
        using var previewHandler = new FakeHandler(HttpStatusCode.OK);
        var preview = await NotificationSender.SendAsync(Report, new("slack", "https://hooks.slack.com/services/secret"), previewHandler);
        Check(!preview.Sent && previewHandler.Calls == 0 && preview.PreviewJson is not null, "preview has concrete payload and performs no request");
        Check(!preview.PreviewJson!.Contains(Secret, StringComparison.Ordinal) && !preview.PreviewJson.Contains("secret-value", StringComparison.Ordinal), "preview excludes raw data and redacts finding evidence");
        foreach (var target in new[] { "slack", "teams", "jira", "ado", "azuremonitor" })
        {
            Environment.SetEnvironmentVariable(Variable, target == "jira" ? "reviewer@example.com:api-token" : "test-token");
            var endpoint = target switch { "ado" => "https://dev.azure.com/example", "azuremonitor" => "https://example.eastus.ingest.monitor.azure.com", _ => "https://example.com/" };
            using var handler = new FakeHandler(HttpStatusCode.Created);
            var options = new NotificationOptions(target, endpoint, true, target is "slack" or "teams" ? null : Variable, "OPS", "Task", "dcr-11111111111111111111111111111111", "Custom-Opscope");
            var result = await NotificationSender.SendAsync(Report, options, handler);
            Check(result.Sent && handler.Calls == 1, target + " performs only its explicit send");
            Check(handler.Body is not null && !handler.Body.Contains(Secret, StringComparison.Ordinal) && !handler.Body.Contains("secret-value", StringComparison.Ordinal), target + " sends only redacted bounded summary");
            Check(handler.Body is not null && Encoding.UTF8.GetByteCount(handler.Body) <= 16 * 1024, target + " payload is bounded");
            Check((target is "jira" or "ado" or "azuremonitor") == (handler.Authorization is not null), target + " authentication is explicit");
            if (target == "azuremonitor") Check(handler.Url!.Contains("/dataCollectionRules/dcr-", StringComparison.Ordinal) && handler.Url.Contains("/streams/Custom-Opscope", StringComparison.Ordinal), "Azure Monitor uses existing DCR and stream");
        }
        Environment.SetEnvironmentVariable(Variable, "https://hooks.slack.com/services/secret");
        using (var webhook = new FakeHandler(HttpStatusCode.OK))
        {
            var result = await NotificationSender.SendAsync(Report, new("slack", ConfirmSend: true, CredentialEnvironmentVariable: Variable), webhook);
            Check(result.Sent && webhook.Calls == 1 && !JsonSerializer.Serialize(result).Contains("services/secret", StringComparison.Ordinal), "webhook may come from environment without being echoed");
        }
        using (var redirect = new FakeHandler(HttpStatusCode.Redirect))
        {
            var result = await NotificationSender.SendAsync(Report, new("slack", "https://example.com/", true), redirect);
            Check(!result.Sent && redirect.Calls == 1 && result.Message.Contains("not followed", StringComparison.Ordinal), "redirect is rejected without another request");
        }
        using (var insecure = new FakeHandler(HttpStatusCode.OK))
        {
            var result = await NotificationSender.SendAsync(Report, new("slack", "http://example.com/", true), insecure);
            Check(!result.Sent && insecure.Calls == 0, "HTTP endpoint is rejected before transport");
        }
        using (var large = new FakeHandler(HttpStatusCode.OK, new string('x', 100000)))
        {
            var result = await NotificationSender.SendAsync(Report, new("teams", "https://example.com/", true), large);
            Check(result.Sent && result.Message.Contains("discarded", StringComparison.Ordinal), "oversized service body is discarded while preserving accepted status");
        }
        foreach (var status in new[] { HttpStatusCode.Created, HttpStatusCode.BadRequest })
        {
            using var brokenBody = new BrokenBodyHandler(status);
            var result = await NotificationSender.SendAsync(Report, new("teams", "https://example.com/", true), brokenBody);
            Check(result.StatusCode == (int)status && result.Sent == (status == HttpStatusCode.Created), "Known delivery status survives an unreadable discarded response body");
            Check(!JsonSerializer.Serialize(result).Contains(Secret, StringComparison.Ordinal), "Response-body failure exposes no exception detail");
        }
        var aws = new FakeCommand();
        var awsOptions = new NotificationOptions("cloudwatch", ConfirmSend: true, LogGroup: "/opscope/reports", LogStream: "manual", Region: "us-east-1", Profile: "review");
        var cloudwatch = await NotificationSender.SendAsync(Report, awsOptions, aws);
        Check(cloudwatch.Sent && aws.Calls == 1 && aws.Arguments!.Take(2).SequenceEqual(new[] { "logs", "put-log-events" }), "CloudWatch uses one isolated explicit put-log-events command");
        var awsArguments = aws.Arguments!;
        Check(awsArguments.Contains("--profile") && awsArguments.Contains("--region") && !string.Join(" ", awsArguments).Contains(Secret, StringComparison.Ordinal), "CloudWatch uses requested scope and redacted inline events");
        var noSend = await NotificationSender.SendAsync(Report, awsOptions with { ConfirmSend = false }, aws);
        Check(!noSend.Sent && aws.Calls == 1, "CloudWatch preview never spawns CLI");
        foreach (var response in new[] { "null", "[]", "\"unexpected\"", "true", "42" })
        {
            var malformed = new FakeCommand(response);
            var result = await NotificationSender.SendAsync(Report, awsOptions, malformed);
            Check(!result.Sent && malformed.Calls == 1 && result.Message.Contains("unknown", StringComparison.Ordinal), "CloudWatch rejects a non-object CLI response without crashing");
        }
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        try { await NotificationSender.SendAsync(Report, new("slack"), cancellation.Token); throw new InvalidOperationException("Cancelled delivery did not cancel."); }
        catch (OperationCanceledException) { }
        Environment.SetEnvironmentVariable(Variable, null);
        Console.WriteLine("Integration fake-transport tests passed.");
    }

    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private sealed class FakeHandler(HttpStatusCode status, string response = "{}") : HttpMessageHandler
    {
        public int Calls { get; private set; }
        public string? Body { get; private set; }
        public string? Authorization { get; private set; }
        public string? Url { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            Body = await request.Content!.ReadAsStringAsync(cancellationToken);
            Url = request.RequestUri!.AbsoluteUri;
            Authorization = request.Headers.Authorization?.ToString();
            return new(status) { Content = new StringContent(response), Headers = { Location = new Uri("https://never-follow.example/") } };
        }
    }
    private sealed class FakeCommand(string response = "{}") : INotificationCommandRunner
    {
        public int Calls { get; private set; }
        public IReadOnlyList<string>? Arguments { get; private set; }
        public Task<CommandResult> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
        {
            Check(tool == "aws", "Only AWS CLI is used for CloudWatch delivery.");
            Calls++; Arguments = arguments;
            return Task.FromResult(new CommandResult(0, response, "", false));
        }
    }
    private sealed class BrokenBodyHandler(HttpStatusCode status) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(status) { Content = new BrokenContent() });
    }
    private sealed class BrokenContent : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => Task.FromException(new IOException(Secret));
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
    }
}
