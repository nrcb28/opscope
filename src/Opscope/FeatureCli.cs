using System.Globalization;
using System.Text;
using System.Security.Cryptography;
using System.Text.Json;
using Opscope.Api;
using Opscope.Cloud;
using Opscope.Evidence;
using Opscope.Integrations;

namespace Opscope;

internal static class FeatureCli
{
    public const string Usage = """

Extended commands:
  collect --pack <pack.yml>              Collect a declarative scenario
  policy validate|check <policy.yml>     Validate or evaluate policies
  plugins check <rules.yml>              Evaluate safe declarative rules
  pack validate <pack.yml>               Validate bounded pack inheritance
  triage --scenario <scenario>           Contextual incident guidance
  ioc <indicators.csv|stix.json>          Match indicators without actions
  timeline [baseline.json]               Build a chronological report
  fleet <snapshot1.json> <snapshot2>...  Compare a saved fleet
  environment                           Detect containers and host context
  report [snapshot.json] [--bundle ZIP] Self-contained HTML/PDF handoff + hashes
  bundle [--pack ...] [--evidence ...]   Redacted sealed ZIP + SHA-256
  verify <bundle> [--public-key <pem>]   Verify hashes and trusted signature
  decrypt <bundle> --private-key <pem> --out <zip>
  azure inventory|posture|health|vm|bundle|drift|patches|cost|arc
  aws inventory|posture|health|instance|bundle|drift|patches|cost
  cloud inventory|posture|health|patches|metadata [--provider azure|aws]
  serve [--port 0] [--history <sqlite>]   Authenticated loopback web UI
  tui [--interval 5] [--page summary]  Five-page read-only terminal dashboard
  history list|show <id>|prune           Private redacted SQLite history
  mcp                                   Read-only MCP over stdio
  notify --target <target>              Preview redacted delivery payload

Extended options:
  --format json|sarif|junit|html|pdf|csv|jsonl|cef|asff
  --policy <opscope.yml> --plugins <rules.yml> --pack <pack.yml>
  --fail-on info|warning|critical|none    Default: warning; operational errors=2
  --evidence logs,packages,accounts,scheduled-tasks,certificates,security
  --ioc <file> --baseline <snapshot> --input <snapshot> --out <path>
  --full                                Explicit full identifiers in new reports
  --sign-private-key <pem> --encrypt-public-key <pem>
  --public-key <pem> --private-key <pem>  Verification/decryption keys
  --subscription <id> --subscriptions <ids> --profile <name> --profiles <names>
  --region <name> --regions <names|all> --accounts <ids> --resource <id>
  --account <12-digit-id>                Required with region for ASFF import
  --cloud-context                       Explicit local metadata lookup
  --confirm-send                        Required for any external delivery
  --endpoint <https-url> --credential-env <variable-name>
  --target slack|teams|jira|azure-devops|azure-monitor|cloudwatch
  --quiet --require-complete

Cloud modules require an installed, authenticated Azure CLI or AWS CLI v2.
They query existing services only and never enable paid services or fetch secrets.
Local collection does not contact cloud metadata or delivery endpoints by default.
""";

    private static readonly HashSet<string> Commands = new(StringComparer.Ordinal)
        { "collect", "policy", "plugins", "pack", "triage", "ioc", "timeline", "fleet", "environment", "report", "verify", "decrypt", "azure", "aws", "cloud", "serve", "tui", "history", "mcp", "notify", "offline", "bundle" };
    private static readonly HashSet<string> FeatureFlags = new(StringComparer.Ordinal)
        { "--format", "--policy", "--plugins", "--pack", "--fail-on", "--evidence", "--ioc", "--full", "--cloud-context", "--seal", "--sign-private-key", "--encrypt-public-key", "--require-complete", "--input", "--baseline", "--quiet", "--page", "--samples" };

    public static async Task<int?> TryRunAsync(string[] args)
    {
        var first = args.FirstOrDefault() ?? "snapshot";
        if (!Commands.Contains(first) && !args.Any(a => FeatureFlags.Contains(a.Split('=')[0])) &&
            !(File.Exists("opscope.yml") && first is "snapshot" or "doctor" or "watch" or "diff")) return null;
        var options = Options.Parse(args);
        if (options.Has("help")) { Console.WriteLine(CliOptions.Usage); return 0; }
        var command = options.Positionals.FirstOrDefault() ?? "snapshot";
        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; cancellation.Cancel(); };
        Console.CancelKeyPress += cancel;
        try
        {
            var token = cancellation.Token;
            var verb = options.Positionals.ElementAtOrDefault(1) ?? "";
            var savedInput = options.Optional("input") ?? (command == "report" ? options.Positionals.ElementAtOrDefault(1) : null);
            if (savedInput is not null)
            {
                if (command is not ("snapshot" or "doctor" or "collect" or "bundle" or "offline" or "report" or "triage" or "ioc" or "timeline" or "policy" or "plugins" or "notify" or "diff"))
                    throw new CliException($"{command} cannot use a saved snapshot. Omit --input to collect the current host.");
                if (options.Has("cloud-context") || options.Has("evidence") || options.Has("pack") || options.Has("no-processes") || options.Has("no-network") || options.Has("no-services") || options.Has("top"))
                    throw new CliException("Collection options require a fresh local collection and cannot be combined with a saved snapshot. Analyze the evidence already stored in the snapshot instead.");
            }
            if (command == "serve") return await ServeAsync(options, token);
            if (command == "mcp") { await McpServer.RunAsync(ct => CollectConfiguredAsync(options, ct), token); return 0; }
            if (command is "tui" or "watch") return await WatchAsync(options, token);
            if (command == "history") return await HistoryAsync(options, token);
            if (command == "pack")
            {
                if (verb != "validate") throw new CliException("Use pack validate <pack.yml>.");
                var pack = CollectionPack.Load(RequirePositional(options, 2, "pack path"));
                return await EmitAsync(new("pack", DateTimeOffset.UtcNow, [], new { pack.Name, pack.Collectors, pack.EvidenceGroups }), options, token);
            }
            if (command is "policy" or "plugins" && verb == "validate")
            {
                var engine = PolicyEngine.Load(options.Positionals.ElementAtOrDefault(2) ?? options.Get("policy", "opscope.yml"));
                var errors = engine.Validate();
                if (errors.Count > 0) throw new InvalidDataException(string.Join(" ", errors));
                return await EmitAsync(new("policy/validation", DateTimeOffset.UtcNow, [], new { valid = true }), options, token);
            }
            if (command == "verify")
            {
                var result = await CustodyBundle.VerifyAsync(RequirePositional(options, 1, "bundle path"), options.Optional("public-key"), options.Optional("private-key"), token);
                Console.WriteLine(JsonSerializer.Serialize(result, ReportSecurity.JsonOptions));
                return result.IsValid ? 0 : 1;
            }
            if (command == "decrypt")
            {
                await CustodyBundle.DecryptAsync(RequirePositional(options, 1, "bundle path"), options.Required("out"), options.Required("private-key"), token);
                return 0;
            }
            if (command is "azure" or "aws" or "cloud") return await CloudAsync(command, verb, options, token);
            if (command == "fleet")
            {
                if (options.Positionals.Count is < 3 or > 101) throw new CliException("fleet requires 2–100 saved snapshots.");
                var snapshots = new List<Snapshot>();
                foreach (var path in options.Positionals.Skip(1)) snapshots.Add(await SnapshotIO.ReadAsync(path, token));
                return await EmitAsync(FleetAnalyzer.Compare(snapshots), options, token);
            }
            if (command == "diff")
            {
                var baseline = await SnapshotIO.ReadAsync(options.Optional("baseline") ?? RequirePositional(options, 1, "baseline snapshot"), token);
                var current = options.Optional("input") is { } currentPath
                    ? ApplyPolicies(await SnapshotIO.ReadAsync(currentPath, token), options)
                    : await CollectConfiguredAsync(options, token);
                var diff = DiffEngine.Compare(baseline, current);
                var report = new AnalysisReport("diff", current.CollectedAtUtc,
                    diff.Significant ? [new(FindingSeverity.Warning, "DRIFT_DETECTED", "Significant drift detected", $"{diff.Changes.Count} entity changes were observed.", "Review the baseline and current evidence.")] : [],
                    options.Has("full") ? diff : Reporter.RedactForOutput(diff), current.CollectionWarnings.Concat(diff.Warnings ?? []).ToArray());
                return await EmitAsync(report, options, token);
            }
            if (command is not ("snapshot" or "doctor" or "collect" or "bundle" or "offline" or "report" or "triage" or "ioc" or "timeline" or "environment" or "policy" or "plugins" or "notify"))
                throw new CliException($"Unsupported extended command '{command}'.");
            var input = savedInput;
            var snapshot = input is null ? await CollectConfiguredAsync(options, token) : ApplyPolicies(await SnapshotIO.ReadAsync(input, token), options);
            var extras = await ExtraReportsAsync(snapshot, options, token);
            if (command is "policy" or "plugins")
            {
                if (verb is not ("check" or "")) throw new CliException("Use policy check <policy.yml> or policy validate <policy.yml>.");
                var path = options.Positionals.ElementAtOrDefault(2) ?? options.Get(command == "plugins" ? "plugins" : "policy", "opscope.yml");
                return await EmitAsync(PolicyEngine.Load(path).Evaluate(snapshot), options, token);
            }
            if (command == "triage") return await EmitAsync(TriageAdvisor.Analyze(snapshot, options.Get("scenario", "high-cpu")), options, token);
            if (command == "ioc") return await EmitAsync(await IocAnalyzer.AnalyzeAsync(snapshot, options.Optional("ioc") ?? RequirePositional(options, 1, "indicator file"), token), options, token);
            if (command == "environment")
            {
                var platform = await PlatformInspector.CollectAsync(snapshot, token);
                var hybrid = await HybridAgents.CollectAsync(snapshot, token);
                return await EmitAsync(new("environment", snapshot.CollectedAtUtc, platform.Findings.Concat(hybrid.Findings).ToArray(), new { platform = platform.Data, hybrid = hybrid.Data }, (platform.Warnings ?? []).Concat(hybrid.Warnings ?? []).ToArray()), options, token);
            }
            if (command == "timeline")
            {
                var baselinePath = options.Optional("baseline") ?? options.Positionals.ElementAtOrDefault(1);
                var baseline = baselinePath is null ? null : await SnapshotIO.ReadAsync(baselinePath, token);
                var evidence = extras.TryGetValue("evidence", out var ev) && ev.Data is EvidenceData data ? data.Records : null;
                var timeline = TimelineBuilder.Build(snapshot, baseline, evidence);
                if (options.Get("format", "json") == "csv")
                {
                    var csv = TimelineBuilder.ToCsv(timeline);
                    if (options.Optional("out") is { } path) await Reporter.WriteTextAtomicallyAsync(path, csv, token);
                    if (!options.Has("quiet")) Console.Write(csv);
                    return CompletionCode(timeline, options);
                }
                return await EmitAsync(timeline, options, token);
            }
            if (command is "bundle" or "offline")
            {
                var path = options.Get("out", $"opscope-{DateTime.UtcNow:yyyyMMdd-HHmmss}.zip");
                var output = await CustodyBundle.WriteAsync(path, snapshot, new(options.Optional("encrypt-public-key"), options.Optional("sign-private-key"), extras), token);
                if (!options.Has("quiet")) Console.WriteLine(JsonSerializer.Serialize(new { bundle = output, sha256 = output + ".sha256", redacted = true }, ReportSecurity.JsonOptions));
                if (options.Has("require-complete") && (snapshot.CollectionWarnings.Count > 0 || extras.Values.Any(r => !r.OperationSucceeded || r.Warnings?.Count > 0))) return 2;
                return FailureCode(snapshot.Findings.Concat(extras.Values.SelectMany(r => r.Findings)), options);
            }
            if (options.Optional("bundle") is { } bundlePath)
            {
                var hash = await HashBundleAsync(bundlePath, token);
                var verification = await CustodyBundle.VerifyAsync(bundlePath, options.Optional("public-key"), options.Optional("private-key"), token);
                extras["bundle"] = new("bundle/integrity", snapshot.CollectedAtUtc,
                    verification.IsValid ? [] : [new(FindingSeverity.Warning, "BUNDLE_VERIFICATION_FAILED", "Bundle verification did not complete successfully", "Review the detached checksum, manifest and signature verification result.", "Use a separately trusted signer public key when verifying authentication.")],
                    new { sha256 = hash, verification }, verification.Errors);
            }
            var reportResult = new AnalysisReport(command, snapshot.CollectedAtUtc,
                snapshot.Findings.Concat(extras.Values.SelectMany(r => r.Findings)).DistinctBy(f => (f.Code, f.Detail)).ToArray(),
                extras.Count == 0 ? snapshot : new { snapshot, reports = extras },
                snapshot.CollectionWarnings.Concat(extras.Values.SelectMany(r => r.Warnings ?? [])).Distinct(StringComparer.Ordinal).ToArray());
            if (command == "notify")
            {
                var delivery = new NotificationOptions(options.Required("target"), options.Optional("endpoint"), options.Has("confirm-send"), options.Optional("credential-env"),
                    options.Optional("project"), options.Optional("issue-type"), options.Optional("dcr"), options.Optional("stream"), options.Optional("log-group"), options.Optional("log-stream"), options.Optional("region"), options.Optional("profile"));
                var result = await NotificationSender.SendAsync(reportResult, delivery, token);
                Console.WriteLine(JsonSerializer.Serialize(result, ReportSecurity.JsonOptions));
                return !result.Sent && result.PreviewJson is null ? 2 : 0;
            }
            if (command is "snapshot" or "doctor" && (!options.Has("format") || options.Get("format", "json") == "json"))
            {
                var redact = !options.Has("full") && (options.Has("redact") || options.Has("format"));
                var complete = snapshot with
                {
                    Findings = reportResult.Findings,
                    CollectionWarnings = reportResult.Warnings ?? [],
                    Reports = extras.Count == 0 ? snapshot.Reports : extras
                };
                var text = command == "doctor" ? Reporter.ToDoctorJson(complete, redact) : Reporter.ToJson(complete, redact);
                if (options.Optional("out") is { } output) await Reporter.WriteTextAtomicallyAsync(output, text, token);
                if (!options.Has("quiet"))
                {
                    if (options.Has("json") || options.Has("format")) Console.WriteLine(text);
                    else
                    {
                        var view = redact ? Reporter.RedactForOutput(complete) : complete;
                        if (command == "doctor") Reporter.PrintFindings(view.Findings, view.CollectionWarnings); else Reporter.PrintSnapshot(view);
                    }
                }
                return CompletionCode(reportResult, options);
            }
            return await EmitAsync(reportResult, options, token, command == "report" ? "html" : "json");
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { return command is "serve" or "tui" or "watch" or "mcp" ? 0 : 2; }
        finally { Console.CancelKeyPress -= cancel; }
    }

    public static async Task<Snapshot> CollectBaseAsync(CollectorOptions options, CancellationToken cancellationToken) =>
        await PlatformInspector.EnrichSnapshotAsync(await SystemProbe.CollectAsync(options, cancellationToken), cancellationToken);

    private static async Task<Snapshot> CollectConfiguredAsync(Options options, CancellationToken token)
    {
        var collector = options.Optional("pack") is { } pack ? CollectionPack.Load(pack).ToCollectorOptions() : new CollectorOptions();
        collector = collector with
        {
            IncludeProcesses = collector.IncludeProcesses && !options.Has("no-processes"),
            IncludeNetwork = collector.IncludeNetwork && !options.Has("no-network"),
            IncludeServices = collector.IncludeServices && !options.Has("no-services"),
            TopProcesses = options.Integer("top", collector.TopProcesses, 1, 200)
        };
        var snapshot = await CollectBaseAsync(collector, token);
        return ApplyPolicies(snapshot, options);
    }

    private static Snapshot ApplyPolicies(Snapshot snapshot, Options options)
    {
        var path = options.Optional("policy") ?? (File.Exists("opscope.yml") ? "opscope.yml" : null);
        if (path is not null)
        {
            var policy = PolicyEngine.Load(path).Evaluate(snapshot);
            var stockThresholds = new HashSet<string>(StringComparer.Ordinal) { "CPU_HIGH", "CPU_ELEVATED", "MEMORY_PRESSURE", "MEMORY_ELEVATED", "DISK_FULL", "DISK_ELEVATED" };
            snapshot = snapshot with { Findings = snapshot.Findings.Where(f => !stockThresholds.Contains(f.Code)).Concat(policy.Findings).DistinctBy(f => (f.Code, f.Detail)).ToArray(), CollectionWarnings = snapshot.CollectionWarnings.Concat(policy.Warnings ?? []).Distinct(StringComparer.Ordinal).ToArray() };
        }
        if (options.Optional("plugins") is { } plugin)
            snapshot = snapshot with { Findings = snapshot.Findings.Concat(PolicyEngine.Load(plugin).Evaluate(snapshot).Findings).ToArray() };
        return snapshot;
    }

    private static async Task<Dictionary<string, AnalysisReport>> ExtraReportsAsync(Snapshot snapshot, Options options, CancellationToken token)
    {
        var reports = new Dictionary<string, AnalysisReport>(StringComparer.Ordinal);
        var groups = options.List("evidence");
        if (options.Optional("pack") is { } pack) groups.AddRange(CollectionPack.Load(pack).EvidenceGroups);
        if (groups.Count > 0) reports["evidence"] = await EvidenceCollector.CollectAsync(snapshot, groups, token);
        if (options.Optional("ioc") is { } ioc) reports["ioc"] = await IocAnalyzer.AnalyzeAsync(snapshot, ioc, token);
        if (options.Has("cloud-context"))
        {
            var metadata = await MetadataAsync(options.Optional("provider"), token);
            var hybrid = await HybridAgents.CollectAsync(snapshot, token);
            reports["cloud"] = new("cloud/context", snapshot.CollectedAtUtc, metadata.Findings.Concat(hybrid.Findings).ToArray(), new { instance = metadata.Data, hybrid = hybrid.Data }, (metadata.Warnings ?? []).Concat(hybrid.Warnings ?? []).ToArray());
        }
        return reports;
    }

    private static async Task<int> CloudAsync(string provider, string operation, Options options, CancellationToken token)
    {
        if (operation.Length == 0) throw new CliException("A cloud operation is required.");
        if (operation == "metadata") return await EmitAsync(await MetadataAsync(provider == "cloud" ? options.Optional("provider") : provider, token), options, token);
        if (provider == "cloud")
        {
            provider = options.Get("provider", "auto");
            if (provider == "auto")
            {
                var detected = await MetadataAsync(null, token);
                provider = detected.Kind.Split('/').ElementAtOrDefault(1) ?? "unknown";
                if (provider is not ("aws" or "azure")) throw new CliException("Cloud provider was not detected. Select --provider azure or aws explicitly.");
            }
        }
        var settings = new Dictionary<string, string>(options.Values, StringComparer.Ordinal);
        if (options.Positionals.ElementAtOrDefault(2) is { } resource) settings["resource"] = resource;
        var runner = new TrustedCloudCommandRunner();
        ICloudProvider cloud = provider switch { "aws" => new AwsProvider(runner), "azure" => new AzureProvider(runner), _ => throw new CliException("Provider must be azure or aws.") };
        AnalysisReport report;
        var profiles = options.List("profiles");
        if (provider == "aws" && profiles.Count > 0)
        {
            if (profiles.Count > 20) throw new CliException("At most 20 AWS profiles can be queried per run.");
            var results = new List<AnalysisReport>();
            foreach (var profile in profiles)
            {
                settings["profile"] = profile;
                var result = await cloud.CollectAsync(operation, settings, token);
                results.Add(result with { Warnings = result.Warnings?.Where(w => !w.StartsWith("AWS --accounts filters", StringComparison.Ordinal)).ToArray() });
            }
            report = new($"cloud/aws/{operation}", DateTimeOffset.UtcNow, results.SelectMany(r => r.Findings).ToArray(), new { profilesQueried = profiles.Count, reports = results }, results.SelectMany(r => r.Warnings ?? []).ToArray()) { OperationSucceeded = results.All(r => r.OperationSucceeded) };
        }
        else report = await cloud.CollectAsync(operation, settings, token);
        report = report with { Kind = $"cloud/{provider}/{operation}" };
        var cloudPolicyPath = options.Optional("policy") ?? (File.Exists("opscope.yml") ? "opscope.yml" : null);
        if (cloudPolicyPath is not null)
        {
            var evaluation = PolicyEngine.Load(cloudPolicyPath).Evaluate(report);
            report = report with { Findings = report.Findings.Concat(evaluation.Findings).ToArray(), Warnings = (report.Warnings ?? []).Concat(evaluation.Warnings ?? []).Distinct(StringComparer.Ordinal).ToArray() };
        }
        if (operation is "bundle" or "vm" or "instance")
        {
            var local = await CollectConfiguredAsync(options, token);
            AnalysisReport? metadata = null;
            var linked = false;
            if (options.Has("cloud-context"))
            {
                metadata = await MetadataAsync(provider, token);
                linked = CloudIdentityLinker.Matches(report, metadata.Data);
            }
            var warnings = (report.Warnings ?? []).Concat(metadata?.Warnings ?? []).Concat(local.CollectionWarnings).ToList();
            if (!linked) warnings.Add("Local snapshot and selected cloud resource remain separate evidence sources; no matching instance identity was established.");
            var linkedReport = report with { Findings = report.Findings.Concat(local.Findings).DistinctBy(f => (f.Code, f.Detail)).ToArray(), Data = new { cloudEvidence = report.Data, instanceIdentity = metadata?.Data, sameResourceLinkVerified = linked }, Warnings = warnings };
            if (operation == "bundle")
            {
                var output = await CustodyBundle.WriteAsync(options.Get("out", $"opscope-{provider}-bundle.zip"), local,
                    new(options.Optional("encrypt-public-key"), options.Optional("sign-private-key"), new Dictionary<string, AnalysisReport> { ["cloud"] = linkedReport }), token);
                Console.WriteLine(JsonSerializer.Serialize(new { bundle = output, localAndCloudEvidence = true, sameResourceLinkVerified = linked }, ReportSecurity.JsonOptions));
                return CompletionCode(linkedReport, options) == 2 ? 2 : FailureCode(report.Findings.Concat(local.Findings), options);
            }
            report = linkedReport with { Data = new { localSnapshot = local, cloud = linkedReport.Data } };
        }
        return await EmitAsync(report, options, token);
    }

    private static async Task<AnalysisReport> MetadataAsync(string? provider, CancellationToken token)
    {
        if (provider is null or "auto" or "aws")
        {
            try
            {
                var identity = await new AwsMetadataClient().ReadAsync(true, token);
                if (identity is not null) return new("cloud/aws/metadata", DateTimeOffset.UtcNow, [], identity);
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException or JsonException or OperationCanceledException && !token.IsCancellationRequested) { }
        }
        if (provider is null or "auto" or "azure")
        {
            try { return new("cloud/azure/metadata", DateTimeOffset.UtcNow, [], await AzureMetadata.ReadIdentityAsync(token)); }
            catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException or JsonException or OperationCanceledException && !token.IsCancellationRequested) { }
        }
        token.ThrowIfCancellationRequested();
        return new AnalysisReport("cloud/unknown/metadata", DateTimeOffset.UtcNow, [], null, ["No supported identity metadata endpoint responded. No credentials were queried."]) { OperationSucceeded = false };
    }

    private static async Task<int> ServeAsync(Options options, CancellationToken token)
    {
        var actions = new Dictionary<string, Func<CancellationToken, Task<AnalysisReport>>>(StringComparer.Ordinal);
        foreach (var provider in options.List("cloud"))
        {
            ICloudProvider client = provider switch { "azure" => new AzureProvider(new TrustedCloudCommandRunner()), "aws" => new AwsProvider(new TrustedCloudCommandRunner()), _ => throw new CliException("--cloud supports azure,aws.") };
            var scopes = provider == "aws" ? options.List("profiles") : options.List("subscriptions");
            if (scopes.Count > 20) throw new CliException("At most 20 configured cloud scopes may be exposed in one local session.");
            if (scopes.Count == 0) scopes.Add(string.Empty);
            for (var index = 0; index < scopes.Count; index++)
            {
                var scope = scopes[index];
                var settings = new Dictionary<string, string>(options.Values, StringComparer.Ordinal);
                if (scope.Length > 0)
                {
                    settings[provider == "aws" ? "profile" : "subscription"] = scope;
                    settings.Remove(provider == "aws" ? "profiles" : "subscriptions");
                }
                var label = scopes.Count == 1 && scope.Length == 0 ? provider : $"{provider}-scope-{index + 1}";
                foreach (var operation in new[] { "inventory", "posture", "health", "patches", "cost" })
                {
                    var verb = operation;
                    actions[$"{label}/{verb}"] = async ct =>
                    {
                        var report = await client.CollectAsync(verb, settings, ct);
                        var path = options.Optional("policy") ?? (File.Exists("opscope.yml") ? "opscope.yml" : null);
                        if (path is not null)
                        {
                            var evaluation = PolicyEngine.Load(path).Evaluate(report);
                            report = report with { Findings = report.Findings.Concat(evaluation.Findings).ToArray(), Warnings = (report.Warnings ?? []).Concat(evaluation.Warnings ?? []).ToArray() };
                        }
                        return ReportSecurity.Redact(report);
                    };
                }
            }
        }
        var policyPath = options.Optional("policy") ?? (File.Exists("opscope.yml") ? "opscope.yml" : null);
        if (policyPath is not null) PolicyEngine.Load(policyPath);
        await LocalServer.RunAsync(new ServerOptions
        {
            Port = options.Integer("port", 0, 0, 65535), HistoryPath = options.Optional("history"),
            RetentionCount = options.Integer("retention", 100, 1, 1000), RetentionDays = options.Integer("retention-days", 30, 1, 3650),
            RefreshInterval = TimeSpan.FromSeconds(options.Integer("interval", 30, 5, 86400)),
            CollectAsync = ct => CollectConfiguredAsync(options, ct), CloudActions = actions,
            PolicyView = policyPath is null ? null : () => new { version = 1, enabled = true, validationErrors = PolicyEngine.Load(policyPath).Validate() }
        }, token);
        return 0;
    }

    private static async Task<int> HistoryAsync(Options options, CancellationToken token)
    {
        var path = options.Get("history", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Opscope", "history.sqlite"));
        using var store = new HistoryStore(path, options.Integer("retention", 100, 1, 1000), options.Integer("retention-days", 30, 1, 3650));
        switch (options.Positionals.ElementAtOrDefault(1) ?? "list")
        {
            case "list": return await EmitAsync(new("history", DateTimeOffset.UtcNow, [], store.List()), options, token);
            case "show":
                if (!long.TryParse(RequirePositional(options, 2, "history id"), NumberStyles.None, CultureInfo.InvariantCulture, out var id) || store.Get(id) is not { } snapshot) throw new CliException("History entry not found.");
                return await EmitAsync(new("history/snapshot", snapshot.CollectedAtUtc, snapshot.Findings, snapshot, snapshot.CollectionWarnings), options, token);
            case "prune": store.Prune(); return 0;
            default: throw new CliException("Use history list, history show <id>, or history prune.");
        }
    }

    private static async Task<int> WatchAsync(Options options, CancellationToken token)
    {
        var pages = new[] { "summary", "findings", "processes", "ports", "services" };
        var page = Array.IndexOf(pages, options.Get("page", "summary"));
        if (page < 0) throw new CliException("--page must be summary, findings, processes, ports, or services.");
        var samples = options.Integer("samples", 0, 0, 10000);
        var observed = 0;
        while (!token.IsCancellationRequested)
        {
            var snapshot = await CollectConfiguredAsync(options, token);
            var view = options.Has("full") ? snapshot : Reporter.RedactForOutput(snapshot);
            var refresh = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(options.Integer("interval", 5, 1, 3600));
            var redraw = true;
            do
            {
                if (redraw)
                {
                    if (!Console.IsOutputRedirected) { try { Console.Clear(); } catch (IOException) { } }
                    Console.WriteLine($"opscope TUI | {pages[page]} | warnings {view.CollectionWarnings.Count} | Tab / 1–5: page | Q: quit");
                    switch (pages[page])
                    {
                        case "summary": Reporter.PrintDashboard(view); break;
                        case "findings": Reporter.PrintFindings(view.Findings, view.CollectionWarnings); break;
                        case "processes":
                            foreach (var process in view.Processes) Console.WriteLine($"{process.Id,7} {process.WorkingSetMb,10:F1} MiB {process.CpuTime} {Reporter.SafeDisplay(process.Name)}");
                            break;
                        case "ports":
                            foreach (var listener in view.Listeners) Console.WriteLine($"{Reporter.SafeDisplay(listener.Protocol),6} {Reporter.SafeDisplay(listener.LocalAddress),30} {Reporter.SafeDisplay(listener.Process)}");
                            break;
                        case "services":
                            foreach (var service in view.Services) Console.WriteLine($"{Reporter.SafeDisplay(service.State),18} {Reporter.SafeDisplay(service.Name)}");
                            break;
                    }
                    redraw = false;
                }
                if (samples > 0 && observed + 1 >= samples) return 0;
                if (!Console.IsInputRedirected && Console.KeyAvailable)
                {
                    var key = Console.ReadKey(intercept: true);
                    if (key.Key == ConsoleKey.Q) return 0;
                    if (key.Key == ConsoleKey.Tab) page = (page + 1) % pages.Length;
                    else if (key.KeyChar is >= '1' and <= '5') page = key.KeyChar - '1';
                    redraw = true;
                }
                await Task.Delay(TimeSpan.FromMilliseconds(100), token);
            } while (DateTimeOffset.UtcNow < refresh);
            observed++;
        }
        return 0;
    }

    private static async Task<int> EmitAsync(AnalysisReport report, Options options, CancellationToken token, string defaultFormat = "json")
    {
        var format = options.Get("format", defaultFormat).ToLowerInvariant();
        if (!ReportExporter.Formats.Contains(format, StringComparer.Ordinal)) throw new CliException("Unsupported report format.");
        var redact = !options.Has("full");
        var output = format == "asff"
            ? ReportExporter.ExportAsff(report, options.Required("account"), options.Required("region"), redact)
            : ReportExporter.Export(report, format, redact);
        if (options.Optional("out") is { } path)
        {
            if (format == "asff") await Reporter.WriteTextAtomicallyAsync(path, output, token);
            else await ReportExporter.WriteAsync(path, report, format, redact, token);
        }
        if (!options.Has("quiet"))
        {
            if (format == "pdf") await Console.OpenStandardOutput().WriteAsync(Encoding.Latin1.GetBytes(output), token);
            else Console.WriteLine(output);
        }
        return CompletionCode(report, options);
    }

    private static int CompletionCode(AnalysisReport report, Options options)
    {
        if (!report.OperationSucceeded) return 2;
        if (options.Has("require-complete") && report.Warnings?.Count > 0) return 2;
        return FailureCode(report.Findings, options);
    }

    private static async Task<string> HashBundleAsync(string path, CancellationToken token)
    {
        await using var stream = SnapshotIO.OpenRegularRead(Path.GetFullPath(path));
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(15));
        var buffer = new byte[8192];
        long total = 0;
        int read;
        while ((read = await stream.ReadAsync(buffer, deadline.Token)) > 0)
        {
            total += read;
            if (total > 64 * 1024 * 1024) throw new InvalidDataException("Bundle exceeds 64 MiB.");
            hash.AppendData(buffer, 0, read);
        }
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static int FailureCode(IEnumerable<Finding> findings, Options options) => PolicyEngine.MeetsFailureThreshold(findings, options.Get("fail-on", "warning")) ? 1 : 0;
    private static string RequirePositional(Options options, int index, string description) => options.Positionals.ElementAtOrDefault(index) ?? throw new CliException($"Missing {description}.");

    private sealed class Options
    {
        private static readonly HashSet<string> Flags = new(StringComparer.Ordinal) { "json", "redact", "full", "help", "no-processes", "no-network", "no-services", "quiet", "require-complete", "seal", "confirm-send", "cloud-context", "imds", "metadata" };
        private static readonly HashSet<string> Arguments = new(StringComparer.Ordinal) { "format", "policy", "plugins", "pack", "fail-on", "evidence", "ioc", "baseline", "input", "bundle", "out", "top", "interval", "page", "samples", "scenario", "sign-private-key", "encrypt-public-key", "public-key", "private-key", "provider", "cloud", "subscription", "subscriptions", "profile", "profiles", "region", "regions", "account", "accounts", "resource", "role-arn", "port", "history", "retention", "retention-days", "target", "endpoint", "credential-env", "project", "issue-type", "dcr", "stream", "log-group", "log-stream", "window-hours", "resource-group" };
        public Dictionary<string, string> Values { get; } = new(StringComparer.Ordinal);
        public List<string> Positionals { get; } = [];
        public static Options Parse(string[] args)
        {
            var result = new Options();
            for (var index = 0; index < args.Length; index++)
            {
                var arg = args[index];
                if (arg == "--") { result.Positionals.AddRange(args.Skip(index + 1)); break; }
                if (arg == "-h") arg = "--help";
                if (!arg.StartsWith("--", StringComparison.Ordinal)) { result.Positionals.Add(arg); continue; }
                var pair = arg[2..].Split('=', 2);
                var name = pair[0];
                if (Flags.Contains(name))
                {
                    if (pair.Length > 1) throw new CliException($"--{name} does not accept a value.");
                    result.Values[name] = "true";
                }
                else if (Arguments.Contains(name))
                {
                    var value = pair.Length > 1 ? pair[1] : ++index < args.Length && !args[index].StartsWith("--", StringComparison.Ordinal) ? args[index] : throw new CliException($"--{name} requires a value.");
                    if (value.Length > 8192 || value.Contains('\0')) throw new CliException("Option exceeds the permitted size.");
                    result.Values[name] = value;
                }
                else throw new CliException($"Unknown option --{name}.");
            }
            if (result.Has("full") && result.Has("redact")) throw new CliException("Choose --full or --redact.");
            _ = PolicyEngine.MeetsFailureThreshold([], result.Get("fail-on", "warning"));
            return result;
        }
        public bool Has(string name) => Values.ContainsKey(name);
        public string? Optional(string name) => Values.GetValueOrDefault(name);
        public string Get(string name, string fallback) => Optional(name) ?? fallback;
        public string Required(string name) => Optional(name) is { Length: > 0 } value ? value : throw new CliException($"--{name} is required.");
        public List<string> List(string name) => Get(name, "").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToList();
        public int Integer(string name, int fallback, int minimum, int maximum) => Optional(name) is not { } value ? fallback : int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) && parsed >= minimum && parsed <= maximum ? parsed : throw new CliException($"--{name} must be between {minimum} and {maximum}.");
    }
}
