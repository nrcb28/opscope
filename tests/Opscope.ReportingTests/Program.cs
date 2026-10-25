using System.IO.Compression;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Opscope;

var directory = Path.Combine(Path.GetTempPath(), "opscope-reporting-tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(directory);
var tests = new List<(string Name, Func<Task> Run)>();
Snapshot Fixture() => new(DateTimeOffset.Parse("2026-10-20T12:00:00Z"), new("private-host", "Linux", "Linux", "x64", ".NET", "6.0", DateTimeOffset.Parse("2026-10-19T12:00:00Z"), TimeSpan.FromDays(1), false, 4, "private-user"), 96, new(1000, 50, 950, 95, "test"), [new("disk", "/private/path", "ext4", 1000, 40, 96, true)], [], [new(1, "sample", "private-user", 10, 1, TimeSpan.Zero, "token=unredacted-secret", false)], [new("tcp", "0.0.0.0:8080", "sample", "fixture")], [new("sshd", "stopped", null, "fixture")], new([], true, false, 1), null, [new(FindingSeverity.Critical, "SCRIPT", "<script>alert(1)</script>", "private-host password=secret 192.168.2.3 /home/private-user/file", "Review")], [], TimeSpan.FromSeconds(1));
void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
void Reject(string yaml)
{
    var path = Path.Combine(directory, Guid.NewGuid() + ".yml"); File.WriteAllText(path, yaml);
    try { PolicyEngine.Load(path); throw new InvalidOperationException("Unsafe YAML accepted: " + yaml); } catch (InvalidDataException) { }
    try { PolicyEngine.Parse(yaml); throw new InvalidOperationException("Unsafe in-memory YAML accepted: " + yaml); } catch (InvalidDataException) { }
}
string Write(string name, string text) { var path = Path.Combine(directory, name); File.WriteAllText(path, text); return path; }
async Task Rehash(string path) => await File.WriteAllTextAsync(path + ".sha256", Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path))).ToLowerInvariant() + "\n");

tests.Add(("bounded strict policy parsing and declarative execution", () =>
{
    var policy = PolicyEngine.Load(Write("policy.yml", "version: 1\nthresholds:\n  cpuWarningPercent: 70\n  cpuCriticalPercent: 90\nallowedPorts: [22]\nrequiredServices: [sshd]\nrules:\n  - id: firewall\n    metric: firewall.active\n    operator: '=='\n    value: 0\n    severity: critical\n"));
    var report = policy.Evaluate(Fixture());
    foreach (var code in new[] { "POLICY_CPU", "POLICY_MEMORY", "POLICY_DISK", "POLICY_PORT", "POLICY_SERVICE", "RULE_firewall" }) Check(report.Findings.Any(f => f.Code == code), "Missing " + code);
    Check(PolicyEngine.MeetsFailureThreshold(report.Findings, "critical") && !PolicyEngine.MeetsFailureThreshold(report.Findings, "none"), "Severity threshold failed");
    Check(PolicyEngine.Parse("version: 1\nallowedPorts: [22]\n").Validate().Count == 0, "Valid in-memory policy failed");
    if (OperatingSystem.IsLinux())
        try { PolicyEngine.Load("/dev/null"); throw new InvalidOperationException("Device policy file accepted"); } catch (InvalidDataException) { }
    try { PolicyEngine.Parse(null!); throw new InvalidOperationException("Null in-memory YAML accepted"); } catch (ArgumentNullException) { }
    Reject(""); Reject("null"); Reject("thresholds: null"); Reject("rules: *undefined"); Reject(new string('x', 128 * 1024 + 1));
    Reject("version: 1\nversion: 1\n"); Reject("command: curl malicious\n"); Reject("rules: &rules []\n"); Reject("!!System.Object {}\n"); Reject("version: 1\n---\nversion: 1\n"); Reject("thresholds:\n  memoryWarningPercent: 99\n  memoryCriticalPercent: 90\n"); Reject("allowedPorts: [0, 65536]\n"); Reject("rules:\n  - id: shell\n    metric: command\n");
    Reject("rules: " + new string('[', 20) + new string(']', 20));
    var servicePolicy = new PolicyEngine(new PolicyDocument { RequiredServices = ["sshd"], Rules = [new DeclarativeRule { Id = "running-service-count", Metric = "services.runningCount", Operator = "==", Value = 1 }] });
    foreach (var state in new[] { "active/running", "RUNNING", "active" })
    {
        var running = servicePolicy.Evaluate(Fixture() with { Services = [new("sshd", state, null, "fixture")] });
        Check(!running.Findings.Any(f => f.Code == "POLICY_SERVICE") && running.Findings.Any(f => f.Code == "RULE_running-service-count"), "Running service state was misclassified: " + state);
    }
    return Task.CompletedTask;
}));
tests.Add(("cloud policies share normalized metrics across providers and preserve unknown coverage", () =>
{
    var policy = PolicyEngine.Parse("version: 1\nrules:\n  - id: resources\n    metric: cloud.resourceCount\n    operator: '=='\n    value: 2\n  - id: warning-count\n    metric: cloud.warningCount\n    operator: '=='\n    value: 1\n  - id: critical-count\n    metric: cloud.criticalCount\n    operator: '=='\n    value: 1\n  - id: local-only\n    metric: cpu.usedPercent\n    value: 0\n");
    foreach (var provider in new[] { "azure", "aws" })
    {
        var resources = new[] { new { provider, account = "123456789012", region = "eu-west-1", id = "first", type = "machine" }, new { provider, account = "123456789012", region = "eu-west-1", id = "second", type = "disk" } };
        var source = new AnalysisReport("cloud/" + provider, Fixture().CollectedAtUtc, [new(FindingSeverity.Warning, "W", "Warning", "Evidence", "Review"), new(FindingSeverity.Critical, "C", "Critical", "Evidence", "Review")], new { reports = new[] { new { data = new { provider, resources } }, new { data = new { provider, resources } } } });
        var result = policy.Evaluate(source);
        Check(result.Findings.Count == 3 && result.Findings.All(finding => finding.Code.StartsWith("RULE_", StringComparison.Ordinal)), "Cloud policy metrics differed for " + provider);
        Check(result.Warnings?.Any(warning => warning.Contains("local snapshot", StringComparison.Ordinal)) == true, "Local-only cloud rule lacked a coverage warning");
        var unknown = policy.Evaluate(source with { Data = new { unexpected = true } });
        Check(!unknown.Findings.Any(finding => finding.Code == "RULE_resources") && unknown.Warnings?.Any(warning => warning.Contains("not evaluated", StringComparison.Ordinal)) == true, "Unknown cloud evidence was treated as an empty inventory");
        var redacted = policy.Evaluate(source with { Data = new { provider, resources = new[] { new { provider, account = "[redacted-account]", region = "eu-west-1", id = "[redacted-id]", type = "machine" } } } });
        Check(!redacted.Findings.Any(finding => finding.Code == "RULE_resources") && redacted.Warnings?.Any(warning => warning.Contains("redacted", StringComparison.Ordinal)) == true, "Redacted resource identities produced an exact-count claim");
    }
    var emptyPolicy = PolicyEngine.Parse("version: 1\nrules:\n  - id: empty\n    metric: cloud.resourceCount\n    operator: '=='\n    value: 0\n");
    var empty = emptyPolicy.Evaluate(new AnalysisReport("cloud/aws", Fixture().CollectedAtUtc, [], new { provider = "aws", resources = Array.Empty<object>() }));
    Check(empty.Findings.Any(finding => finding.Code == "RULE_empty"), "Known empty cloud inventory was confused with unavailable data");
    return Task.CompletedTask;
}));
tests.Add(("safe inherited packs reject traversal and cycles", () =>
{
    Write("base.yml", "name: base\ncollectors: [host, cpu, memory]\n");
    var pack = CollectionPack.Load(Write("pack.yml", "name: incident\nextends: base.yml\ncollectors: [network, logs, accounts]\n"));
    Check(pack.Collectors.Count == 6 && pack.ToCollectorOptions().IncludeNetwork && !pack.ToCollectorOptions().IncludeProcesses && pack.EvidenceGroups.Contains("logs"), "Pack groups were not merged");
    foreach (var yaml in new[] { "name: bad\ncollectors: [shell]\n", "name: bad\nextends: ../outside.yml\n", "name: cycle\nextends: pack-cycle.yml\n" })
    {
        var path = Write("pack-cycle.yml", yaml); try { CollectionPack.Load(path); throw new InvalidOperationException("Unsafe pack accepted"); } catch (InvalidDataException) { }
    }
    return Task.CompletedTask;
}));
tests.Add(("standard output schemas and escaped markup", async () =>
{
    var snapshot = Fixture();
    using var sarif = JsonDocument.Parse(ReportExporter.Export(snapshot, "sarif")); var root = sarif.RootElement;
    Check(root.GetProperty("version").GetString() == "2.1.0" && root.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver").GetProperty("name").GetString() == "Opscope", "Invalid SARIF tool/version");
    var result = root.GetProperty("runs")[0].GetProperty("results")[0]; Check(result.GetProperty("level").GetString() == "error" && result.GetProperty("message").GetProperty("text").GetString() is not null, "Invalid SARIF result");
    var junit = XDocument.Parse(ReportExporter.Export(snapshot, "junit")); Check(junit.Root?.Name == "testsuites" && junit.Descendants("failure").Count() == 1 && (string?)junit.Descendants("testsuite").Single().Attribute("failures") == "1", "Invalid JUnit schema");
    var html = ReportExporter.Export(snapshot, "html"); Check(!html.Contains("<script>", StringComparison.Ordinal) && html.Contains("&lt;script&gt;", StringComparison.Ordinal) && html.Contains("@media print", StringComparison.Ordinal), "HTML escaping/print CSS failed");
    foreach (var format in new[] { "json", "sarif", "junit", "html", "csv", "jsonl", "cef", "asff" })
    {
        var text = ReportExporter.Export(snapshot, format); Check(!text.Contains("private-host", StringComparison.Ordinal) && !text.Contains("unredacted-secret", StringComparison.Ordinal), "Redaction failed for " + format);
    }
    var structured = new AnalysisReport("evidence", snapshot.CollectedAtUtc, [], new { count = 3, token = "never-export-me", hostname = "confidential-host", items = new[] { new { metric = 12, detail = "password=never-export-me" } } });
    var structuredJson = ReportExporter.Export(structured, "json");
    using (var parsed = JsonDocument.Parse(structuredJson)) Check(parsed.RootElement.GetProperty("data").GetProperty("count").GetInt32() == 3, "Analysis evidence was discarded");
    Check(!structuredJson.Contains("never-export-me", StringComparison.Ordinal) && !structuredJson.Contains("confidential-host", StringComparison.Ordinal), "Structured analysis redaction failed");
    var report = new AnalysisReport("test", snapshot.CollectedAtUtc, [new(FindingSeverity.Warning, "CODE|X", "=dangerous", "line\nfield=value", "review")]);
    Check(ReportExporter.Export(report, "csv").Contains("'=dangerous", StringComparison.Ordinal), "CSV formula injection guard failed");
    var cef = ReportExporter.Export(report, "cef"); Check(cef.Contains("CODE\\|X", StringComparison.Ordinal) && cef.Contains("line\\nfield\\=value", StringComparison.Ordinal) && cef.Count(c => c == '\n') == 1, "CEF escaping failed");
    using var asff = JsonDocument.Parse(ReportExporter.Export(snapshot, "asff")); var finding = asff.RootElement.GetProperty("Findings")[0];
    foreach (var property in new[] { "SchemaVersion", "Id", "ProductArn", "GeneratorId", "AwsAccountId", "Types", "CreatedAt", "UpdatedAt", "Severity", "Title", "Description", "Resources" }) Check(finding.TryGetProperty(property, out _), "Missing ASFF " + property);
    using (var configuredAsff = JsonDocument.Parse(ReportExporter.ExportAsff(snapshot, "123456789012", "eu-west-1")))
    {
        var configured = configuredAsff.RootElement.GetProperty("Findings")[0];
        Check(configured.GetProperty("AwsAccountId").GetString() == "123456789012" && configured.GetProperty("ProductArn").GetString() == "arn:aws:securityhub:eu-west-1:123456789012:product/123456789012/default", "Configured ASFF account and region were not used");
        Check(configured.GetProperty("Resources")[0].GetProperty("Region").GetString() == "eu-west-1" && !configured.GetProperty("ProductFields").TryGetProperty("opscope/notice", out _), "Configured ASFF retained placeholders");
    }
    using (var chinaAsff = JsonDocument.Parse(ReportExporter.ExportAsff(report, "123456789012", "cn-north-1"))) Check(chinaAsff.RootElement.GetProperty("Findings")[0].GetProperty("ProductArn").GetString()!.StartsWith("arn:aws-cn:", StringComparison.Ordinal), "ASFF partition is wrong");
    foreach (var (account, region) in new[] { ("000000000000", "us-east-1"), ("1234", "us-east-1"), ("123456789012", "us-east-1\nmalicious"), ("123456789012", "us-east-1\n"), ("123456789012\n", "us-east-1"), ("123456789012", "BAD") })
        try { ReportExporter.ExportAsff(report, account, region); throw new InvalidOperationException("Invalid ASFF context accepted"); } catch (ArgumentException) { }
    foreach (var line in ReportExporter.Export(snapshot, "jsonl").Split('\n', StringSplitOptions.RemoveEmptyEntries)) using (JsonDocument.Parse(line)) { }
    var warningDiff = new DiffReport("a", "b", snapshot.CollectedAtUtc, snapshot.CollectedAtUtc, false, [], [], ["Service identities are redacted; only service state counts were compared."]);
    using (var diffSarif = JsonDocument.Parse(ReportExporter.Export(warningDiff, "sarif"))) Check(diffSarif.RootElement.GetProperty("runs")[0].GetProperty("invocations")[0].GetProperty("toolExecutionNotifications").GetArrayLength() == 1, "Diff coverage warning was lost in export");
    var pdfPath = Path.Combine(directory, "report.pdf"); await ReportExporter.WriteAsync(pdfPath, snapshot, "pdf"); var pdf = await File.ReadAllTextAsync(pdfPath, Encoding.Latin1); Check(pdf.StartsWith("%PDF-1.4", StringComparison.Ordinal) && pdf.EndsWith("%%EOF\n", StringComparison.Ordinal) && pdf.Contains("xref", StringComparison.Ordinal), "Invalid standalone PDF");
}));
tests.Add(("nested credential fields and repeated secrets stay redacted", () =>
{
    foreach (var key in new[] { "password", "passwd", "pwd", "apiKey", "api_key", "connectionString" })
    {
        var secret = "credential-sentinel-" + key;
        var report = new AnalysisReport("evidence", Fixture().CollectedAtUtc,
            [new(FindingSeverity.Warning, "CREDENTIAL", "Review", "Observed " + secret, "Rotate " + secret)],
            new { nested = new Dictionary<string, object> { [key] = secret, ["message"] = "Observed " + secret }, count = 7 }, ["Warning: " + secret]);
        var text = ReportExporter.Export(report, "json");
        Check(!text.Contains(secret, StringComparison.Ordinal), "Credential field or repeated secret leaked: " + key);
        using var json = JsonDocument.Parse(text);
        Check(json.RootElement.GetProperty("data").GetProperty("count").GetInt32() == 7, "Secret redaction removed numeric evidence");
    }
    foreach (var assignment in new[] { "password=\"quoted credential sentinel\"", "pwd='single quoted credential sentinel'", "api_key=\"another credential sentinel\"", """{"token":"first \"quoted\" credential sentinel"}""" })
    {
        var text = Reporter.RedactEvidenceText(assignment);
        Check(!text.Contains("credential sentinel", StringComparison.Ordinal) && text.Contains("redacted-secret", StringComparison.Ordinal), "Quoted credential was only partly redacted: " + text);
    }
    Check(!Reporter.RedactEvidenceText("private-prefix-value", "private", "private-prefix-value").Contains("prefix-value", StringComparison.Ordinal), "Short identifier replacement exposed a suffix of the longer secret");
    return Task.CompletedTask;
}));
tests.Add(("deep identifiers retain redaction context in findings", () =>
{
    JsonNode data = new JsonObject { ["id"] = "deep-resource-identifier-sentinel" };
    for (var depth = 0; depth < 26; depth++) data = new JsonObject { ["nested"] = data };
    var report = new AnalysisReport("evidence", Fixture().CollectedAtUtc,
        [new(FindingSeverity.Warning, "DEEP", "Review", "Resource deep-resource-identifier-sentinel", "Review")], data);
    Check(!ReportExporter.Export(report, "json").Contains("deep-resource-identifier-sentinel", StringComparison.Ordinal), "Nested identifier leaked through findings");
    return Task.CompletedTask;
}));
tests.Add(("redaction context overflow omits text with an explicit coverage warning", () =>
{
    const string secret = "context-overflow-credential-sentinel";
    var resources = Enumerable.Range(0, 1024).Select(index => new { name = "context-resource-" + index }).ToArray();
    var report = new AnalysisReport("evidence", Fixture().CollectedAtUtc,
        [new(FindingSeverity.Warning, "CONTEXT", "Review", "Observed " + secret, "Rotate " + secret)],
        new { resources, password = secret, message = "Observed " + secret, records = new Dictionary<string, int> { [secret] = 3 }, count = 7 }, ["Warning: " + secret]);
    var text = ReportExporter.Export(report, "json");
    Check(!text.Contains(secret, StringComparison.Ordinal), "Context overflow exposed credential text or a dictionary key");
    using var json = JsonDocument.Parse(text);
    Check(json.RootElement.GetProperty("data").GetProperty("count").GetInt32() == 7 && json.RootElement.GetProperty("findings")[0].GetProperty("severity").GetInt32() == (int)FindingSeverity.Warning, "Context overflow discarded numeric evidence or severity");
    Check(json.RootElement.GetProperty("warnings").EnumerateArray().Any(warning => warning.GetString()!.Contains("Redaction context", StringComparison.Ordinal)), "Context overflow lacks an explicit coverage warning");
    var complete = ReportSecurity.Redact(report with { Data = new { resources }, Findings = [], Warnings = [] });
    Check(complete.Warnings?.Count == 0, "Exactly 1024 fully collected identifiers were reported as incomplete");
    var ordinary = ReportSecurity.Redact(report with { Data = new { tags = new { environment = "QA" } },
        Findings = [new(FindingSeverity.Warning, "CONTROL", "Review", "Review collected evidence", "Review")], Warnings = [] });
    Check(ordinary.Warnings?.Count == 0 && ordinary.Findings[0].Code == "CONTROL", "Short metadata caused a spurious context limit or discarded finding text");
    return Task.CompletedTask;
}));
tests.Add(("manifest tampering detected after recomputing outer hash", async () =>
{
    var path = Path.Combine(directory, "plain.zip"); await CustodyBundle.WriteAsync(path, Fixture());
    var valid = await CustodyBundle.VerifyAsync(path); Check(valid.IsValid && !valid.IsSigned, string.Join(";", valid.Errors));
    using (var archive = ZipFile.Open(path, ZipArchiveMode.Update))
    {
        archive.GetEntry("snapshot.json")!.Delete(); var entry = archive.CreateEntry("snapshot.json"); using var writer = new StreamWriter(entry.Open()); writer.Write("{}");
    }
    await Rehash(path); var tampered = await CustodyBundle.VerifyAsync(path); Check(!tampered.IsValid && tampered.Errors.Any(e => e.Contains("hash", StringComparison.Ordinal)), "Manifest accepted modified evidence");
    var unsafePath = Path.Combine(directory, "unsafe.zip"); await CustodyBundle.WriteAsync(unsafePath, Fixture());
    using (var archive = ZipFile.Open(unsafePath, ZipArchiveMode.Update)) { var entry = archive.CreateEntry("../escaped"); using var writer = new StreamWriter(entry.Open()); writer.Write("unsafe"); }
    await Rehash(unsafePath); Check(!(await CustodyBundle.VerifyAsync(unsafePath)).IsValid && !File.Exists(Path.Combine(directory, "escaped")), "Unsafe archive name accepted");
}));
tests.Add(("bundle verification rejects FIFO inputs without blocking", async () =>
{
    if (!OperatingSystem.IsLinux()) return;
    var fifo = Path.Combine(directory, "archive.fifo");
    var start = new ProcessStartInfo("/usr/bin/mkfifo") { UseShellExecute = false }; start.ArgumentList.Add(fifo);
    using (var process = Process.Start(start) ?? throw new InvalidOperationException("Unable to create FIFO fixture")) { await process.WaitForExitAsync(); Check(process.ExitCode == 0, "mkfifo fixture failed"); }
    var verification = await CustodyBundle.VerifyAsync(fifo).WaitAsync(TimeSpan.FromSeconds(2));
    Check(!verification.IsValid && verification.Errors.Any(error => error.Contains("regular", StringComparison.OrdinalIgnoreCase)), "FIFO archive was not rejected as a non-regular file");
}));
tests.Add(("RSA signature and AES-GCM encryption round trip", async () =>
{
    using var rsa = RSA.Create(2048); using var other = RSA.Create(2048);
    var privateKey = Write("private.pem", rsa.ExportPkcs8PrivateKeyPem()); var publicKey = Write("public.pem", rsa.ExportSubjectPublicKeyInfoPem()); var wrongKey = Write("wrong.pem", other.ExportSubjectPublicKeyInfoPem());
    var path = Path.Combine(directory, "sealed.enc"); await CustodyBundle.WriteAsync(path, Fixture(), new(publicKey, privateKey));
    var valid = await CustodyBundle.VerifyAsync(path, publicKey, privateKey); Check(valid.IsValid && valid.IsSigned && valid.IsEncrypted && valid.SignatureVerified, string.Join(";", valid.Errors));
    Check(!(await CustodyBundle.VerifyAsync(path, wrongKey, privateKey)).IsValid, "Wrong signer accepted");
    Check(!(await CustodyBundle.VerifyAsync(path, publicKey)).IsValid, "Encrypted verification accepted without private key");
    var decrypted = Path.Combine(directory, "decrypted.zip"); await CustodyBundle.DecryptAsync(path, decrypted, privateKey); Check((await CustodyBundle.VerifyAsync(decrypted, publicKey)).IsValid, "Decrypted bundle signature invalid");
    using (var zip = ZipFile.OpenRead(decrypted)) Check(zip.Entries.All(e => !e.FullName.EndsWith(".pem", StringComparison.Ordinal)), "A cryptographic key leaked into the archive");
    using (var archive = ZipFile.Open(decrypted, ZipArchiveMode.Update)) { archive.GetEntry("manifest.sig")!.Delete(); var entry = archive.CreateEntry("manifest.sig"); using var stream = entry.Open(); stream.Write(new byte[256]); }
    await Rehash(decrypted); Check(!(await CustodyBundle.VerifyAsync(decrypted, publicKey)).IsValid, "Invalid signature accepted");
    if (!OperatingSystem.IsWindows()) Check((File.GetUnixFileMode(path) & (UnixFileMode.GroupRead | UnixFileMode.OtherRead | UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) == 0, "Bundle file permissions are not private");
}));
var failed = 0;
try { foreach (var (name, run) in tests) try { await run(); Console.WriteLine("PASS " + name); } catch (Exception exception) { failed++; Console.Error.WriteLine("FAIL " + name + ": " + exception); } }
finally { Directory.Delete(directory, true); }
return failed == 0 ? 0 : 1;
