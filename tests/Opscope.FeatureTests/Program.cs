using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using Opscope;

var temporary = Path.Combine(Path.GetTempPath(), "opscope-feature-tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(temporary);
var cases = new List<(string Name, Func<Task> Run)>();
var failures = 0;
void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
Snapshot Fixture() => new(DateTimeOffset.UtcNow, new("fixture-host", "Linux", "Linux", "x64", ".NET", "6", DateTimeOffset.UtcNow, TimeSpan.Zero, false, 1, "fixture-user"), 5, new(100, 95, 5, 5, "fixture"), [], [], [], [], [], new([], true, true, 0), new([]), [new(FindingSeverity.Info, "TEST", "Test", "Detail", "Review")], [], TimeSpan.Zero);
void RejectMalformed(Action<JsonObject> mutate)
{
    var json = JsonNode.Parse(Reporter.ToJson(Fixture()))!.AsObject(); mutate(json);
    try { Reporter.ParseSnapshot(json.ToJsonString()); throw new InvalidOperationException("Malformed snapshot was accepted: " + json.ToJsonString()); }
    catch (Exception exception) when (exception is InvalidDataException or System.Text.Json.JsonException) { }
}
cases.Add(("snapshot validates nested required fields before downstream use", () =>
{
    RejectMalformed(json => json["host"]!["osDescription"] = null);
    RejectMalformed(json => json["findings"]![0]!["detail"] = null);
    RejectMalformed(json => json["tooling"]!["tools"] = new JsonArray((JsonNode?)null));
    RejectMalformed(json => json["security"]!["firewalls"] = new JsonArray((JsonNode?)null));
    RejectMalformed(json => json["listeners"] = new JsonArray(new JsonObject { ["protocol"] = "tcp", ["localAddress"] = null, ["process"] = "p", ["source"] = "fixture" }));
    return Task.CompletedTask;
}));
cases.Add(("structured report redacts sensitive dictionary keys", () =>
{
    var report = new AnalysisReport("evidence", DateTimeOffset.UtcNow, [], new Dictionary<string, object> { ["/home/private-user/private-file"] = new { count = 2 }, ["192.168.78.44"] = new { count = 1 } });
    var text = ReportSecurity.Serialize(report);
    Check(!text.Contains("private-user", StringComparison.Ordinal) && !text.Contains("192.168.78.44", StringComparison.Ordinal), "Dictionary keys expose paths or addresses: " + text);
    return Task.CompletedTask;
}));
cases.Add(("JSON log text and authorization headers redact credentials", () =>
{
    var report = new AnalysisReport("logs", DateTimeOffset.UtcNow, [], new { messages = new[] { "{\"token\":\"never-export-json-value\"}", "Authorization: Bearer never-export-bearer-value" } });
    var text = ReportSecurity.Serialize(report);
    Check(!text.Contains("never-export-json-value", StringComparison.Ordinal) && !text.Contains("never-export-bearer-value", StringComparison.Ordinal), "Log text exposes credentials: " + text);
    return Task.CompletedTask;
}));
cases.Add(("nested snapshot redaction drops command lines before export", () =>
{
    var snapshot = Fixture() with { Processes = [new(42, "curl", "private-user", 1, 1, TimeSpan.Zero, "curl -u private-user:never-export-command-secret", false)] };
    var text = ReportSecurity.Serialize(new AnalysisReport("handoff", DateTimeOffset.UtcNow, [], new { snapshot, bundleSha256 = new string('a', 64) }));
    Check(!text.Contains("never-export-command-secret", StringComparison.Ordinal), "Nested snapshot command line was exported: " + text);
    return Task.CompletedTask;
}));
cases.Add(("text redaction preserves durations while removing network endpoints", () =>
{
    var text = Reporter.RedactEvidenceText("Elapsed 00:00:00; socket [2001:db8::1]:443");
    Check(text.Contains("00:00:00", StringComparison.Ordinal) && !text.Contains("2001:db8", StringComparison.Ordinal), "Duration or endpoint redaction is incorrect: " + text);
    return Task.CompletedTask;
}));
cases.Add(("redacted service baselines roundtrip and compare aggregate state changes", () =>
{
    var current = Fixture() with { Services = [new("alpha", "active/running", null, "fixture"), new("beta", "active/running", null, "fixture"), new("gamma", "inactive/dead", null, "fixture")] };
    var baseline = Reporter.ParseSnapshot(Reporter.ToJson(current, true));
    Check(baseline.Services.Count == 3 && baseline.Services.All(service => service.Name == "[redacted-service]"), "Redacted services were not retained");
    var unchanged = DiffEngine.Compare(baseline, current);
    Check(!unchanged.Changes.Any(change => change.Category is "host" or "service") && unchanged.Warnings?.Any(warning => warning.Contains("state counts", StringComparison.Ordinal)) == true, "Redacted baseline caused false identity drift or lost coverage warnings");
    var changed = current with { Services = [current.Services[0] with { State = "inactive/dead" }, current.Services[1], current.Services[2]] };
    var diff = DiffEngine.Compare(baseline, changed);
    Check(diff.Significant && diff.Changes.Any(change => change.Category == "service" && change.Details.Contains("count", StringComparison.Ordinal)), "Changed redacted service state counts were missed");
    return Task.CompletedTask;
}));
cases.Add(("drift identifies disabled firewall as a security change", () =>
{
    var before = Fixture();
    var after = before with { Security = before.Security with { HasActiveFirewall = false, ProtectionVerified = false } };
    var diff = DiffEngine.Compare(before, after);
    Check(diff.Significant && diff.Changes.Any(change => change.Category == "security" && change.Identity == "firewall.active"), "Firewall disablement was missed");
    return Task.CompletedTask;
}));
cases.Add(("numeric percentages survive evidence redaction", () =>
{
    var text = Reporter.RedactEvidenceText("CPU 95.5% memory 84.25%; remote 10.20.30.40");
    Check(text.Contains("95.5%", StringComparison.Ordinal) && text.Contains("84.25%", StringComparison.Ordinal) && !text.Contains("10.20.30.40", StringComparison.Ordinal), "Percentage or IP redaction is incorrect: " + text);
    return Task.CompletedTask;
}));
cases.Add(("cloud identities in findings use structured-data redaction context", () =>
{
    const string resourceId = "arn:aws:ec2:eu-west-1:123456789012:instance/i-0123456789abcdef0";
    var report = new AnalysisReport("cloud/aws", DateTimeOffset.UtcNow, [new(FindingSeverity.Warning, "CLOUD", "Review " + resourceId, "Host customer-private-host at 10.20.30.40", "Review " + resourceId)], new { resources = new[] { new { id = resourceId, name = "customer-private-host", privateIp = "10.20.30.40" } } });
    var text = ReportSecurity.Serialize(report);
    Check(!text.Contains(resourceId, StringComparison.Ordinal) && !text.Contains("123456789012", StringComparison.Ordinal) && !text.Contains("customer-private-host", StringComparison.Ordinal) && !text.Contains("10.20.30.40", StringComparison.Ordinal), "Structured cloud identity leaked into output: " + text);
    return Task.CompletedTask;
}));
cases.Add(("cloud identifier arrays and failed-query resource scope remain private", () =>
{
    const string subscription = "11111111-1111-1111-1111-111111111111";
    var report = new AnalysisReport("cloud", DateTimeOffset.UtcNow,
        [new(FindingSeverity.Info, "SCOPE", "Scope", $"Subscription {subscription}", "Review")],
        new { subscriptions = new[] { subscription }, accounts = new[] { "123456789012" }, scope = new { resource = "private-requested-vm" }, resources = new[] { new { name = "resources", id = "private-vm-id" } } });
    var text = ReportSecurity.Serialize(report);
    Check(!text.Contains(subscription, StringComparison.Ordinal) && !text.Contains("123456789012", StringComparison.Ordinal) && !text.Contains("private-requested-vm", StringComparison.Ordinal), "Identifier arrays/scope leaked");
    var json = JsonNode.Parse(text)!;
    Check(json["data"]!["resources"] is JsonArray, "A resource named resources corrupted the schema key");
    Check(json["data"]!["resources"]![0]!["name"]!.GetValue<string>() != "resources", "Resource name was not redacted");
    return Task.CompletedTask;
}));
cases.Add(("snapshot IO enforces byte and text limits", async () =>
{
    var huge = Path.Combine(temporary, "huge.json");
    await using (var file = new FileStream(huge, FileMode.CreateNew, FileAccess.Write)) file.SetLength(SnapshotIO.MaximumBytes + 1L);
    try { await SnapshotIO.ReadTextAsync(huge); throw new InvalidOperationException("Oversized file accepted"); } catch (InvalidDataException) { }
    var valid = Path.Combine(temporary, "valid.json"); await File.WriteAllTextAsync(valid, Reporter.ToJson(Fixture()));
    Check((await SnapshotIO.ReadAsync(valid)).Host.Hostname == "fixture-host", "Valid snapshot IO failed");
    var invalidUtf8 = Path.Combine(temporary, "utf8.json"); await File.WriteAllBytesAsync(invalidUtf8, [0xff, 0xfe]);
    try { await SnapshotIO.ReadTextAsync(invalidUtf8); throw new InvalidOperationException("Malformed UTF8 accepted"); } catch (DecoderFallbackException) { }
    try { SnapshotIO.ValidateJson("{\"text\":\"" + new string('x', 65537) + "\"}"); throw new InvalidOperationException("Oversized text accepted"); } catch (InvalidDataException) { }
}));
cases.Add(("snapshot IO rejects FIFOs and device files promptly", async () =>
{
    if (!OperatingSystem.IsLinux()) return;
    foreach (var path in new[] { "/dev/null", temporary })
        try { await SnapshotIO.ReadTextAsync(path); throw new InvalidOperationException("Special input file accepted"); } catch (InvalidDataException) { }
    var fifo = Path.Combine(temporary, "input.fifo");
    var start = new ProcessStartInfo("/usr/bin/mkfifo") { UseShellExecute = false }; start.ArgumentList.Add(fifo);
    using (var process = Process.Start(start) ?? throw new InvalidOperationException("mkfifo failed")) { await process.WaitForExitAsync(); Check(process.ExitCode == 0, "mkfifo returned nonzero"); }
    var elapsed = Stopwatch.StartNew();
    try { await SnapshotIO.ReadTextAsync(fifo).WaitAsync(TimeSpan.FromSeconds(2)); throw new InvalidOperationException("FIFO accepted"); } catch (InvalidDataException) { }
    Check(elapsed.Elapsed < TimeSpan.FromSeconds(2), "FIFO validation blocked");
}));
try
{
    foreach (var (name, run) in cases)
        try { await run(); Console.WriteLine("PASS " + name); }
        catch (Exception exception) { failures++; Console.Error.WriteLine("FAIL " + name + ": " + exception.Message); }
}
finally { Directory.Delete(temporary, true); }
return failures == 0 ? 0 : 1;
