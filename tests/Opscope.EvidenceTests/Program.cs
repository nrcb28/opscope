using System.Diagnostics;
using System.Security.Cryptography;
using Opscope;
using Opscope.Evidence;

var snapshot = Create("host-a", 10, 30);
var csv = IocAnalyzer.Parse("type,value,label\r\nip,198.51.100.10,\"address, exact\"\r\ndomain,evil.example,domain\r\nprocess,suspicious,process\r\n", "csv");
Assert(csv.Indicators.Count == 3 && csv.Indicators[0].Label == "address, exact", "CSV quoted label");
var ioc = IocAnalyzer.Analyze(snapshot, csv.Indicators);
Assert(ioc.Findings.Count == 3, "IP, domain, process observable matching");
Assert(((IocData)ioc.Data!).Matches.Count == 3, "structured IoC matches");
Assert(IocAnalyzer.Analyze(snapshot, [new IocIndicator("ip", "198.51.100.1")]).Findings.Count == 0, "IP prefix is not an exact match");
Assert(IocAnalyzer.Analyze(snapshot, [new IocIndicator("domain", "vil.example")]).Findings.Count == 0, "domain suffix is not an exact match");
Assert(IocAnalyzer.Analyze(snapshot, [new IocIndicator("process", "SUSPICIOUS")]).Findings.Count == 0, "Linux process names are case sensitive");
Assert(IocAnalyzer.Analyze(snapshot with { Host = snapshot.Host with { Platform = "windows" } }, [new IocIndicator("process", "SUSPICIOUS")]).Findings.Count == 1, "Windows process names ignore case");
Assert(IocAnalyzer.Analyze(snapshot with { Host = snapshot.Host with { Platform = "windows" } }, [new IocIndicator("process", "suspicious.exe")]).Findings.Count == 1, "Windows executable suffix matches ProcessName convention");
Assert(IocAnalyzer.Analyze(snapshot, [new IocIndicator("sha256", new string('a', 64))]).Warnings!.Any(warning => warning.Contains("hashes could not", StringComparison.Ordinal)), "offline hashes are explicitly unevaluated");
Throws<InvalidDataException>(() => IocAnalyzer.Parse("type,value\nprocess,\"unfinished", "csv"), "malformed quoted CSV rejected");
Throws<InvalidDataException>(() => IocAnalyzer.Parse("type,value\nip,not-an-ip", "csv"), "invalid IP rejected");
Throws<InvalidDataException>(() => IocAnalyzer.Parse("type,value\nprocess,/bin/evil", "csv"), "process path is not a command");
var stix = IocAnalyzer.Parse("""
{"type":"bundle","objects":[
 {"type":"indicator","pattern_type":"stix","pattern":"[ipv4-addr:value = '198.51.100.10']"},
 {"type":"indicator","pattern_type":"stix","pattern":"[domain-name:value = 'evil.example'] AND [process:name = 'suspicious']"},
 {"type":"file","hashes":{"SHA-256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
]}
""", "stix");
Assert(stix.Indicators.Count == 2 && stix.Warnings.Any(warning => warning.Contains("compound", StringComparison.Ordinal)), "STIX simple patterns work and compound patterns are not partially evaluated");

var exposure = EvidenceCollector.EvaluateSnapshotSecurity(snapshot);
Assert(exposure.Findings.Any(finding => finding.Code == "SSH_NON_LOOPBACK_LISTENER"), "SSH non-loopback binding finding");
Assert(!exposure.Findings.Any(finding => finding.Code == "RDP_NON_LOOPBACK_LISTENER"), "loopback RDP is not reported exposed");
Assert(EvidenceCollector.InspectSshConfiguration("PermitRootLogin no\n").State == "pass", "explicit root-login prohibition");
Assert(EvidenceCollector.InspectSshConfiguration("Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no").State == "not_evaluated", "SSH includes prevent misleading static pass");
Assert(EvidenceCollector.InspectSshConfiguration("Match User root\nPermitRootLogin no").State == "not_evaluated", "SSH Match prevents misleading static pass");
Assert(EvidenceCollector.InspectSmbConfiguration("[global]\nserver min protocol = NT1").State == "fail", "SMB1 static detection");
Assert(EvidenceCollector.InspectSmbConfiguration("[global]\nserver min protocol = SMB2").State == "pass", "SMB2 explicit minimum");
Assert(EvidenceCollector.InspectSmbConfiguration(null).State == "not_evaluated", "missing Samba configuration is not a pass");

var baseline = snapshot with { CollectedAtUtc = snapshot.CollectedAtUtc.AddMinutes(-5), Services = [new ServiceInfo("daemon", "running", null, "fixture")] };
var timeline = TimelineBuilder.Build(snapshot, baseline,
    [new EvidenceRecord("logs", "fixture", "collected", "=HYPERLINK(\"example\")", snapshot.CollectedAtUtc.AddMinutes(-1))]);
var events = ((TimelineData)timeline.Data!).Events;
Assert(events.SequenceEqual(events.OrderBy(entry => entry.TimestampUtc).ThenBy(entry => entry.Kind, StringComparer.Ordinal).ThenBy(entry => entry.Source, StringComparer.Ordinal).ThenBy(entry => entry.Description, StringComparer.Ordinal)), "timeline sorted deterministically");
Assert(events.Any(entry => entry.Kind == "drift" && entry.TimestampUtc == snapshot.CollectedAtUtc), "drift uses observation time");
Assert(events.Any(entry => entry.Kind == "boot") && events.Any(entry => entry.Kind == "log"), "boot and log events present");
Assert(TimelineBuilder.ToCsv(timeline).Contains("\"'=HYPERLINK", StringComparison.Ordinal), "CSV formula injection neutralized");
Throws<ArgumentException>(() => TimelineBuilder.Build(snapshot, baseline with { CollectedAtUtc = snapshot.CollectedAtUtc.AddDays(1) }), "future baseline rejected");

var fleet = FleetAnalyzer.Compare([snapshot, Create("host-b", 15, 35), Create("host-c", 97, 40)]);
Assert(fleet.Findings.Count(finding => finding.Code == "FLEET_CPU_OUTLIER") == 1, "high-utilization fleet outlier");
Assert(((FleetData)fleet.Data!).MedianCpuUsedPercent == 15, "fleet median");
var historyFleet = FleetAnalyzer.Compare([snapshot with { CpuUsedPercent = 98, CollectedAtUtc = snapshot.CollectedAtUtc.AddMinutes(-1) }, snapshot, Create("host-b", 15, 35)]);
Assert(((FleetData)historyFleet.Data!).Hosts.Single(host => host.Host == "host-a").CpuUsedPercent == 10, "latest host snapshot used");
Throws<ArgumentException>(() => FleetAnalyzer.Compare([snapshot, snapshot]), "two distinct fleet hosts required");
Throws<InvalidDataException>(() => FleetAnalyzer.Compare([snapshot, Create("host-b", double.NaN, 35)]), "nonfinite fleet metric rejected");

foreach (var scenario in new[] { "high-cpu", "disk-full", "port-exposed" })
    Assert(((TriageData)TriageAdvisor.Analyze(snapshot, scenario).Data!).Steps.Count == 3, $"contextual triage {scenario}");
Assert(((TriageData)TriageAdvisor.Analyze(snapshot, "high-cpu").Data!).Steps[1].Guidance.Contains("cumulative", StringComparison.Ordinal), "cumulative process CPU is not described as instantaneous");
Throws<ArgumentException>(() => TriageAdvisor.Analyze(snapshot, "restart-services"), "action scenario not allowed");

var docker = PlatformInspector.Detect("0::/docker/abc", false, false, new HashSet<string>(), false);
Assert(docker.ContainerDetected && docker.DockerDetected && !docker.PodmanDetected, "Docker cgroup detection");
var podman = PlatformInspector.Detect("0::/libpod-abc.scope", false, false, new HashSet<string>(), false);
Assert(podman.PodmanDetected, "Podman cgroup detection");
var kubernetes = PlatformInspector.Detect("", false, false, new HashSet<string> { "KUBERNETES_SERVICE_HOST" }, false);
Assert(kubernetes.KubernetesDetected && kubernetes.Signals.Any(signal => signal.Contains("value was not read", StringComparison.Ordinal)), "Kubernetes presence without env value inspection");
var memory = PlatformInspector.ParseMacMemory(100 * 4096, "Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages free: 10.\nPages inactive: 20.\nPages speculative: 5.\n");
Assert(memory.AvailableBytes == 35 * 4096 && memory.UsedPercent == 65, "macOS memory pages and page size");
Throws<InvalidDataException>(() => PlatformInspector.ParseMacMemory(4096, "Pages free: 1"), "unknown macOS page size is not guessed");
Assert(PlatformInspector.ParseMacCpu("CPU usage: 5.0% user, 5.0% sys, 90.0% idle\nCPU usage: 10.0% user, 15.0% sys, 75.0% idle") == 25, "macOS second host CPU sample");
Assert(PlatformInspector.ParseMacCpu("CPU usage unavailable") is null, "missing host CPU does not become zero");

var environment = await PlatformInspector.CollectAsync(snapshot);
if (Environment.GetEnvironmentVariable("OPSCOPE_EXPECT_KUBE") == "1")
    Assert(((RuntimeEnvironment)environment.Data!).KubernetesDetected, "native inherited environment-name presence probe");
Assert(!ReportSecurity.Serialize(environment).Contains("private-environment-sentinel", StringComparison.Ordinal), "environment value is never exposed");
var protectedAccounts = new AnalysisReport("evidence", snapshot.CollectedAtUtc, [], new EvidenceData(
    [new EvidenceRecord("users", "fixture", "collected", "Account metadata", Metadata: new Dictionary<string, string> { ["user"] = "private-account-sentinel" })], []));
Assert(!ReportSecurity.Serialize(protectedAccounts).Contains("private-account-sentinel", StringComparison.Ordinal), "structured account identity redacted");

if (OperatingSystem.IsLinux())
{
    using var current = Process.GetCurrentProcess();
    await using var executable = File.OpenRead($"/proc/{current.Id}/exe");
    var hash = Convert.ToHexString(await SHA256.HashDataAsync(executable)).ToLowerInvariant();
    var path = Path.Combine(Path.GetTempPath(), $"opscope-evidence-ioc-{Guid.NewGuid():N}.csv");
    try
    {
        await File.WriteAllTextAsync(path, $"type,value\nsha256,{hash}\n");
        var live = snapshot with
        {
            CollectedAtUtc = DateTimeOffset.UtcNow,
            Host = snapshot.Host with { Hostname = Environment.MachineName },
            Processes = [new ProcessInfo(current.Id, current.ProcessName, "test", 0, 0, current.TotalProcessorTime, null, false)]
        };
        Assert((await IocAnalyzer.AnalyzeAsync(live, path)).Findings.Count == 1, "live kernel-identified executable SHA256 matching");
    }
    finally { File.Delete(path); }
}
if (args.Contains("--smoke", StringComparer.Ordinal))
{
    var local = await SystemProbe.CollectAsync(new CollectorOptions(TopProcesses: 5));
    var collected = await EvidenceCollector.CollectAsync(local, []);
    var collectedData = (EvidenceData)collected.Data!;
    Assert(collectedData.Records.Count > 0 && collectedData.Coverage.Count > 0, "real bounded local evidence collection");
    Assert(ReportSecurity.Serialize(collected).Length > 0, "real evidence serializes through shared redaction");
    Console.WriteLine($"Local evidence smoke passed: {collectedData.Records.Count} records, {collectedData.Coverage.Count} coverage controls, {collected.Warnings!.Count} explicit limitations.");
}
Console.WriteLine("Opscope Evidence tests passed (CSV/STIX, exact IoCs, live hashes, security coverage, timeline, fleet, triage, containers, macOS fixtures).");

static Snapshot Create(string host, double cpu, double memory) => new(
    DateTimeOffset.Parse("2026-10-25T12:00:00Z", System.Globalization.CultureInfo.InvariantCulture),
    new HostInfo(host, "Linux fixture", "linux", "X64", ".NET 8", "kernel", DateTimeOffset.Parse("2026-10-25T10:00:00Z", System.Globalization.CultureInfo.InvariantCulture), TimeSpan.FromHours(2), false, 4, "operator"),
    cpu, new MemoryInfo(1000, 700, 300, memory, "fixture"),
    [new DiskInfo("disk", "/", "test", 1000, 700, 30, true)], [],
    [new ProcessInfo(100, "suspicious", "operator", 1000, 1, TimeSpan.FromSeconds(30), "--remote=https://evil.example --address=198.51.100.10", false)],
    [new ListenerInfo("TCP", "0.0.0.0:22", "sshd", "fixture"), new ListenerInfo("TCP", "127.0.0.1:3389", "rdp", "fixture")],
    [new ServiceInfo("daemon", "failed", null, "fixture")], new SecurityPosture([], true, false, 1), null, [], [], TimeSpan.Zero);

static void Assert(bool condition, string name)
{
    if (!condition) throw new InvalidOperationException($"Evidence test failed: {name}");
}

static void Throws<T>(Action action, string name) where T : Exception
{
    try { action(); }
    catch (T) { return; }
    throw new InvalidOperationException($"Evidence test failed: {name}");
}
