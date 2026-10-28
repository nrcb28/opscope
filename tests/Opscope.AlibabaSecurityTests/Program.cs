using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Opscope;
using Opscope.Cloud;

const string Account = "1234567890123456", Region = "eu-central-1", Group = "sg-privategroup";
var assertions = 0;
void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); assertions++; }
Dictionary<string, string> Options() => new() { ["account"] = Account, ["region"] = Region, ["profile"] = "private-reader" };
JsonElement Json(object value) => JsonSerializer.SerializeToElement(value);
JsonElement Identity(string account = Account) => Json(new { AccountId = account });
object Disk(string id = "d-privatedisk", object? encrypted = null, string region = Region) => new { DiskId = id, RegionId = region, Encrypted = encrypted, Description = "SECRET-DISK-DESCRIPTION" };
JsonElement Disks(object[]? items = null, int? total = null, int page = 1) { items ??= [Disk(encrypted: false)]; return Json(new { TotalCount = total ?? items.Length, PageNumber = page, PageSize = 100, Disks = new { Disk = items } }); }
JsonElement Groups(string[]? ids = null, int? total = null, int page = 1, string region = Region) { ids ??= [Group]; return Json(new { RegionId = region, TotalCount = total ?? ids.Length, PageNumber = page, PageSize = 20, SecurityGroups = new { SecurityGroup = ids.Select(id => new { SecurityGroupId = id, Description = "SECRET-GROUP-DESCRIPTION" }) } }); }
object Rule(string policy = "Accept", string port = "22/22", string priority = "100", string protocol = "tcp", string source = "0.0.0.0/0", string ipv6 = "", string direction = "ingress") => new { Direction = direction, Policy = policy, IpProtocol = protocol, PortRange = port, Priority = priority, SourceCidrIp = source, Ipv6SourceCidrIp = ipv6, Description = "SECRET-RULE-DESCRIPTION", SourceGroupName = "SECRET-GROUP-NAME" };
JsonElement Rules(object[]? items = null, string id = Group, string region = Region, string? next = null) { items ??= [Rule()]; return Json(new { RegionId = region, SecurityGroupId = id, NextToken = next, Permissions = new { Permission = items } }); }
JsonElement Default(IReadOnlyList<string> args) => args[0] switch { "identity" => Identity(), "disks" => Disks(), "groups" => Groups(), "rules" => Rules(id: args[4]), _ => throw new InvalidOperationException("Unexpected fixture read") };
JsonElement Data(AnalysisReport report) => JsonSerializer.SerializeToElement(report.Data, ReportSecurity.JsonOptions);
JsonElement CheckData(AnalysisReport report, string check) => Data(report).GetProperty("configurationEvidence").GetProperty("checks").EnumerateArray().Single(row => row.GetProperty("check").GetString() == check);
string State(AnalysisReport report) => Data(report).GetProperty("coverage").GetProperty("state").GetString()!;
string CheckState(AnalysisReport report, string check) => CheckData(report, check).GetProperty("state").GetString()!;
int Count(AnalysisReport report, string check, string field) => CheckData(report, check).GetProperty("observations").GetProperty(field).GetInt32();
bool Unknown(AnalysisReport report, string check, string field) { var row = CheckData(report, check).GetProperty("observations"); return !row.TryGetProperty(field, out var value) || value.ValueKind == JsonValueKind.Null; }
async Task<(AnalysisReport Report, FakeRunner Runner)> Collect(Func<IReadOnlyList<string>, JsonElement>? response = null, Dictionary<string, string>? options = null)
{
    var fixture = new FakeRunner(response ?? Default);
    return (await new AlibabaSecurityProvider(fixture).CollectAsync("posture", options ?? Options()), fixture);
}

var (basic, basicRunner) = await Collect();
Check(basic.OperationSucceeded && State(basic) == "complete", "Both scoped configuration reads complete");
Check(basicRunner.Calls.Select(call => call.Arguments[0]).SequenceEqual(new[] { "identity", "disks", "groups", "rules" }), "Identity precedes every scoped resource source");
Check(basic.Findings.Any(finding => finding.Code == "ALIBABA_DISK_UNENCRYPTED"), "Observed false disk encryption retains the existing finding");
Check(basic.Findings.Any(finding => finding.Code == "ALIBABA_GLOBAL_ADMIN_INGRESS_RULE" && finding.Severity == FindingSeverity.Warning), "Observed global TCP administration allow produces configuration finding");
Check(Count(basic, "disks", "disksRead") == 1 && Count(basic, "disks", "unencryptedDisks") == 1, "Disk counts preserve observed false");
Check(Count(basic, "security-groups", "groupsRead") == 1 && Count(basic, "security-groups", "rulesRead") == 1, "Group/rule counts match observed rows");
Check(Count(basic, "security-groups", "worldIngressAllowRules") == 1 && Count(basic, "security-groups", "administrativeIngressAllowRules") == 1, "Global administration counters retain actual observations");
var exported = ReportSecurity.Serialize(basic);
foreach (var secret in new[] { Account, Group, "d-privatedisk", "private-reader", "SECRET-DISK-DESCRIPTION", "SECRET-GROUP-DESCRIPTION", "SECRET-RULE-DESCRIPTION", "SECRET-GROUP-NAME", "0.0.0.0/0" }) Check(!exported.Contains(secret, StringComparison.Ordinal), "Shared report omits identity and raw source property: " + secret);
Check(exported.Contains("administrativeIngressAllowRules", StringComparison.Ordinal) && exported.Contains("configuration-only", StringComparison.Ordinal), "Redaction preserves operational configuration metadata");

foreach (var mutate in new Action<Dictionary<string, string>>[] { o => o.Remove("account"), o => o["account"] = "https://untrusted.invalid", o => o.Remove("region"), o => o["region"] = "../region", o => o["profile"] = "--endpoint", o => o["security-groups"] = "sg-a,sg-a", o => o["security-groups"] = "sg-a,", o => o["security-groups"] = string.Join(',', Enumerable.Range(0, 21).Select(index => "sg-" + index)), o => o["resource"] = "arbitrary" })
{
    var options = Options(); mutate(options); var (report, fixture) = await Collect(options: options);
    Check(State(report) == "not_configured" && fixture.Calls.Count == 0, "Invalid scope cannot start a remote read");
}
var unsupportedRunner = new FakeRunner(Default);
Check(! (await new AlibabaSecurityProvider(unsupportedRunner).CollectAsync("delete", Options())).OperationSucceeded && unsupportedRunner.Calls.Count == 0, "Mutation operation is never collected");
var (mismatch, mismatchRunner) = await Collect(args => args[0] == "identity" ? Identity("9999999999999999") : Default(args));
Check(State(mismatch) == "permission_denied" && mismatchRunner.Calls.Count == 1, "Mismatched account stops before resource enumeration");
foreach (var status in new[] { "permission_denied", "rate_limited", "failed" })
{
    var (deniedIdentity, fixture) = await Collect(_ => throw new AdditionalCloudQueryException(status, "PRIVATE-PROVIDER-ERROR"));
    Check(State(deniedIdentity) == status && fixture.Calls.Count == 1, "Identity failure state stays explicit");
    Check(!ReportSecurity.Serialize(deniedIdentity, false).Contains("PRIVATE-PROVIDER-ERROR", StringComparison.Ordinal), "Raw identity provider errors stay private");
    Check(Unknown(deniedIdentity, "disks", "disksRead") && Unknown(deniedIdentity, "security-groups", "rulesRead"), "Unobserved sources cannot become synthetic zero counts");
}
var (partialDisks, _) = await Collect(args => args[0] == "disks" ? throw new AdditionalCloudQueryException("permission_denied", "PRIVATE-DISK-ERROR") : Default(args));
Check(State(partialDisks) == "partial" && CheckState(partialDisks, "disks") == "permission_denied" && CheckState(partialDisks, "security-groups") == "complete", "One denied source retains useful independent group evidence");
Check(Unknown(partialDisks, "disks", "unencryptedDisks"), "Denied encryption is unknown rather than encrypted or unencrypted");
var (limited, limitedRunner) = await Collect(args => args[0] == "disks" ? throw new AdditionalCloudQueryException("rate_limited", "PRIVATE-QUOTA-ERROR") : Default(args));
Check(State(limited) == "rate_limited" && limitedRunner.Calls.Count == 2 && CheckState(limited, "security-groups") == "not_requested", "Throttling prevents further product reads without retry");
var (unknownDisk, _) = await Collect(args => args[0] == "disks" ? Disks([Disk()]) : Default(args));
Check(State(unknownDisk) == "partial" && Count(unknownDisk, "disks", "unknownEncryption") == 1 && !unknownDisk.Findings.Any(finding => finding.Code == "ALIBABA_DISK_UNENCRYPTED"), "Missing encryption cannot become false or a compliant verdict");
foreach (var invalidDisk in new[] { Disk(region: "cn-hangzhou"), Disk(id: "https://untrusted.invalid"), Disk(id: "d-valid", encrypted: "false") })
{
    var (report, _) = await Collect(args => args[0] == "disks" ? Disks([invalidDisk]) : Default(args));
    Check(State(report) == "partial" && !report.Findings.Any(finding => finding.Code == "ALIBABA_DISK_UNENCRYPTED"), "Unverified or nonboolean disk evidence creates no encryption finding");
}
var (duplicateDisk, _) = await Collect(args => args[0] == "disks" ? Disks([Disk(encrypted: false), Disk(encrypted: false)]) : Default(args));
Check(CheckState(duplicateDisk, "disks") == "partial" && Count(duplicateDisk, "disks", "disksRead") == 1, "Duplicate disk IDs remain partial without double counting");
var (empty, _) = await Collect(args => args[0] switch { "disks" => Disks([], 0), "groups" => Groups([], 0), _ => Default(args) });
Check(empty.OperationSucceeded && State(empty) == "no_data" && Count(empty, "disks", "disksRead") == 0 && Count(empty, "security-groups", "rulesRead") == 0, "Only complete empty pages establish genuine observed zero counts");
var selected = Options(); selected["security-groups"] = Group;
var (missingGroup, _) = await Collect(args => args[0] == "groups" ? Groups([], 0) : Default(args), selected);
Check(CheckState(missingGroup, "security-groups") == "partial" && Unknown(missingGroup, "security-groups", "rulesRead"), "Missing explicitly selected groups cannot establish zero rules");
var (wrongGroupScope, _) = await Collect(args => args[0] == "groups" ? Groups(region: "cn-hangzhou") : Default(args));
Check(CheckState(wrongGroupScope, "security-groups") == "permission_denied" && Data(wrongGroupScope).GetProperty("resources").GetArrayLength() == 1, "Wrong returned region cannot introduce group resources");
var (wrongRuleScope, _) = await Collect(args => args[0] == "rules" ? Rules(id: "sg-other") : Default(args));
Check(CheckState(wrongRuleScope, "security-groups") == "permission_denied" && Unknown(wrongRuleScope, "security-groups", "rulesRead"), "Rule identity must agree with selected group");
var (foreignGroup, foreignRunner) = await Collect(args => args[0] == "groups" ? Groups(["sg-other"]) : Default(args), selected);
Check(CheckState(foreignGroup, "security-groups") == "partial" && foreignRunner.Calls.All(call => call.Arguments[0] != "rules"), "Returned groups outside the allowlist are never followed");
var (shortDisks, shortRunner) = await Collect(args => args[0] == "disks" ? Disks(total: 2) : Default(args));
Check(CheckState(shortDisks, "disks") == "partial" && shortRunner.Calls.Count(call => call.Arguments[0] == "disks") == 1, "Short pages cannot imply enumeration completeness or skip omitted positions");
var (shortGroups, _) = await Collect(args => args[0] == "groups" ? Groups(total: 2) : Default(args));
Check(CheckState(shortGroups, "security-groups") == "partial", "Short group pages preserve incomplete enumeration");
var (changedTotal, _) = await Collect(args => args[0] == "disks" ? int.Parse(args[4], CultureInfo.InvariantCulture) == 1 ? Disks(Enumerable.Range(0,100).Select(index => Disk("d-"+index,true)).ToArray(),101) : Disks([Disk("d-tail",true)],103,2) : Default(args));
Check(CheckState(changedTotal, "disks") == "partial" && Count(changedTotal, "disks", "disksRead") == 100, "Changing provider totals invalidate subsequent page coverage");

foreach (var (rule, expectedAdmin) in new[] { (Rule(port:"3389/3389"),1), (Rule(port:"-1/-1",protocol:"all"),1), (Rule(port:"443/443"),0), (Rule(protocol:"udp"),0), (Rule(source:"192.0.2.0/24"),0), (Rule(source:"",ipv6:"::/0"),1), (Rule(policy:"Drop"),0) })
{
    var (report, _) = await Collect(args => args[0] == "rules" ? Rules([rule]) : Default(args));
    Check(Count(report, "security-groups", "administrativeIngressAllowRules") == expectedAdmin, "Only observed global TCP/all administrative allow configuration is counted");
}
foreach (var invalidRule in new[] { Rule(policy:"unknown"), Rule(port:"nonsense"), Rule(source:"not-a-cidr"), Rule(direction:"egress"), Rule(source:"",ipv6:"") })
{
    var (report, _) = await Collect(args => args[0] == "rules" ? Rules([invalidRule]) : Default(args));
    Check(CheckState(report, "security-groups") == "partial" && Count(report,"security-groups","unknownRules") == 1 && Count(report,"security-groups","administrativeIngressAllowRules") == 0, "Unknown rule semantics do not create a synthetic public-access assessment");
}
foreach (var blocker in new[] { Rule(policy:"Drop",priority:"1"), Rule(policy:"Drop",priority:"100") })
{
    var (report, _) = await Collect(args => args[0] == "rules" ? Rules([Rule(),blocker]) : Default(args));
    Check(Count(report,"security-groups","possiblyShadowedAdminAllowRules") == 1 && report.Findings.Single(finding => finding.Code == "ALIBABA_GLOBAL_ADMIN_INGRESS_RULE").Severity == FindingSeverity.Info, "Covering deny priorities retain an uncertain configuration candidate");
}
var (noPriority, _) = await Collect(args => args[0] == "rules" ? Rules([Rule(priority:"")]) : Default(args));
Check(CheckState(noPriority,"security-groups") == "partial" && Count(noPriority,"security-groups","possiblyShadowedAdminAllowRules") == 1, "Missing priority keeps the assessment uncertain");
var (administrativeOverlap, _) = await Collect(args => args[0] == "rules" ? Rules([Rule(port:"22/1000"),Rule(policy:"Drop",port:"22/22",priority:"1")]) : Default(args));
Check(Count(administrativeOverlap,"security-groups","possiblyShadowedAdminAllowRules") == 1 && administrativeOverlap.Findings.Single(finding => finding.Code == "ALIBABA_GLOBAL_ADMIN_INGRESS_RULE").Severity == FindingSeverity.Info, "A deny covering the administrative port marks a wider allow range uncertain");
var (repeatedCursor, repeatedRunner) = await Collect(args => args[0] == "rules" ? Rules(next:"repeated") : Default(args));
Check(CheckState(repeatedCursor,"security-groups") == "partial" && Count(repeatedCursor,"security-groups","rulesRead") == 1 && repeatedRunner.Calls.Count(call => call.Arguments[0] == "rules") == 2, "Repeated cursors stop before counting ambiguous duplicate page content");
var rulePage = 0;
var (pageBound, pageRunner) = await Collect(args => args[0] == "rules" ? Rules(next:"next" + ++rulePage) : Default(args));
Check(CheckState(pageBound,"security-groups") == "partial" && pageRunner.Calls.Count(call => call.Arguments[0] == "rules") == 10, "Each group rule source has a ten-page bound");
var readCounter = 0;
var (readBound, budgetRunner) = await Collect(args => args[0] switch { "groups" => Groups(Enumerable.Range(0,20).Select(index=>"sg-"+index).ToArray()), "rules" => Rules(id:args[4],next:"next" + ++readCounter), _ => Default(args) });
Check(State(readBound) == "partial" && budgetRunner.Calls.Count == 60, "All sources share the sixty-read budget");
var (rowBound, rowRunner) = await Collect(args => args[0] == "disks" ? Disks(Enumerable.Range(0,100).Select(index=>Disk("d-"+args[4]+"x"+index,true)).ToArray(),1100,int.Parse(args[4],CultureInfo.InvariantCulture)) : Default(args));
Check(State(rowBound) == "partial" && Data(rowBound).GetProperty("resources").GetArrayLength() <= 1000 && rowRunner.Calls.Count(call=>call.Arguments[0]=="disks") == 10, "The whole operation retains at most one thousand disk/rule rows");
var huge = new string('x',4*1024*1024);
var (bodyBound, bodyRunner) = await Collect(args => args[0]=="disks" ? Json(new { TotalCount=0,PageNumber=1,PageSize=100,Disks=new {Disk=System.Array.Empty<object>()},Padding=huge }) : Default(args));
Check(CheckState(bodyBound,"disks") == "partial" && Unknown(bodyBound,"disks","disksRead"), "Oversized projected response is unavailable rather than empty");
Check(bodyRunner.Calls.Count == 2 && CheckState(bodyBound,"security-groups") == "not_requested", "Exhausted response budget stops later product reads");
var padding = new string('x',3*1024*1024);
var (byteBound, byteRunner) = await Collect(args => { var node=JsonNode.Parse(Default(args).GetRawText())!.AsObject();node["Padding"]=padding;return JsonSerializer.SerializeToElement(node); });
Check(State(byteBound)=="partial" && byteRunner.Calls.Count==3 && Unknown(byteBound,"security-groups","rulesRead"), "Projected JSON responses share the aggregate eight-MiB budget");
using (var cancellation = new CancellationTokenSource())
{
    cancellation.Cancel();var fixture=new FakeRunner(Default);
    try { await new AlibabaSecurityProvider(fixture).CollectAsync("posture",Options(),cancellation.Token);throw new Exception("Cancellation ignored"); }
    catch(OperationCanceledException) { Check(fixture.Calls.Count==0,"Caller cancellation propagates before any provider read"); }
}

foreach (var action in new[] { new[] {"identity",Account,Region,"private-reader"}, new[] {"disks",Account,Region,"private-reader","1"}, new[] {"groups",Account,Region,"private-reader","1","[\"sg-privategroup\"]"}, new[] {"rules",Account,Region,"private-reader",Group,"safe-cursor"} })
{
    var prepared=AlibabaSecurityCommandRunner.Prepare(action);
    Check(prepared.Contains("--cli-query") && prepared.Contains("--profile") && !prepared.Contains("--endpoint"), "Only closed read-only operations and a literal profile reach the CLI");
    var query=prepared[prepared.ToList().IndexOf("--cli-query")+1];
    Check(!query.Contains("Description",StringComparison.Ordinal) && !query.Contains("Name",StringComparison.Ordinal) && !query.Contains("Tag",StringComparison.Ordinal), "Source projection excludes arbitrary names, descriptions and tags");
}
foreach (var action in new[] { new[] {"delete",Account,Region,""}, new[] {"identity","not-account",Region,""}, new[] {"identity",Account,"https://evil.invalid",""},new[] {"identity",Account,Region,"--endpoint"},new[] {"disks",Account,Region,"","11"},new[] {"groups",Account,Region,"","1","[\"sg-a\",\"sg-a\"]"},new[] {"rules",Account,Region,"","https://evil.invalid",""},new[] {"rules",Account,Region,"",Group,"--endpoint"} })
{
    try { AlibabaSecurityCommandRunner.Prepare(action);throw new Exception("Unsafe grammar accepted"); } catch(InvalidOperationException) { Check(true,"Mutation, endpoint, duplicate and unsupported grammar is rejected"); }
}
Check(AlibabaSecurityCommandRunner.Classify("Throttling PRIVATE") == "rate_limited" && AlibabaSecurityCommandRunner.Classify("Forbidden PRIVATE") == "permission_denied" && AlibabaSecurityCommandRunner.Classify("PRIVATE") == "failed", "Only bounded known error categories are retained");
Console.WriteLine($"PASS: {assertions} Alibaba scoped configuration checks.");

sealed class FakeRunner(Func<IReadOnlyList<string>, JsonElement> response) : ICloudCommandRunner
{
    public List<(string Tool,IReadOnlyList<string> Arguments)> Calls { get; }=[];
    public Task<JsonElement> RunAsync(string tool,IReadOnlyList<string> arguments,CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();Calls.Add((tool,arguments.ToArray()));
        if(tool!="alibaba-security")throw new InvalidOperationException("Unexpected fixture tool");
        return Task.FromResult(response(arguments));
    }
}
