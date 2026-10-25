using System.Net;
using System.Reflection;
using System.Text.Json;
using Opscope;
using Opscope.Cloud;

var assertions = 0;
void Assert(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); assertions++; }
static Dictionary<string, string> Options(params (string Key, string Value)[] pairs) => pairs.ToDictionary(p => p.Key, p => p.Value);
static string Text(object? value) => JsonSerializer.Serialize(value);
static bool Has(AnalysisReport report, string code) => report.Findings.Any(f => f.Code == code);
var runner = new FakeRunner();
var provider = new AwsProvider(runner);
var opts = Options(("profile", "readonly-sso"), ("regions", "eu-west-1,us-east-1"));
var inventory = await provider.CollectAsync("inventory", opts);
Assert(inventory.Kind == "aws.inventory", "Inventory has normalized report kind");
Assert(inventory.OperationSucceeded, "Valid inventory is successful");
Assert(runner.Calls.Count(c => c[0] == "ec2" && c[1] == "describe-instances") == 2, "Inventory traverses both regions");
Assert(Text(inventory.Data).Contains("AWS::EC2::VPC") && Text(inventory.Data).Contains("AWS::EC2::NetworkInterface") && Text(inventory.Data).Contains("AWS::EC2::EIP"), "Inventory includes VPC, interfaces and EIPs");
Assert(!Text(inventory).Contains("DO_NOT_EXPORT_SECRET"), "Unexpected response fields are excluded");
Assert(runner.Calls.All(c => c.Contains("--profile") && c[c.IndexOf("--profile") + 1] == "readonly-sso"), "Profile preserves caller credential chain");
Assert(runner.Calls.All(c => c.Contains("--query") && c.Contains("--no-cli-pager") && !c.Contains("--no-paginate")), "Every call projects JSON and retains CLI pagination");
var posture = await provider.CollectAsync("posture", Options(("region", "eu-west-1")));
foreach (var code in new[] { "AWS_IMDSV1_ENABLED", "AWS_EBS_UNENCRYPTED", "AWS_SECURITY_GROUP_WORLD_OPEN", "AWS_S3_PUBLIC_ACCESS", "AWS_SECURITYHUB_FINDING", "AWS_GUARDDUTY_FINDING" }) Assert(Has(posture, code), code);
Assert(posture.Findings.Any(f => f.Code == "AWS_GUARDDUTY_FINDING" && f.Severity == FindingSeverity.Critical), "High GuardDuty severity is critical");
Assert(!Text(posture).Contains("DO_NOT_EXPORT_SECRET"), "Nested unexpected service fields are excluded");
var health = await provider.CollectAsync("health", Options(("region", "eu-west-1")));
foreach (var code in new[] { "AWS_EC2_STATUS_IMPAIRED", "AWS_EC2_SCHEDULED_EVENT", "AWS_CLOUDWATCH_ALARM", "AWS_HEALTH_EVENT" }) Assert(Has(health, code), code);
var instance = await provider.CollectAsync("instance", Options(("region", "eu-west-1"), ("resource", "i-0123456789abcdef0")));
Assert(Text(instance.Data).Contains("CPUUtilization") && Text(instance.Data).Contains("c7i.large"), "Instance includes type and metric context");
Assert(instance.OperationSucceeded, "Resolved required instance succeeds");
var bundle = await provider.CollectAsync("bundle", Options(("region", "eu-west-1"), ("resource", "i-0123456789abcdef0")));
Assert(Text(bundle.Data).Contains("AWS::CloudTrail::Event") && !Text(bundle).Contains("DO_NOT_EXPORT_SECRET"), "Bundle includes projected event metadata only");
var drift = await provider.CollectAsync("drift", Options(("region", "eu-west-1")));
Assert(Has(drift, "AWS_CLOUDFORMATION_DRIFT") && Has(drift, "AWS_RESOURCE_DRIFT"), "Drift reports existing stack/resource results");
Assert(drift.Warnings!.Any(w => w.Contains("other IaC formats are unsupported")), "Drift limitations are explicit");
Assert(!Text(drift).Contains("DO_NOT_EXPORT_SECRET"), "Expected and actual property values never enter drift output");
var baselinePath = Path.GetTempFileName();
try
{
    await File.WriteAllTextAsync(baselinePath, """
        {"data":{"resources":[
          {"provider":"aws","account":"123456789012","region":"eu-west-1","id":"i-0123456789abcdef0","type":"AWS::EC2::Instance","properties":{"Type":"t3.micro","Secret":"DO_NOT_EXPORT_SECRET"}},
          {"provider":"aws","account":"123456789012","region":"eu-west-1","id":"vol-missing","type":"AWS::EC2::Volume","properties":{"Encrypted":true}},
          {"provider":"aws","account":"123456789012","region":"eu-west-1","id":"sg-123","type":"AWS::EC2::SecurityGroup","properties":{"Ingress":[{"IPv6":[],"IPv4":["0.0.0.0/0"],"To":22,"From":22,"Protocol":"tcp"}]}}
        ]}}
        """);
    var compared = await provider.CollectAsync("drift", Options(("region", "eu-west-1"), ("baseline", baselinePath)));
    Assert(Has(compared, "AWS_BASELINE_ADDED") && Has(compared, "AWS_BASELINE_REMOVED") && Has(compared, "AWS_BASELINE_CHANGED"), "Baseline detects added, removed and changed resources");
    Assert(compared.Findings.Count(f => f.Code == "AWS_BASELINE_CHANGED") == 1, "Canonical properties do not report reordered SG object fields as drift");
    Assert(!Text(compared).Contains("t3.micro") && !Text(compared).Contains("DO_NOT_EXPORT_SECRET"), "Baseline emits changed property names without expected secret/value material");
    var partial = await new AwsProvider(new FakeRunner { Denied = "ec2 describe-volumes" }).CollectAsync("drift", Options(("region", "eu-west-1"), ("baseline", baselinePath)));
    Assert(!partial.Findings.Any(f => f.Code == "AWS_BASELINE_REMOVED" && f.Detail.Contains("vol-missing")) && partial.Warnings!.Any(w => w.Contains("absence could not be assessed")), "Failed inventory does not create a false removal");
    Assert(!partial.OperationSucceeded, "Required baseline inventory failure is unsuccessful");
    foreach (var malformedJson in new[] { "{}", "null", "[null]", "[42]" })
    {
        var malformed = await new AwsProvider(new FakeRunner { OverrideCommand = "ec2 describe-volumes", OverrideJson = malformedJson }).CollectAsync("drift", Options(("region", "eu-west-1"), ("baseline", baselinePath)));
        Assert(!malformed.OperationSucceeded && !malformed.Findings.Any(f => f.Code == "AWS_BASELINE_REMOVED" && f.Detail.Contains("vol-missing")), "Malformed successful response cannot establish resource absence: " + malformedJson);
        Assert(malformed.Warnings!.Any(w => w.Contains("describe-volumes") && w.Contains("coverage unavailable")), "Malformed response exposes a bounded coverage warning");
    }
    await File.WriteAllTextAsync(baselinePath, ReportSecurity.Serialize(inventory));
    var redacted = await provider.CollectAsync("drift", Options(("region", "eu-west-1"), ("baseline", baselinePath)));
    Assert(redacted.Warnings!.Any(w => w.Contains("redacted identifiers")) && !redacted.Findings.Any(f => f.Code.StartsWith("AWS_BASELINE_", StringComparison.Ordinal)), "Redacted baseline is explicitly incomplete and cannot create spurious changes");
    Assert(!redacted.OperationSucceeded, "Entirely redacted baseline cannot claim a completed comparison");
    await File.WriteAllTextAsync(baselinePath, """
        {"version":4,"resources":[
          {"mode":"managed","type":"aws_instance","instances":[{"attributes":{"id":"i-0123456789abcdef0","instance_type":"t3.micro","vpc_security_group_ids":["sg-123"],"metadata_options":[{"http_tokens":"optional"}],"user_data":"DO_NOT_EXPORT_SECRET"}}]},
          {"mode":"managed","type":"aws_ebs_volume","instances":[{"attributes":{"id":"vol-123","encrypted":true,"size":20}}]},
          {"mode":"managed","type":"aws_security_group","instances":[{"attributes":{"id":"sg-123","ingress":[{"protocol":"tcp","from_port":22,"to_port":22,"cidr_blocks":["0.0.0.0/0"],"ipv6_cidr_blocks":[]}]}}]},
          {"mode":"managed","type":"aws_secretsmanager_secret_version","instances":[{"attributes":{"id":"secret","secret_string":"DO_NOT_EXPORT_SECRET"}}]}
        ]}
        """);
    var terraform = await provider.CollectAsync("drift", Options(("region", "eu-west-1"), ("baseline", baselinePath)));
    Assert(terraform.Findings.Count(f => f.Code == "AWS_BASELINE_CHANGED") == 2, "Terraform instance and EBS fixed mappings detect changes while equivalent SG does not");
    Assert(terraform.Warnings!.Any(w => w.Contains("unsupported resource types")) && terraform.Warnings!.Any(w => w.Contains("JSON state only")), "Terraform baseline limitations and unsupported resources explicit");
    Assert(!Text(terraform).Contains("DO_NOT_EXPORT_SECRET") && !Text(terraform).Contains("t3.micro"), "Terraform state secret/user-data and expected values never enter evidence");
    await File.WriteAllTextAsync(baselinePath, Text(new { Data = new { Reports = new[] { inventory } } }));
    var multiProfileBaseline = await provider.CollectAsync("drift", Options(("region", "eu-west-1"), ("baseline", baselinePath)));
    Assert(!multiProfileBaseline.Findings.Any(f => f.Code.StartsWith("AWS_BASELINE_", StringComparison.Ordinal)), "Exported multi-profile reports retain comparable resources with regional filtering");
    var baselineWithoutCfn = await new AwsProvider(new FakeRunner { Denied = "cloudformation describe-stacks" }).CollectAsync("drift", Options(("region", "eu-west-1"), ("baseline", baselinePath)));
    Assert(baselineWithoutCfn.OperationSucceeded, "Recorded CloudFormation is optional when inventory baseline comparison succeeds");
}
finally { File.Delete(baselinePath); }
var patches = await provider.CollectAsync("patches", Options(("region", "eu-west-1")));
Assert(Has(patches, "AWS_PATCH_NONCOMPLIANT") && Has(patches, "AWS_SSM_NODE_OFFLINE"), "Patch and offline findings generated");
Assert(Text(patches.Data).Contains("HybridManagedInstance"), "Hybrid managed nodes included");
var cost = await provider.CollectAsync("cost", Options(("region", "eu-west-1")));
foreach (var code in new[] { "AWS_ORPHAN_EBS", "AWS_ORPHAN_EIP", "AWS_OLD_SNAPSHOT", "AWS_LOW_CPU_CANDIDATE" }) Assert(Has(cost, code), code);
var missingCpu = await new AwsProvider(new FakeRunner { OverrideCommand = "cloudwatch get-metric-statistics", OverrideJson = "[{\"Samples\":288},{\"Samples\":288},{\"Samples\":288},{\"Samples\":288},{\"Samples\":288},{\"Samples\":288},{\"Samples\":288}]" }).CollectAsync("cost", Options(("region", "eu-west-1")));
Assert(!Has(missingCpu, "AWS_LOW_CPU_CANDIDATE") && missingCpu.Warnings!.Any(w => w.Contains("get-metric-statistics")), "Missing CPU observations cannot be interpreted as zero utilization");
Assert(runner.Calls.All(c => c[1].StartsWith("describe-", StringComparison.Ordinal) || c[1].StartsWith("get-", StringComparison.Ordinal) || c[1].StartsWith("list-", StringComparison.Ordinal) || c[1] == "lookup-events"), "All calls use explicit read-only operations");
Assert(runner.Calls.All(c => !c.Any(a => a.Contains("credentials", StringComparison.OrdinalIgnoreCase) || a.Contains("user-data", StringComparison.OrdinalIgnoreCase) || a.Contains("console-output", StringComparison.OrdinalIgnoreCase))), "Credentials, user data and console output never requested");
var roleRunner = new FakeRunner();
var role = await new AwsProvider(roleRunner).CollectAsync("inventory", Options(("role-arn", "arn:aws:iam::123456789012:role/test")));
Assert(roleRunner.Calls.Count == 0 && role.Warnings!.Any(w => w.Contains("source_profile")), "Explicit role option reports profile guidance without credential calls");
Assert(!role.OperationSucceeded, "Unsupported direct role request is unsuccessful");
var filteredRunner = new FakeRunner();
var filtered = await new AwsProvider(filteredRunner).CollectAsync("inventory", Options(("accounts", "000000000000")));
Assert(filteredRunner.Calls.Count == 1 && filtered.Warnings!.Any(w => w.Contains("outside --accounts")), "Account filter prevents unintended resource queries");
Assert(!filtered.OperationSucceeded, "Disallowed authenticated account is unsuccessful");
var deniedRunner = new FakeRunner { Denied = "securityhub get-findings" };
var denied = await new AwsProvider(deniedRunner).CollectAsync("posture", Options(("region", "eu-west-1")));
Assert(denied.Warnings!.Any(w => w.Contains("securityhub get-findings") && w.Contains("coverage unavailable")), "Denied optional service has coverage warning");
Assert(denied.OperationSucceeded, "Optional service denial preserves successful partial collection");
Assert(!Text(denied).Contains("SECRET_FROM_STDERR"), "Raw native error text never enters report");
var noDetector = await new AwsProvider(new FakeRunner { NoDetectors = true }).CollectAsync("posture", Options(("region", "eu-west-1")));
Assert(noDetector.Warnings!.Any(w => w.Contains("GuardDuty is not enabled")), "Disabled optional service has coverage warning");
var discoveryRunner = new FakeRunner();
await new AwsProvider(discoveryRunner).CollectAsync("inventory", Options(("regions", "all")));
Assert(discoveryRunner.Calls.Any(c => c[1] == "describe-regions") && discoveryRunner.Calls.Count(c => c[1] == "describe-vpcs") == 2, "Region discovery traverses enabled returned regions");
var noIdentity = await new AwsProvider(new FakeRunner { Denied = "sts get-caller-identity" }).CollectAsync("inventory", Options(("region", "eu-west-1")));
Assert(!noIdentity.OperationSucceeded, "Missing CLI or denied identity is unsuccessful");
var invalidIdentity = await new AwsProvider(new FakeRunner { InvalidIdentity = true }).CollectAsync("inventory", Options(("region", "eu-west-1")));
Assert(!invalidIdentity.OperationSucceeded, "Missing authenticated account is unsuccessful");
var emptyInventory = await new AwsProvider(new FakeRunner { EmptyInventory = true }).CollectAsync("inventory", Options(("region", "eu-west-1")));
Assert(emptyInventory.OperationSucceeded && !Text(emptyInventory.Data).Contains("AWS::EC2::"), "Successful empty inventory is legitimate success");
var unresolved = await new AwsProvider(new FakeRunner { EmptyInventory = true }).CollectAsync("instance", Options(("region", "eu-west-1"), ("resource", "i-0123456789abcdef0")));
Assert(!unresolved.OperationSucceeded && unresolved.Warnings!.Any(w => w.Contains("could not be resolved")), "Unresolved required instance is unsuccessful");
var unresolvedBundle = await new AwsProvider(new FakeRunner { EmptyInventory = true }).CollectAsync("bundle", Options(("region", "eu-west-1"), ("resource", "i-0123456789abcdef0")));
Assert(!unresolvedBundle.OperationSucceeded, "CloudTrail history cannot turn an unresolved EC2 bundle target into success");
var regionalTarget = await new AwsProvider(new FakeRunner { UnresolvedRegion = "eu-west-1" }).CollectAsync("instance", Options(("regions", "eu-west-1,us-east-1"), ("resource", "i-0123456789abcdef0")));
Assert(regionalTarget.OperationSucceeded, "Instance resolved in a later selected region succeeds");
var genericBundle = await new AwsProvider(new FakeRunner { NoCorrelatedEvidence = true }).CollectAsync("bundle", Options(("region", "eu-west-1"), ("resource", "resource-with-no-evidence")));
Assert(!genericBundle.OperationSucceeded, "Generic bundle with no correlated evidence is explicitly unresolved");
foreach (var (verb, command) in new[]
{
    ("inventory", "ec2 describe-volumes"), ("posture", "ec2 describe-security-groups"),
    ("health", "ec2 describe-instance-status"), ("health", "cloudwatch describe-alarms"),
    ("instance", "ec2 describe-instances"), ("bundle", "cloudtrail lookup-events"),
    ("drift", "cloudformation describe-stacks"), ("patches", "ssm describe-instance-information"),
    ("patches", "ssm describe-instance-patch-states"), ("cost", "ec2 describe-snapshots")
})
{
    var failureOptions = Options(("region", "eu-west-1"));
    if (verb is "instance" or "bundle") failureOptions["resource"] = "i-0123456789abcdef0";
    var failed = await new AwsProvider(new FakeRunner { Denied = command }).CollectAsync(verb, failureOptions);
    Assert(!failed.OperationSucceeded, "Required API failure is unsuccessful: " + verb + " / " + command);
}
using (var cancelled = new CancellationTokenSource())
{
    cancelled.Cancel();
    try { await provider.CollectAsync("inventory", opts, cancelled.Token); throw new Exception("Cancellation did not propagate"); }
    catch (OperationCanceledException) { Assert(true, "Caller cancellation propagates"); }
}

var factory = typeof(AwsMetadataClient).GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic, null, [typeof(HttpMessageHandler)], null)!;
AwsMetadataClient Metadata(HttpMessageHandler handler) => (AwsMetadataClient)factory.Invoke([handler]);
var metadataHandler = new MetadataHandler();
Assert(await Metadata(metadataHandler).ReadAsync(false) is null && metadataHandler.Paths.Count == 0, "Metadata opt-out never connects");
var identity = await Metadata(metadataHandler).ReadAsync(true);
Assert(identity is { AccountId: "123456789012", Region: "eu-west-1", InstanceId: "i-0123456789abcdef0", Architecture: "x86_64" }, "IMDSv2 parses identity");
Assert(metadataHandler.Paths.SequenceEqual(new[] { "/latest/api/token", "/latest/dynamic/instance-identity/document" }), "Only fixed IMDSv2 token/identity endpoints requested");
Assert(!Text(identity).Contains("SESSION_TOKEN"), "Metadata token never returned");
try { await Metadata(new MetadataHandler { Oversize = true }).ReadAsync(true); throw new Exception("Oversize accepted"); } catch (InvalidDataException) { Assert(true, "Metadata size bound enforced"); }
try { await Metadata(new MetadataHandler { Redirect = true }).ReadAsync(true); throw new Exception("Redirect accepted"); } catch (HttpRequestException) { Assert(true, "Metadata redirects rejected"); }
Console.WriteLine($"AWS tests passed: {assertions} assertions; fake CLI/HTTP only, no cloud calls.");

sealed class FakeRunner : ICloudCommandRunner
{
    public List<List<string>> Calls { get; } = [];
    public string? Denied { get; init; }
    public string? OverrideCommand { get; init; }
    public string? OverrideJson { get; init; }
    public bool NoDetectors { get; init; }
    public bool InvalidIdentity { get; init; }
    public bool EmptyInventory { get; init; }
    public string? UnresolvedRegion { get; init; }
    public bool NoCorrelatedEvidence { get; init; }
    public Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _ = TrustedCloudCommandRunner.PrepareArguments(tool, arguments);
        if (tool != "aws") throw new InvalidOperationException("Unexpected tool");
        var a = arguments.ToList(); Calls.Add(a);
        var command = a[0] + " " + a[1];
        if (command == OverrideCommand) return Task.FromResult(JsonDocument.Parse(OverrideJson!).RootElement.Clone());
        if (command == Denied) throw new InvalidOperationException("SECRET_FROM_STDERR");
        if (InvalidIdentity && command == "sts get-caller-identity") return Task.FromResult(JsonDocument.Parse("{}").RootElement.Clone());
        if ((EmptyInventory && a[0] == "ec2" && a[1] != "describe-regions") ||
            (UnresolvedRegion is not null && command == "ec2 describe-instances" && a.Contains("--region") && a[a.IndexOf("--region") + 1] == UnresolvedRegion) ||
            (NoCorrelatedEvidence && command is "securityhub get-findings" or "cloudtrail lookup-events"))
            return Task.FromResult(JsonDocument.Parse("[]").RootElement.Clone());
        var json = command switch
        {
            "sts get-caller-identity" => """{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:role/test"}""",
            "ec2 describe-regions" => """["eu-west-1","us-east-1"]""",
            "ec2 describe-instances" => """[{"Id":"i-0123456789abcdef0","Name":"test","Type":"c7i.large","State":"running","HttpTokens":"optional","Groups":["sg-123"],"SecretAccessKey":"DO_NOT_EXPORT_SECRET"}]""",
            "ec2 describe-volumes" => """[{"Id":"vol-123","State":"available","Encrypted":false,"Size":20,"Attachments":[]}]""",
            "ec2 describe-security-groups" => """[{"Id":"sg-123","Name":"web","Ingress":[{"Protocol":"tcp","From":22,"To":22,"IPv4":["0.0.0.0/0"],"IPv6":[]}]}]""",
            "ec2 describe-vpcs" => """[{"Id":"vpc-123","Cidr":"10.0.0.0/16"}]""",
            "ec2 describe-network-interfaces" => """[{"Id":"eni-123","Status":"available"}]""",
            "ec2 describe-addresses" => """[{"Id":"eipalloc-123","PublicIp":"192.0.2.1","Association":null,"Instance":null,"Interface":null}]""",
            "ec2 describe-instance-status" => """[{"Id":"i-0123456789abcdef0","State":"running","System":"impaired","Instance":"ok","Events":[{"Code":"instance-reboot"}]}]""",
            "ec2 describe-snapshots" => """[{"Id":"snap-123","Started":"2020-01-01T00:00:00Z","State":"completed"}]""",
            "s3api list-buckets" => """[{"Id":"test-bucket","Created":"2020-01-01T00:00:00Z"}]""",
            "s3api get-bucket-location" => "\"eu-west-1\"",
            "s3api get-bucket-policy-status" => """{"Public":true}""",
            "s3api get-public-access-block" => """{"BlockPublicAcls":false,"IgnorePublicAcls":false,"BlockPublicPolicy":false,"RestrictPublicBuckets":false}""",
            "s3api get-bucket-acl" => """[{"Permission":"READ","Group":"http://acs.amazonaws.com/groups/global/AllUsers"}]""",
            "securityhub get-findings" => """[{"Id":"hub-1","Title":"Test finding","Severity":"HIGH","Resources":[{"Id":"i-0123456789abcdef0","Type":"AwsEc2Instance","Secret":"DO_NOT_EXPORT_SECRET"}]}]""",
            "guardduty list-detectors" => NoDetectors ? "[]" : "[\"detector-1\"]",
            "guardduty list-findings" => "[\"finding-1\"]",
            "guardduty get-findings" => """[{"Id":"finding-1","Type":"UnauthorizedAccess","Severity":8.0}]""",
            "health describe-events" => """[{"Id":"health-1","Service":"EC2","Status":"open"}]""",
            "cloudwatch describe-alarms" => """{"Metric":[{"Id":"alarm-1","Name":"CPU alarm","State":"ALARM"}],"Composite":[]}""",
            "cloudwatch get-metric-statistics" => "[" + string.Join(',', Enumerable.Range(0, 14).Select(_ => """{"Time":"2026-10-01T00:00:00Z","Average":1.0,"Maximum":3.0,"Samples":288}""")) + "]",
            "cloudtrail lookup-events" => """[{"Id":"event-1","Name":"ModifyInstanceAttribute","Time":"2026-10-01T00:00:00Z","CloudTrailEvent":"DO_NOT_EXPORT_SECRET"}]""",
            "cloudformation describe-stacks" => """[{"Id":"stack-1","Name":"test","Drift":"DRIFTED","Checked":"2026-10-01T00:00:00Z"}]""",
            "cloudformation list-stack-resources" => """[{"Id":"i-0123456789abcdef0","LogicalId":"Server","Type":"AWS::EC2::Instance","Drift":"MODIFIED"}]""",
            "cloudformation describe-stack-resource-drifts" => """[{"Id":"i-0123456789abcdef0","Status":"MODIFIED","Differences":[{"Path":"/InstanceType","Type":"NOT_EQUAL","ActualValue":"DO_NOT_EXPORT_SECRET"}]}]""",
            "ssm describe-instance-information" => """[{"Id":"mi-0123456789abcdef0","Ping":"ConnectionLost","Platform":"Linux","ResourceType":"ManagedInstance"}]""",
            "ssm describe-instance-patch-states" => """[{"Id":"mi-0123456789abcdef0","Missing":2,"Failed":1,"PendingReboot":1,"Operation":"Scan"}]""",
            _ => throw new InvalidOperationException("Unexpected command " + command)
        };
        return Task.FromResult(JsonDocument.Parse(json).RootElement.Clone());
    }
}

sealed class MetadataHandler : HttpMessageHandler
{
    public List<string> Paths { get; } = [];
    public bool Oversize { get; init; }
    public bool Redirect { get; init; }
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri?.Host != "169.254.169.254") throw new Exception("Unexpected metadata endpoint");
        Paths.Add(request.RequestUri.AbsolutePath);
        if (Redirect) return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Redirect) { Headers = { Location = new Uri("http://example.invalid/") } });
        if (request.Method == HttpMethod.Put)
        {
            if (!request.Headers.Contains("X-aws-ec2-metadata-token-ttl-seconds")) throw new Exception("Missing token TTL");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Oversize ? new string('x', 1025) : "SESSION_TOKEN") });
        }
        if (request.Headers.GetValues("X-aws-ec2-metadata-token").Single() != "SESSION_TOKEN") throw new Exception("Missing IMDSv2 token");
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("""{"accountId":"123456789012","region":"eu-west-1","instanceId":"i-0123456789abcdef0","architecture":"x86_64","credentials":"DO_NOT_EXPORT_SECRET"}""") });
    }
}
