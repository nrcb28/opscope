using Opscope;
using Opscope.Cloud;

var resource = new CloudResource("aws", "123456789012", "eu-west-1", "i-0123456789abcdef0", "AWS::EC2::Instance", "private-host");
var report = new AnalysisReport("cloud", DateTimeOffset.UtcNow, [], new { resources = new[] { resource } });
var identity = new AwsInstanceIdentity(resource.Account, resource.Region, resource.Id, "x86_64");
Check(CloudIdentityLinker.Matches(report, identity), "Matching AWS identity must link");
Check(!CloudIdentityLinker.Matches(report, identity with { AccountId = "999999999999" }), "Account mismatch must not link");
Check(!CloudIdentityLinker.Matches(report, identity with { Region = "us-east-1" }), "Region mismatch must not link");
Check(!CloudIdentityLinker.Matches(report, identity with { InstanceId = "i-fffffffffffffffff" }), "Instance mismatch must not link");
var azure = new AzureInstanceIdentity("11111111-1111-1111-1111-111111111111", "rg", "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm", "id", "vm", "westeurope", "size", "Linux", "1", "AzurePublicCloud");
var azureReport = report with { Data = new { resources = new[] { new CloudResource("azure", azure.SubscriptionId, azure.Location, azure.ResourceId, "Microsoft.Compute/virtualMachines", azure.Name) } } };
Check(CloudIdentityLinker.Matches(azureReport, azure), "Matching Azure resource must link");
Check(!CloudIdentityLinker.Matches(azureReport, azure with { ResourceId = azure.ResourceId + "other" }), "Different Azure resource must not link");
Check(!CloudIdentityLinker.Matches(report, null), "Missing metadata must not link");
var runner = new TrustedCloudCommandRunner();
foreach (var request in new[] { ("aws", new[] { "ec2", "terminate-instances" }), ("az", new[] { "vm", "delete" }), ("aws", new[] { "ec2", "describe-instances", "--endpoint-url", "https://example.invalid" }), ("aws", new[] { "ec2", "describe-instances", "--endpoint-url=https://example.invalid" }), ("aws", new[] { "ec2", "describe-instances", "--cli-input-json={}" }), ("az", new[] { "account", "show", "--debug=true" }) })
{
    try { await runner.RunAsync(request.Item1, request.Item2, CancellationToken.None); throw new Exception("Unsafe query was accepted"); }
    catch (InvalidOperationException) { }
}
Console.WriteLine("Cloud identity and command-boundary checks passed (13 assertions)");
static void Check(bool value, string message) { if (!value) throw new Exception(message); }
