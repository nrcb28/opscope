using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Opscope.Cloud;

/// <summary>Read-only AWS collection through the optional AWS CLI and its normal credential chain.</summary>
public sealed class AwsProvider(ICloudCommandRunner runner) : ICloudProvider
{
    public string Name => "aws";
    private static readonly HashSet<string> Operations = new(StringComparer.OrdinalIgnoreCase)
        { "inventory", "posture", "health", "instance", "bundle", "drift", "patches", "cost" };
    private static readonly HashSet<string> Commands = new(StringComparer.Ordinal)
    {
        "sts get-caller-identity", "ec2 describe-regions", "ec2 describe-instances", "ec2 describe-volumes",
        "ec2 describe-security-groups", "ec2 describe-vpcs", "ec2 describe-network-interfaces", "ec2 describe-addresses",
        "ec2 describe-instance-status", "ec2 describe-snapshots", "s3api list-buckets", "s3api get-bucket-location",
        "s3api get-public-access-block", "s3api get-bucket-policy-status", "s3api get-bucket-acl",
        "securityhub get-findings", "guardduty list-detectors", "guardduty list-findings", "guardduty get-findings",
        "health describe-events", "cloudwatch describe-alarms", "cloudwatch get-metric-statistics",
        "cloudtrail lookup-events", "cloudformation describe-stacks", "cloudformation list-stack-resources",
        "cloudformation describe-stack-resource-drifts", "ssm describe-instance-information", "ssm describe-instance-patch-states"
    };
    private const string InstanceQuery = "Reservations[].Instances[].{Id:InstanceId,Name:Tags[?Key=='Name']|[0].Value,Type:InstanceType,Image:ImageId,State:State.Name,Vpc:VpcId,Subnet:SubnetId,PrivateIp:PrivateIpAddress,PublicIp:PublicIpAddress,Profile:IamInstanceProfile.Arn,HttpTokens:MetadataOptions.HttpTokens,Groups:SecurityGroups[].GroupId,LaunchTime:LaunchTime}";
    private const string VolumeQuery = "Volumes[].{Id:VolumeId,State:State,Encrypted:Encrypted,Size:Size,Type:VolumeType,Attachments:Attachments[].{InstanceId:InstanceId,Device:Device,State:State}}";
    private const string GroupQuery = "SecurityGroups[].{Id:GroupId,Name:GroupName,Vpc:VpcId,Ingress:IpPermissions[].{Protocol:IpProtocol,From:FromPort,To:ToPort,IPv4:IpRanges[].CidrIp,IPv6:Ipv6Ranges[].CidrIpv6}}";

    public async Task<AnalysisReport> CollectAsync(string operation, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!Operations.Contains(operation)) throw new ArgumentException("Unsupported AWS operation.", nameof(operation));
        operation = operation.ToLowerInvariant();
        var c = new Collection(runner, options, cancellationToken);
        IEnumerable<string> required = operation switch
        {
            "inventory" => InventoryCommands.Values.Select(command => "ec2 " + command),
            "posture" => ["ec2 describe-instances", "ec2 describe-volumes", "ec2 describe-security-groups"],
            "health" => ["ec2 describe-instance-status", "cloudwatch describe-alarms"],
            "instance" => ["ec2 describe-instances", "ec2 describe-volumes", "ec2 describe-security-groups", "ec2 describe-instance-status"],
            "bundle" => ["cloudtrail lookup-events", "ec2 describe-instances", "ec2 describe-volumes", "ec2 describe-security-groups", "ec2 describe-instance-status"],
            "drift" => c.Option("baseline").Length > 0 ? InventoryCommands.Values.Select(command => "ec2 " + command) : ["cloudformation describe-stacks", "cloudformation list-stack-resources", "cloudformation describe-stack-resource-drifts"],
            "patches" => ["ssm describe-instance-information", "ssm describe-instance-patch-states"],
            "cost" => ["ec2 describe-instances", "ec2 describe-volumes", "ec2 describe-addresses", "ec2 describe-snapshots"],
            _ => []
        };
        c.RequiredCommands.UnionWith(required);
        if (!string.IsNullOrWhiteSpace(c.Option("role-arn")))
        {
            c.Warnings.Add("AWS coverage unavailable: --role-arn does not fetch temporary credentials. Configure role_arn/source_profile or credential_source in an AWS CLI profile, then select --profile.");
            return c.Report(operation);
        }
        var profile = c.Option("profile");
        if (profile.Length > 128 || profile.StartsWith('-') || profile.Any(char.IsControl)) throw new ArgumentException("Invalid AWS profile name.");
        var identity = await c.Call("sts", "get-caller-identity", null, "{Account:Account,Arn:Arn}");
        if (identity is null) return c.Report(operation);
        c.Account = String(identity.Value, "Account");
        if (!Regex.IsMatch(c.Account, "^[0-9]{12}$"))
        {
            c.Warnings.Add("AWS identity did not contain a valid account ID; collection stopped.");
            return c.Report(operation);
        }
        var accounts = Split(c.Option("accounts"));
        if (accounts.Any(a => !Regex.IsMatch(a, "^[0-9]{12}$"))) throw new ArgumentException("AWS --accounts must contain comma-separated 12-digit account IDs.");
        if (accounts.Count > 0 && !accounts.Contains(c.Account, StringComparer.Ordinal))
        {
            c.Warnings.Add("AWS authenticated account is outside --accounts; no resource APIs were queried. Select a profile for an allowed account.");
            return c.Report(operation);
        }
        c.IdentityVerified = true;
        if (accounts.Count > 1) c.Warnings.Add("AWS --accounts filters the authenticated account; it does not assume roles or traverse other accounts. Run once per configured account profile.");
        var regions = Split(c.Option("regions", c.Option("region")));
        if (regions.Count == 1 && regions[0].Equals("all", StringComparison.OrdinalIgnoreCase))
        {
            var available = await c.Call("ec2", "describe-regions", null, "Regions[].RegionName");
            regions = available is null ? [] : Elements(available.Value).Select(v => v.GetString() ?? "").Where(v => v.Length > 0).ToList();
            if (regions.Count == 0) { c.OperationSucceeded = false; c.Warnings.Add("AWS region discovery returned no regions; coverage is unavailable."); return c.Report(operation); }
        }
        if (regions.Any(r => !Regex.IsMatch(r, "^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$"))) throw new ArgumentException("Invalid AWS region.");
        if (regions.Count == 0) { regions.Add(""); c.Warnings.Add("AWS region comes from the active CLI profile/environment; use --region or --regions for explicit coverage."); }
        c.Regions.AddRange(regions.Select(r => r.Length == 0 ? "profile-default" : r));
        foreach (var region in regions)
        {
            cancellationToken.ThrowIfCancellationRequested();
            switch (operation)
            {
                case "inventory": await Inventory(c, region); break;
                case "posture": await Posture(c, region); break;
                case "health": await Health(c, region); break;
                case "instance": await Instance(c, region); break;
                case "bundle": await Bundle(c, region); break;
                case "drift": await Drift(c, region); break;
                case "patches": await Patches(c, region); break;
                case "cost": await Cost(c, region); break;
            }
        }
        if (operation == "drift" && c.Option("baseline").Length > 0) await CompareBaseline(c);
        if (operation == "posture") await Buckets(c, regions[0]);
        if (operation == "health")
        {
            var events = await c.Call("health", "describe-events", "us-east-1", "events[].{Id:arn,Service:service,Code:eventTypeCode,Region:region,Start:startTime,End:endTime,Status:statusCode}", "--filter", "{\"eventStatusCodes\":[\"open\",\"upcoming\"]}");
            foreach (var e in Items(events)) { c.Add("us-east-1", "AWS::Health::Event", e, "Id", "Service"); c.Find("AWS_HEALTH_EVENT", "AWS Health event is active", e, "Id", "Review the AWS Health event and affected resources."); }
            c.Warnings.Add("AWS Health API availability depends on the account support plan; API failures above indicate missing coverage.");
        }
        if (c.RequiresTargetResolution && !c.TargetResolved)
            c.Warnings.Add("AWS requested resource could not be resolved in the selected account/regions; required target evidence is unavailable.");
        return c.Report(operation);
    }

    private static async Task Inventory(Collection c, string region)
    {
        await AddInstances(c, region);
        foreach (var v in Items(await c.Call("ec2", "describe-volumes", region, VolumeQuery))) c.Add(region, "AWS::EC2::Volume", v);
        foreach (var g in Items(await c.Call("ec2", "describe-security-groups", region, GroupQuery))) c.Add(region, "AWS::EC2::SecurityGroup", g);
        foreach (var v in Items(await c.Call("ec2", "describe-vpcs", region, "Vpcs[].{Id:VpcId,Cidr:CidrBlock,State:State,Default:IsDefault}"))) c.Add(region, "AWS::EC2::VPC", v);
        foreach (var n in Items(await c.Call("ec2", "describe-network-interfaces", region, "NetworkInterfaces[].{Id:NetworkInterfaceId,Status:Status,Vpc:VpcId,Subnet:SubnetId,Instance:Attachment.InstanceId,PrivateIp:PrivateIpAddress,PublicIp:Association.PublicIp,Groups:Groups[].GroupId}"))) c.Add(region, "AWS::EC2::NetworkInterface", n);
        foreach (var a in Items(await c.Call("ec2", "describe-addresses", region, "Addresses[].{Id:AllocationId,PublicIp:PublicIp,Association:AssociationId,Instance:InstanceId,Interface:NetworkInterfaceId}"))) c.Add(region, "AWS::EC2::EIP", a, "Id", "PublicIp");
    }

    private static async Task<IReadOnlyList<JsonElement>> AddInstances(Collection c, string region, string? id = null)
    {
        var result = id is null ? await c.Call("ec2", "describe-instances", region, InstanceQuery) : await c.Call("ec2", "describe-instances", region, InstanceQuery, "--instance-ids", id);
        var instances = Items(result);
        foreach (var i in instances) c.Add(region, "AWS::EC2::Instance", i);
        return instances;
    }

    private static async Task Posture(Collection c, string region)
    {
        foreach (var i in await AddInstances(c, region))
            if (String(i, "HttpTokens") == "optional") c.Find("AWS_IMDSV1_ENABLED", "EC2 permits IMDSv1", i, "Id", "Require IMDSv2 (HttpTokens=required) after validating workload compatibility.");
        foreach (var v in Items(await c.Call("ec2", "describe-volumes", region, VolumeQuery)))
        {
            c.Add(region, "AWS::EC2::Volume", v);
            if (Bool(v, "Encrypted") == false) c.Find("AWS_EBS_UNENCRYPTED", "EBS volume is unencrypted", v, "Id", "Plan migration to an encrypted volume and enable EBS encryption by default.");
        }
        foreach (var g in Items(await c.Call("ec2", "describe-security-groups", region, GroupQuery)))
        {
            c.Add(region, "AWS::EC2::SecurityGroup", g);
            foreach (var ingress in Elements(Property(g, "Ingress")))
                if (Elements(Property(ingress, "IPv4")).Any(x => x.GetString() == "0.0.0.0/0") || Elements(Property(ingress, "IPv6")).Any(x => x.GetString() == "::/0"))
                {
                    c.Find("AWS_SECURITY_GROUP_WORLD_OPEN", "Security group permits ingress from the internet", g, "Id", $"Review protocol {String(ingress, "Protocol")} ports {String(ingress, "From")}-{String(ingress, "To")}; restrict source CIDRs according to intended exposure.");
                    break;
                }
        }
        var hub = await c.Call("securityhub", "get-findings", region, "Findings[].{Id:Id,Title:Title,Severity:Severity.Label,Workflow:Workflow.Status,RecordState:RecordState,Resources:Resources[].{Id:Id,Type:Type}}", "--filters", "{\"RecordState\":[{\"Value\":\"ACTIVE\",\"Comparison\":\"EQUALS\"}],\"WorkflowStatus\":[{\"Value\":\"NEW\",\"Comparison\":\"EQUALS\"},{\"Value\":\"NOTIFIED\",\"Comparison\":\"EQUALS\"}]}");
        foreach (var f in Items(hub))
        {
            c.Add(region, "AWS::SecurityHub::Finding", f, "Id", "Title");
            c.Find("AWS_SECURITYHUB_FINDING", "Active Security Hub finding", f, "Id", "Review the Security Hub finding and its affected resources.", String(f, "Severity") is "CRITICAL" or "HIGH" ? FindingSeverity.Critical : FindingSeverity.Warning);
        }
        var detectors = await c.Call("guardduty", "list-detectors", region, "DetectorIds");
        if (detectors.HasValue && Elements(detectors.Value).Count == 0) c.Warnings.Add($"AWS GuardDuty is not enabled in {Label(region)}; threat finding coverage is unavailable.");
        foreach (var detector in Items(detectors))
        {
            var detectorId = detector.GetString() ?? "";
            var ids = await c.Call("guardduty", "list-findings", region, "FindingIds", "--detector-id", detectorId, "--finding-criteria", "{\"Criterion\":{\"service.archived\":{\"Eq\":[\"false\"]}}}");
            foreach (var batch in Items(ids).Select(x => x.GetString() ?? "").Chunk(50))
            {
                var args = new List<string> { "--detector-id", detectorId, "--finding-ids" }; args.AddRange(batch);
                var findings = await c.Call("guardduty", "get-findings", region, "Findings[].{Id:Id,Type:Type,Title:Title,Severity:Severity,Instance:Resource.InstanceDetails.InstanceId}", args.ToArray());
                foreach (var f in Items(findings)) { c.Add(region, "AWS::GuardDuty::Finding", f, "Id", "Title"); c.Find("AWS_GUARDDUTY_FINDING", "Active GuardDuty finding", f, "Id", "Investigate the threat finding in GuardDuty.", Number(f, "Severity") >= 7 ? FindingSeverity.Critical : FindingSeverity.Warning); }
            }
        }
        c.Warnings.Add($"AWS posture in {Label(region)} evaluates selected API evidence; it is not a complete CIS/compliance assessment. AWS Config results are not collected.");
    }

    private static async Task Buckets(Collection c, string defaultRegion)
    {
        var buckets = await c.Call("s3api", "list-buckets", defaultRegion, "Buckets[].{Id:Name,Created:CreationDate}");
        foreach (var b in Items(buckets))
        {
            var name = String(b, "Id");
            var location = await c.Call("s3api", "get-bucket-location", defaultRegion, "LocationConstraint", "--bucket", name);
            if (location is null) { c.Warnings.Add("AWS S3 bucket location unavailable; public-access checks skipped for this bucket."); continue; }
            var region = location.Value.ValueKind == JsonValueKind.String ? location.Value.GetString() ?? "us-east-1" : "us-east-1";
            if (region == "EU") region = "eu-west-1";
            c.Add(region, "AWS::S3::Bucket", b);
            var policy = await c.Call("s3api", "get-bucket-policy-status", region, "{Public:PolicyStatus.IsPublic}", "--bucket", name);
            var access = await c.Call("s3api", "get-public-access-block", region, "PublicAccessBlockConfiguration.{BlockPublicAcls:BlockPublicAcls,IgnorePublicAcls:IgnorePublicAcls,BlockPublicPolicy:BlockPublicPolicy,RestrictPublicBuckets:RestrictPublicBuckets}", "--bucket", name);
            var acl = await c.Call("s3api", "get-bucket-acl", region, "Grants[].{Permission:Permission,Group:Grantee.URI}", "--bucket", name);
            var publicAcl = Items(acl).Any(a => String(a, "Group") is "http://acs.amazonaws.com/groups/global/AllUsers" or "http://acs.amazonaws.com/groups/global/AuthenticatedUsers");
            var aclEffective = publicAcl && (!access.HasValue || Bool(access.Value, "IgnorePublicAcls") != true);
            if ((policy.HasValue && Bool(policy.Value, "Public") == true) || aclEffective)
                c.Find("AWS_S3_PUBLIC_ACCESS", "S3 bucket has a public policy or potentially effective public ACL", b, "Id", "Review effective policy, ACLs, access points and account/bucket Block Public Access before restricting intended public content.");
            if (access.HasValue && new[] { "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets" }.Any(p => Bool(access.Value, p) != true))
                c.Find("AWS_S3_BLOCK_PUBLIC_ACCESS_INCOMPLETE", "S3 bucket Block Public Access is incomplete", b, "Id", "Enable appropriate bucket/account Block Public Access controls; absence of these controls alone does not prove exposure.");
        }
        c.Warnings.Add("S3 checks use bucket policy status, ACLs and bucket Block Public Access. Account controls and access-point policies are not evaluated; no definitive effective-access claim is made.");
    }

    private static async Task Health(Collection c, string region)
    {
        var status = await c.Call("ec2", "describe-instance-status", region, "InstanceStatuses[].{Id:InstanceId,State:InstanceState.Name,System:SystemStatus.Status,Instance:InstanceStatus.Status,AvailabilityZone:AvailabilityZone,Events:Events[].{Code:Code,Before:NotBefore,After:NotAfter}}", "--include-all-instances");
        foreach (var s in Items(status))
        {
            c.Add(region, "AWS::EC2::InstanceStatus", s);
            if (String(s, "System") == "impaired" || String(s, "Instance") == "impaired") c.Find("AWS_EC2_STATUS_IMPAIRED", "EC2 status checks are impaired", s, "Id", "Investigate instance and system status checks.", FindingSeverity.Critical);
            if (Elements(Property(s, "Events")).Count > 0) c.Find("AWS_EC2_SCHEDULED_EVENT", "EC2 has scheduled maintenance events", s, "Id", "Review the scheduled event window and plan the required maintenance.");
        }
        var alarms = await c.Call("cloudwatch", "describe-alarms", region, "{Metric:MetricAlarms[].{Id:AlarmArn,Name:AlarmName,State:StateValue,Updated:StateUpdatedTimestamp},Composite:CompositeAlarms[].{Id:AlarmArn,Name:AlarmName,State:StateValue,Updated:StateUpdatedTimestamp}}", "--state-value", "ALARM", "--alarm-types", "MetricAlarm", "CompositeAlarm");
        if (alarms.HasValue)
            foreach (var a in Elements(Property(alarms.Value, "Metric")).Concat(Elements(Property(alarms.Value, "Composite")))) { c.Add(region, "AWS::CloudWatch::Alarm", a); c.Find("AWS_CLOUDWATCH_ALARM", "CloudWatch alarm is active", a, "Name", "Review the metric, recent changes and alarm runbook."); }
    }

    private static async Task Instance(Collection c, string region)
    {
        var id = c.Option("resource");
        if (!Regex.IsMatch(id, "^i-[a-f0-9]{8,32}$")) throw new ArgumentException("AWS instance requires --resource with an EC2 instance ID.");
        c.RequiresTargetResolution = true;
        var instances = await AddInstances(c, region, id);
        c.TargetResolved |= instances.Any(i => String(i, "Id") == id);
        foreach (var i in instances)
        {
            if (String(i, "HttpTokens") == "optional") c.Find("AWS_IMDSV1_ENABLED", "EC2 permits IMDSv1", i, "Id", "Require IMDSv2 after validating workload compatibility.");
            var groups = Elements(Property(i, "Groups")).Where(g => g.ValueKind == JsonValueKind.String).Select(g => g.GetString()!).ToArray();
            if (groups.Length > 0)
            {
                var groupArgs = new List<string> { "--group-ids" }; groupArgs.AddRange(groups);
                foreach (var group in Items(await c.Call("ec2", "describe-security-groups", region, GroupQuery, groupArgs.ToArray()))) c.Add(region, "AWS::EC2::SecurityGroup", group);
            }
            var filter = JsonSerializer.Serialize(new[] { new { Name = "attachment.instance-id", Values = new[] { id } } });
            foreach (var volume in Items(await c.Call("ec2", "describe-volumes", region, VolumeQuery, "--filters", filter))) c.Add(region, "AWS::EC2::Volume", volume);
            foreach (var status in Items(await c.Call("ec2", "describe-instance-status", region, "InstanceStatuses[].{Id:InstanceId,State:InstanceState.Name,System:SystemStatus.Status,Instance:InstanceStatus.Status}", "--instance-ids", id, "--include-all-instances")))
            {
                c.Add(region, "AWS::EC2::InstanceStatus", status);
                if (String(status, "System") == "impaired" || String(status, "Instance") == "impaired") c.Find("AWS_EC2_STATUS_IMPAIRED", "EC2 status checks are impaired", status, "Id", "Investigate instance and system status checks.", FindingSeverity.Critical);
            }
            await Metrics(c, region, id, false);
        }
        c.Warnings.Add("AWS instance context includes API metadata and CloudWatch CPU metrics. Console output, user data and IAM credentials are deliberately not collected because they can contain secrets. The host snapshot is a separate local collection.");
    }

    private static async Task Bundle(Collection c, string region)
    {
        var resource = c.Option("resource");
        if (resource.Length is < 1 or > 2048 || resource.Any(char.IsControl)) throw new ArgumentException("AWS bundle requires --resource.");
        c.RequiresTargetResolution = true;
        var isInstance = Regex.IsMatch(resource, "^i-[a-f0-9]{8,32}$");
        if (isInstance) await Instance(c, region);
        var correlatedBefore = c.Resources.Count;
        var lookup = JsonSerializer.Serialize(new[] { new { AttributeKey = "ResourceName", AttributeValue = resource } });
        var events = await c.Call("cloudtrail", "lookup-events", region, "Events[].{Id:EventId,Time:EventTime,Name:EventName,Username:Username,Resources:Resources[].{Type:ResourceType,Name:ResourceName}}", "--lookup-attributes", lookup, "--start-time", DateTimeOffset.UtcNow.AddHours(-24).ToString("O", CultureInfo.InvariantCulture));
        foreach (var e in Items(events)) c.Add(region, "AWS::CloudTrail::Event", e, "Id", "Name");
        await ResourceFindings(c, region, resource);
        if (!isInstance) c.TargetResolved |= c.Resources.Count > correlatedBefore;
        c.Warnings.Add("AWS bundle provides the last 24 hours of regional CloudTrail event-history metadata. Raw event payloads are excluded; data events and organization/Lake trails are outside this coverage. Combine this report with the CLI's local bundle for host evidence.");
    }

    private static async Task ResourceFindings(Collection c, string region, string resource)
    {
        var resourceIds = new List<string> { resource };
        var instance = Regex.IsMatch(resource, "^i-[a-f0-9]{8,32}$");
        if (instance && region.Length > 0)
        {
            var partition = region.StartsWith("cn-", StringComparison.Ordinal) ? "aws-cn" : region.StartsWith("us-gov-", StringComparison.Ordinal) ? "aws-us-gov" : "aws";
            resourceIds.Add($"arn:{partition}:ec2:{region}:{c.Account}:instance/{resource}");
        }
        if (instance && region.Length == 0) c.Warnings.Add("AWS resource finding correlation cannot construct the instance ARN without an explicit --region; Security Hub ARN matches may be incomplete.");
        var filters = JsonSerializer.Serialize(new { ResourceId = resourceIds.Select(id => new { Value = id, Comparison = "EQUALS" }).ToArray(), RecordState = new[] { new { Value = "ACTIVE", Comparison = "EQUALS" } } });
        var hub = await c.Call("securityhub", "get-findings", region, "Findings[].{Id:Id,Title:Title,Severity:Severity.Label,Workflow:Workflow.Status,RecordState:RecordState,Resources:Resources[].{Id:Id,Type:Type}}", "--filters", filters);
        foreach (var f in Items(hub))
        {
            c.Add(region, "AWS::SecurityHub::Finding", f, "Id", "Title");
            c.Find("AWS_SECURITYHUB_FINDING", "Resource has an active Security Hub finding", f, "Id", "Review the resource finding in Security Hub.", String(f, "Severity") is "CRITICAL" or "HIGH" ? FindingSeverity.Critical : FindingSeverity.Warning);
        }
        if (!instance) return;
        var detectors = await c.Call("guardduty", "list-detectors", region, "DetectorIds");
        if (detectors.HasValue && Items(detectors).Count == 0) c.Warnings.Add($"AWS GuardDuty is not enabled in {Label(region)}; resource threat finding coverage is unavailable.");
        foreach (var detector in Items(detectors))
        {
            var detectorId = detector.GetString() ?? "";
            var criteria = JsonSerializer.Serialize(new { Criterion = new Dictionary<string, object> { ["resource.instanceDetails.instanceId"] = new { Eq = new[] { resource } }, ["service.archived"] = new { Eq = new[] { "false" } } } });
            var ids = await c.Call("guardduty", "list-findings", region, "FindingIds", "--detector-id", detectorId, "--finding-criteria", criteria);
            foreach (var batch in Items(ids).Select(x => x.GetString() ?? "").Chunk(50))
            {
                var args = new List<string> { "--detector-id", detectorId, "--finding-ids" }; args.AddRange(batch);
                foreach (var f in Items(await c.Call("guardduty", "get-findings", region, "Findings[].{Id:Id,Type:Type,Title:Title,Severity:Severity,Instance:Resource.InstanceDetails.InstanceId}", args.ToArray())))
                {
                    c.Add(region, "AWS::GuardDuty::Finding", f, "Id", "Title");
                    c.Find("AWS_GUARDDUTY_FINDING", "Resource has an active GuardDuty finding", f, "Id", "Investigate the resource threat finding in GuardDuty.", Number(f, "Severity") >= 7 ? FindingSeverity.Critical : FindingSeverity.Warning);
                }
            }
        }
    }

    private static async Task Drift(Collection c, string region)
    {
        if (c.Option("baseline").Length > 0) await Inventory(c, region);
        var requested = c.Option("resource");
        var stacks = requested.Length == 0 ? await c.Call("cloudformation", "describe-stacks", region, "Stacks[].{Id:StackId,Name:StackName,Status:StackStatus,Drift:DriftInformation.StackDriftStatus,Checked:DriftInformation.LastCheckTimestamp}") : await c.Call("cloudformation", "describe-stacks", region, "Stacks[].{Id:StackId,Name:StackName,Status:StackStatus,Drift:DriftInformation.StackDriftStatus,Checked:DriftInformation.LastCheckTimestamp}", "--stack-name", requested);
        foreach (var stack in Items(stacks))
        {
            c.Add(region, "AWS::CloudFormation::Stack", stack);
            var id = String(stack, "Id");
            if (String(stack, "Drift") == "DRIFTED") c.Find("AWS_CLOUDFORMATION_DRIFT", "CloudFormation reports stack drift", stack, "Id", "Review the existing drift results and their last-check timestamp before remediation.");
            if (String(stack, "Drift") is "" or "NOT_CHECKED") c.Warnings.Add($"CloudFormation stack {String(stack, "Name")} has no previous drift assessment; current drift is unknown.");
            foreach (var r in Items(await c.Call("cloudformation", "list-stack-resources", region, "StackResourceSummaries[].{Id:PhysicalResourceId,LogicalId:LogicalResourceId,Type:ResourceType,Status:ResourceStatus,Drift:DriftInformation.StackResourceDriftStatus,Checked:DriftInformation.LastCheckTimestamp}", "--stack-name", id))) c.Add(region, "AWS::CloudFormation::Resource", r);
            foreach (var d in Items(await c.Call("cloudformation", "describe-stack-resource-drifts", region, "StackResourceDrifts[].{Id:PhysicalResourceId,LogicalId:LogicalResourceId,Type:ResourceType,Status:StackResourceDriftStatus,Checked:Timestamp,Differences:PropertyDifferences[].{Path:PropertyPath,Type:DifferenceType}}", "--stack-name", id)))
            {
                c.Add(region, "AWS::CloudFormation::Drift", d);
                if (String(d, "Status") is "MODIFIED" or "DELETED") c.Find("AWS_RESOURCE_DRIFT", "CloudFormation resource differs from its template", d, "Id", "Review property paths against the approved template; actual/expected property values are not collected.");
            }
        }
        c.Warnings.Add("AWS drift reads existing CloudFormation drift results and their timestamps; it never starts DetectStackDrift. Unchecked/stale results do not establish current conformance. --baseline also compares supported inventory fields from normalized JSON or Terraform state; other IaC formats are unsupported.");
    }

    private sealed record BaselineResource(string Account, string Region, string Id, string Type, Dictionary<string, JsonElement> Properties);
    private static readonly IReadOnlyDictionary<string, string[]> ComparedFields = new Dictionary<string, string[]>(StringComparer.Ordinal)
    {
        ["AWS::EC2::Instance"] = ["Type", "Image", "State", "Vpc", "Subnet", "PrivateIp", "PublicIp", "Profile", "HttpTokens", "Groups"],
        ["AWS::EC2::Volume"] = ["Encrypted", "Size", "Type", "Attachments"],
        ["AWS::EC2::SecurityGroup"] = ["Name", "Vpc", "Ingress"],
        ["AWS::EC2::VPC"] = ["Cidr", "Default"],
        ["AWS::EC2::NetworkInterface"] = ["Status", "Vpc", "Subnet", "Instance", "PrivateIp", "PublicIp", "Groups"],
        ["AWS::EC2::EIP"] = ["PublicIp", "Instance", "Interface", "Association"]
    };
    private static readonly IReadOnlyDictionary<string, string> InventoryCommands = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["AWS::EC2::Instance"] = "describe-instances", ["AWS::EC2::Volume"] = "describe-volumes",
        ["AWS::EC2::SecurityGroup"] = "describe-security-groups", ["AWS::EC2::VPC"] = "describe-vpcs",
        ["AWS::EC2::NetworkInterface"] = "describe-network-interfaces", ["AWS::EC2::EIP"] = "describe-addresses"
    };

    private static async Task CompareBaseline(Collection c)
    {
        var json = await SnapshotIO.ReadTextAsync(c.Option("baseline"), c.CancellationToken);
        SnapshotIO.ValidateJson(json);
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 64 });
        var root = document.RootElement;
        var arrays = new List<JsonElement>();
        FindBaselineArrays(root, arrays, 0);
        if (arrays.Count == 0)
        {
            c.OperationSucceeded = false;
            c.Warnings.Add("AWS baseline format is unsupported. Supply an exported normalized resource report/array or Terraform JSON state with resources[]. No baseline comparison was performed.");
            return;
        }
        var expected = new List<BaselineResource>();
        var redacted = false;
        var unsupported = 0;
        var items = arrays.SelectMany(Elements).ToArray();
        var terraform = items.Any(r => PropertyIgnoreCase(r, "instances").ValueKind == JsonValueKind.Array);
        foreach (var item in items)
        {
            c.CancellationToken.ThrowIfCancellationRequested();
            if (PropertyIgnoreCase(item, "instances").ValueKind == JsonValueKind.Array)
            {
                if (StringIgnoreCase(item, "mode") == "data") continue;
                var tfType = StringIgnoreCase(item, "type");
                var type = tfType switch { "aws_instance" => "AWS::EC2::Instance", "aws_ebs_volume" => "AWS::EC2::Volume", "aws_security_group" => "AWS::EC2::SecurityGroup", "aws_vpc" => "AWS::EC2::VPC", "aws_network_interface" => "AWS::EC2::NetworkInterface", "aws_eip" => "AWS::EC2::EIP", _ => "" };
                if (type.Length == 0) { unsupported++; continue; }
                foreach (var instance in Elements(PropertyIgnoreCase(item, "instances")))
                {
                    var attributes = PropertyIgnoreCase(instance, "attributes");
                    var id = StringIgnoreCase(attributes, "id");
                    var fields = TerraformFields(tfType, attributes);
                    if (id.Length == 0 || IsRedacted(id) || fields.Values.Any(ContainsRedaction)) { redacted = true; continue; }
                    var region = StringIgnoreCase(attributes, "region");
                    var zone = StringIgnoreCase(attributes, "availability_zone");
                    if (region.Length == 0 && Regex.IsMatch(zone, "^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+[a-z]$")) region = zone[..^1];
                    expected.Add(new("", region, id, type, fields));
                }
            }
            else
            {
                var provider = StringIgnoreCase(item, "provider");
                if (provider.Length > 0 && !provider.Equals("aws", StringComparison.OrdinalIgnoreCase)) continue;
                var type = StringIgnoreCase(item, "type");
                if (!ComparedFields.TryGetValue(type, out var allowed)) { unsupported++; continue; }
                var id = StringIgnoreCase(item, "id");
                var account = StringIgnoreCase(item, "account");
                var region = StringIgnoreCase(item, "region");
                var properties = PropertyIgnoreCase(item, "properties");
                var fields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
                foreach (var key in allowed)
                {
                    var value = PropertyIgnoreCase(properties, key);
                    if (value.ValueKind == JsonValueKind.Undefined) continue;
                    if (ContainsRedaction(value)) { redacted = true; continue; }
                    fields[key] = value.Clone();
                }
                if (id.Length == 0 || IsRedacted(id) || IsRedacted(account) || IsRedacted(region)) { redacted = true; continue; }
                expected.Add(new(account, region, id, type, fields));
            }
        }
        if (redacted) c.Warnings.Add("AWS baseline contains redacted identifiers or attributes; those entries/fields were excluded. Redacted baselines cannot establish complete drift coverage; export a private --full baseline for exact comparisons.");
        if (unsupported > 0) c.Warnings.Add("AWS baseline contains unsupported resource types; only EC2 instances, EBS volumes, security groups, VPCs, network interfaces and EIPs are compared.");
        if (terraform) c.Warnings.Add("Terraform baseline comparison reads JSON state only: supported EC2/EBS/SG/VPC/NIC/EIP IDs and fixed allowlisted attributes. State is recorded evidence, not a live Terraform plan. Secrets, outputs, provisioners, user data, tags, egress and peer-group SG rules are not read; live resources outside the state are reported only as untracked candidates.");
        var current = c.Resources.Where(r => ComparedFields.ContainsKey(r.Type)).ToArray();
        if (expected.Count == 0)
        {
            c.OperationSucceeded = false;
            c.Warnings.Add("AWS baseline contains no comparable resources; no baseline added/removed/changed assessment was performed.");
            return;
        }
        var applicable = expected.Where(e => (e.Account.Length == 0 || e.Account == c.Account) && (e.Region.Length == 0 || c.Regions.Contains(e.Region, StringComparer.Ordinal))).ToArray();
        if (applicable.Length != expected.Count) c.Warnings.Add("AWS baseline resources outside the authenticated account or selected regions were excluded; no absence claim is made for them.");
        if (applicable.Length == 0) c.OperationSucceeded = false;
        var matched = new HashSet<string>(StringComparer.Ordinal);
        foreach (var e in applicable)
        {
            var live = current.Where(r => r.Id == e.Id && r.Type == e.Type && (e.Region.Length == 0 || r.Region == e.Region)).ToArray();
            if (live.Length == 0)
            {
                var coverage = e.Region.Length > 0 ? new[] { e.Region } : c.Regions.ToArray();
                if (coverage.All(r => c.SuccessfulCalls.Contains(r + "|ec2 " + InventoryCommands[e.Type])))
                    BaselineChange(c, e.Id, e.Type, "Removed", [], "AWS_BASELINE_REMOVED", "Baseline resource is absent from the selected live inventory", "Verify scope, ownership and intended deletion against the approved baseline.");
                else c.Warnings.Add("AWS baseline absence could not be assessed because one or more required inventory API calls failed.");
                continue;
            }
            foreach (var actual in live)
            {
                matched.Add(actual.Region + "|" + actual.Type + "|" + actual.Id);
                var values = JsonSerializer.SerializeToElement(actual.Properties);
                var changed = e.Properties.Where(pair => PropertyIgnoreCase(values, pair.Key).ValueKind != JsonValueKind.Undefined && Canonical(pair.Value) != Canonical(PropertyIgnoreCase(values, pair.Key))).Select(pair => pair.Key).ToArray();
                if (changed.Length > 0) BaselineChange(c, actual.Id, actual.Type, "Changed", changed, "AWS_BASELINE_CHANGED", "Live resource differs from baseline attributes", "Review the listed attribute names against the approved baseline. Expected/actual values are deliberately excluded.");
            }
        }
        // When redaction hid baseline identities, apparent additions cannot be assessed safely.
        if (!redacted && applicable.Length > 0)
            foreach (var actual in current.Where(r => !matched.Contains(r.Region + "|" + r.Type + "|" + r.Id)))
                BaselineChange(c, actual.Id, actual.Type, "Added", [], "AWS_BASELINE_ADDED", terraform ? "Live resource is not tracked in the supplied Terraform state" : "Live resource is absent from the supplied inventory baseline", terraform ? "Review as an untracked candidate; the state may cover only part of the account. This alone does not prove unauthorized drift." : "Verify whether the resource is an approved addition and update the baseline if appropriate.", FindingSeverity.Info);
        c.Warnings.Add("AWS baseline comparisons cover selected regions and successfully collected allowlisted inventory fields only. Missing optional fields and unsupported resources do not establish conformance.");
    }

    private static void FindBaselineArrays(JsonElement value, List<JsonElement> arrays, int depth)
    {
        if (depth > 8) return;
        if (value.ValueKind == JsonValueKind.Array) { arrays.Add(value); return; }
        var resources = PropertyIgnoreCase(value, "resources");
        if (resources.ValueKind == JsonValueKind.Array) { arrays.Add(resources); return; }
        var data = PropertyIgnoreCase(value, "data");
        if (data.ValueKind == JsonValueKind.Object) FindBaselineArrays(data, arrays, depth + 1);
        var reports = PropertyIgnoreCase(value, "reports");
        foreach (var report in Elements(reports)) FindBaselineArrays(report, arrays, depth + 1);
        var cloud = PropertyIgnoreCase(value, "cloudEvidence");
        if (cloud.ValueKind == JsonValueKind.Object) FindBaselineArrays(cloud, arrays, depth + 1);
    }

    private static Dictionary<string, JsonElement> TerraformFields(string type, JsonElement attributes)
    {
        var result = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        void Map(string source, string target) { var value = PropertyIgnoreCase(attributes, source); if (value.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null)) result[target] = value.Clone(); }
        switch (type)
        {
            case "aws_instance":
                Map("instance_type", "Type"); Map("ami", "Image"); Map("subnet_id", "Subnet"); Map("private_ip", "PrivateIp"); Map("public_ip", "PublicIp"); Map("vpc_security_group_ids", "Groups");
                var metadata = Elements(PropertyIgnoreCase(attributes, "metadata_options")).FirstOrDefault();
                var tokens = PropertyIgnoreCase(metadata, "http_tokens"); if (tokens.ValueKind == JsonValueKind.String) result["HttpTokens"] = tokens.Clone();
                break;
            case "aws_ebs_volume": Map("size", "Size"); Map("encrypted", "Encrypted"); Map("type", "Type"); break;
            case "aws_security_group":
                Map("name", "Name"); Map("vpc_id", "Vpc");
                var ingress = PropertyIgnoreCase(attributes, "ingress");
                if (ingress.ValueKind == JsonValueKind.Array)
                    result["Ingress"] = JsonSerializer.SerializeToElement(Elements(ingress).Select(rule => new { Protocol = StringIgnoreCase(rule, "protocol"), From = PropertyIgnoreCase(rule, "from_port").Clone(), To = PropertyIgnoreCase(rule, "to_port").Clone(), IPv4 = Elements(PropertyIgnoreCase(rule, "cidr_blocks")).ToArray(), IPv6 = Elements(PropertyIgnoreCase(rule, "ipv6_cidr_blocks")).ToArray() }).ToArray());
                break;
            case "aws_vpc": Map("cidr_block", "Cidr"); Map("is_default", "Default"); break;
            case "aws_network_interface": Map("subnet_id", "Subnet"); Map("private_ip", "PrivateIp"); Map("security_groups", "Groups"); break;
            case "aws_eip": Map("public_ip", "PublicIp"); Map("instance", "Instance"); Map("network_interface", "Interface"); break;
        }
        return result;
    }

    private static void BaselineChange(Collection c, string id, string type, string change, IReadOnlyList<string> properties, string code, string title, string recommendation, FindingSeverity severity = FindingSeverity.Warning)
    {
        c.BaselineChanges.Add(new { Id = id, Type = type, Change = change, Properties = properties });
        c.Findings.Add(new(severity, code, title, $"AWS account {c.Account}, {type} {id}. Changed attributes: {string.Join(", ", properties)}.", recommendation));
    }
    private static JsonElement PropertyIgnoreCase(JsonElement element, string name) => element.ValueKind == JsonValueKind.Object ? element.EnumerateObject().FirstOrDefault(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Value : default;
    private static string StringIgnoreCase(JsonElement element, string name) { var value = PropertyIgnoreCase(element, name); return value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : ""; }
    private static bool IsRedacted(string value) => value.Contains("[redacted", StringComparison.OrdinalIgnoreCase);
    private static bool ContainsRedaction(JsonElement value) => value.ValueKind switch { JsonValueKind.String => IsRedacted(value.GetString() ?? ""), JsonValueKind.Array => value.EnumerateArray().Any(ContainsRedaction), JsonValueKind.Object => value.EnumerateObject().Any(p => ContainsRedaction(p.Value)), _ => false };
    private static string Canonical(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Object => "{" + string.Join(",", value.EnumerateObject().OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).Select(p => JsonSerializer.Serialize(p.Name.ToLowerInvariant()) + ":" + Canonical(p.Value))) + "}",
        JsonValueKind.Array => "[" + string.Join(",", value.EnumerateArray().Select(Canonical).OrderBy(p => p, StringComparer.Ordinal)) + "]",
        JsonValueKind.Number => value.TryGetDecimal(out var number) ? number.ToString(CultureInfo.InvariantCulture) : value.GetDouble().ToString("R", CultureInfo.InvariantCulture),
        JsonValueKind.Undefined or JsonValueKind.Null => "null", _ => value.GetRawText()
    };

    private static async Task Patches(Collection c, string region)
    {
        var managed = await c.Call("ssm", "describe-instance-information", region, "InstanceInformationList[].{Id:InstanceId,Ping:PingStatus,Platform:PlatformType,PlatformName:PlatformName,PlatformVersion:PlatformVersion,AgentVersion:AgentVersion,ResourceType:ResourceType,LastPing:LastPingDateTime,Association:AssociationStatus}");
        var nodes = Items(managed).Where(n => c.Option("resource").Length == 0 || String(n, "Id") == c.Option("resource")).ToArray();
        foreach (var n in nodes)
        {
            c.Add(region, String(n, "Id").StartsWith("mi-", StringComparison.Ordinal) ? "AWS::SSM::HybridManagedInstance" : "AWS::SSM::ManagedInstance", n);
            if (String(n, "Ping") != "Online") c.Find("AWS_SSM_NODE_OFFLINE", "SSM managed node is not online", n, "Id", "Check SSM agent health, connectivity and registration. Patch results can be stale.");
        }
        if (managed.HasValue && nodes.Length == 0) c.Warnings.Add($"AWS SSM has no matching managed nodes in {Label(region)}; patch/agent coverage is unavailable. Unmanaged hosts are not assessed.");
        foreach (var batch in nodes.Select(n => String(n, "Id")).Where(id => id.Length > 0).Chunk(50))
        {
            var args = new List<string> { "--instance-ids" }; args.AddRange(batch);
            var states = await c.Call("ssm", "describe-instance-patch-states", region, "InstancePatchStates[].{Id:InstanceId,Baseline:BaselineId,Operation:Operation,Started:OperationStartTime,Ended:OperationEndTime,Installed:InstalledCount,Missing:MissingCount,Failed:FailedCount,Rejected:InstalledRejectedCount,PendingReboot:InstalledPendingRebootCount,NotApplicable:NotApplicableCount}", args.ToArray());
            var returned = new HashSet<string>(StringComparer.Ordinal);
            foreach (var s in Items(states))
            {
                returned.Add(String(s, "Id")); c.Add(region, "AWS::SSM::PatchState", s);
                if (Number(s, "Missing") > 0 || Number(s, "Failed") > 0 || Number(s, "Rejected") > 0 || Number(s, "PendingReboot") > 0) c.Find("AWS_PATCH_NONCOMPLIANT", "SSM reports patch actions outstanding", s, "Id", "Review baseline, scan timestamp, missing/failed/rejected patches and pending reboot before scheduling maintenance.");
            }
            if (states.HasValue && batch.Any(id => !returned.Contains(id))) c.Warnings.Add($"AWS SSM patch state is missing for one or more managed nodes in {Label(region)}; compliance is unknown.");
        }
        c.Warnings.Add("SSM patch evidence reflects the latest recorded Scan/Install operation. No scan, Run Command, installation or hybrid activation is performed; absence of a result is not compliance.");
    }

    private static async Task Cost(Collection c, string region)
    {
        foreach (var v in Items(await c.Call("ec2", "describe-volumes", region, VolumeQuery)))
            if (String(v, "State") == "available" && Elements(Property(v, "Attachments")).Count == 0) { c.Add(region, "AWS::EC2::Volume", v); c.Find("AWS_ORPHAN_EBS", "EBS volume is unattached", v, "Id", "Confirm retention, recovery and ownership requirements before considering removal."); }
        foreach (var a in Items(await c.Call("ec2", "describe-addresses", region, "Addresses[].{Id:AllocationId,PublicIp:PublicIp,Association:AssociationId,Instance:InstanceId,Interface:NetworkInterfaceId}")))
            if (String(a, "Association").Length == 0 && String(a, "Instance").Length == 0 && String(a, "Interface").Length == 0) { c.Add(region, "AWS::EC2::EIP", a, "Id", "PublicIp"); c.Find("AWS_ORPHAN_EIP", "Elastic IP is unassociated", a, "PublicIp", "Confirm the address is not reserved for failover before considering release."); }
        var snapshots = await c.Call("ec2", "describe-snapshots", region, "Snapshots[].{Id:SnapshotId,Volume:VolumeId,Size:VolumeSize,Started:StartTime,Encrypted:Encrypted,State:State}", "--owner-ids", "self");
        foreach (var s in Items(snapshots))
            if (DateTimeOffset.TryParse(String(s, "Started"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var started) && started < DateTimeOffset.UtcNow.AddDays(-90)) { c.Add(region, "AWS::EC2::Snapshot", s); c.Find("AWS_OLD_SNAPSHOT", "EBS snapshot is older than 90 days", s, "Id", "Review backup retention, legal holds and AMI dependencies; age alone does not make a snapshot safe to delete."); }
        foreach (var i in await AddInstances(c, region))
            if (String(i, "State") == "running") await Metrics(c, region, String(i, "Id"), true);
        c.Warnings.Add("AWS cost results are candidates for review, not billing estimates. CPU alone cannot establish safe downsizing; memory, latency, burst credits, workload schedules and storage dependencies are not evaluated.");
    }

    private static async Task Metrics(Collection c, string region, string instanceId, bool detectUnderuse)
    {
        var points = await c.Call("cloudwatch", "get-metric-statistics", region, "Datapoints[].{Time:Timestamp,Average:Average,Maximum:Maximum,Samples:SampleCount}", "--namespace", "AWS/EC2", "--metric-name", "CPUUtilization", "--dimensions", $"Name=InstanceId,Value={instanceId}", "--statistics", "Average", "Maximum", "SampleCount", "--period", "86400", "--start-time", DateTimeOffset.UtcNow.AddDays(-14).ToString("O", CultureInfo.InvariantCulture), "--end-time", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        if (!points.HasValue) return;
        var samples = Items(points);
        var weight = samples.Sum(p => Number(p, "Samples"));
        var average = weight > 0 ? samples.Sum(p => Number(p, "Average") * Number(p, "Samples")) / weight : (double?)null;
        c.Resources.Add(new("aws", c.Account, Label(region), instanceId, "AWS::CloudWatch::CPUUtilization", instanceId, new { WindowDays = 14, DataPoints = samples.Select(p => Project(p)).ToArray(), AveragePercent = average }));
        if (samples.Count == 0) c.Warnings.Add($"AWS CloudWatch has no CPU data for {instanceId} in {Label(region)}; underuse cannot be assessed.");
        if (detectUnderuse && samples.Count >= 7 && average.HasValue && average.Value < 5 && samples.All(p => Number(p, "Maximum") < 20))
            c.Findings.Add(new(FindingSeverity.Info, "AWS_LOW_CPU_CANDIDATE", "EC2 has consistently low observed CPU", $"{instanceId}: sample-weighted CPU average {average.Value:F2}% over {samples.Count} daily datapoints in the last 14 days; observed daily maximum below 20%.", "Validate memory, I/O, latency, schedules and availability requirements before considering rightsizing."));
    }

    private sealed class Collection(ICloudCommandRunner commandRunner, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken)
    {
        public string Account { get; set; } = "unknown";
        public bool IdentityVerified { get; set; }
        public bool OperationSucceeded { get; set; } = true;
        public bool RequiresTargetResolution { get; set; }
        public bool TargetResolved { get; set; }
        public List<string> Regions { get; } = [];
        public List<Finding> Findings { get; } = [];
        public List<string> Warnings { get; } = [];
        public List<CloudResource> Resources { get; } = [];
        public List<object> BaselineChanges { get; } = [];
        public HashSet<string> RequiredCommands { get; } = new(StringComparer.Ordinal);
        public HashSet<string> SuccessfulCalls { get; } = new(StringComparer.Ordinal);
        public CancellationToken CancellationToken => cancellationToken;
        public string Option(string key, string fallback = "") => options.TryGetValue(key, out var value) ? value : fallback;
        public async Task<JsonElement?> Call(string service, string command, string? region, string query, params string[] extra)
        {
            if (!Commands.Contains(service + " " + command)) throw new InvalidOperationException("AWS command is outside the read-only allowlist.");
            var args = new List<string> { service, command, "--output", "json", "--no-cli-pager", "--query", query };
            if (Option("profile").Length > 0) { args.Add("--profile"); args.Add(Option("profile")); }
            if (!string.IsNullOrEmpty(region)) { args.Add("--region"); args.Add(region); }
            args.AddRange(extra);
            try
            {
                var result = await commandRunner.RunAsync("aws", args, cancellationToken);
                SuccessfulCalls.Add(Label(region ?? "") + "|" + service + " " + command);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception ex) when (ex is not OutOfMemoryException && ex is not StackOverflowException)
            {
                if (RequiredCommands.Contains(service + " " + command)) OperationSucceeded = false;
                // Native stderr can contain request material; never copy it to evidence.
                Warnings.Add($"AWS coverage unavailable: {service} {command} in {Label(region ?? "")} failed ({ex.GetType().Name}). Check CLI availability, credentials, service enablement and read permissions.");
                return null;
            }
        }
        public void Add(string region, string type, JsonElement value, string idKey = "Id", string nameKey = "Name")
        {
            var id = String(value, idKey); if (id.Length == 0) id = String(value, nameKey);
            Resources.Add(new("aws", Account, Label(region), id, type, String(value, nameKey), Project(value)));
        }
        public void Find(string code, string title, JsonElement evidence, string idKey, string recommendation, FindingSeverity severity = FindingSeverity.Warning) => Findings.Add(new(severity, code, title, $"AWS account {Account}, resource {String(evidence, idKey)}.", recommendation));
        public AnalysisReport Report(string operation) => new("aws." + operation, DateTimeOffset.UtcNow, Findings, new { Provider = "aws", Account, Regions, Resources, BaselineChanges, ReadOnly = true }, Warnings.Distinct(StringComparer.Ordinal).ToArray())
        {
            OperationSucceeded = IdentityVerified && OperationSucceeded && (!RequiresTargetResolution || TargetResolved) &&
                SuccessfulCalls.Any(call => !call.EndsWith("|sts get-caller-identity", StringComparison.Ordinal) && !call.EndsWith("|ec2 describe-regions", StringComparison.Ordinal))
        };
    }

    private static List<string> Split(string value) => value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.Ordinal).ToList();
    private static string Label(string region) => region.Length == 0 ? "profile-default" : region;
    private static JsonElement Property(JsonElement element, string name) => element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) ? value : default;
    private static string String(JsonElement element, string name) { var p = Property(element, name); return p.ValueKind is JsonValueKind.String ? p.GetString() ?? "" : p.ValueKind is JsonValueKind.Number ? p.GetRawText() : ""; }
    private static bool? Bool(JsonElement element, string name) { var p = Property(element, name); return p.ValueKind == JsonValueKind.True ? true : p.ValueKind == JsonValueKind.False ? false : null; }
    private static double Number(JsonElement element, string name) => Property(element, name).TryGetDoubleSafe();
    private static IReadOnlyList<JsonElement> Elements(JsonElement element) => element.ValueKind == JsonValueKind.Array ? element.EnumerateArray().ToArray() : [];
    private static IReadOnlyList<JsonElement> Items(JsonElement? element) => element.HasValue ? Elements(element.Value) : [];
    // Defense in depth after the CLI's JMESPath projection: unexpected fields from a wrapper/fake are excluded.
    private static readonly HashSet<string> SafeFields = new(StringComparer.Ordinal)
    {
        "Id", "Name", "Type", "Image", "State", "Vpc", "Subnet", "PrivateIp", "PublicIp", "Profile", "HttpTokens", "Groups", "LaunchTime", "Encrypted", "Size", "Attachments", "InstanceId", "Device", "Protocol", "From", "To", "IPv4", "IPv6", "Ingress", "Cidr", "Default", "Status", "Instance", "Interface", "Association", "Title", "Severity", "Workflow", "RecordState", "Resources", "Created", "Permission", "Group", "System", "AvailabilityZone", "Events", "Code", "Before", "After", "Updated", "Time", "Username", "LogicalId", "Drift", "Checked", "Differences", "Path", "Ping", "Platform", "PlatformName", "PlatformVersion", "AgentVersion", "ResourceType", "LastPing", "Baseline", "Operation", "Started", "Ended", "Installed", "Missing", "Failed", "Rejected", "PendingReboot", "NotApplicable", "Volume", "Average", "Maximum", "Samples", "Service", "Region", "Start", "End"
    };
    private static object? Project(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Object => value.EnumerateObject().Where(p => SafeFields.Contains(p.Name)).ToDictionary(p => p.Name, p => Project(p.Value), StringComparer.Ordinal),
        JsonValueKind.Array => value.EnumerateArray().Select(Project).ToArray(),
        JsonValueKind.String => value.GetString(), JsonValueKind.Number => value.TryGetInt64(out var n) ? n : value.GetDouble(),
        JsonValueKind.True => true, JsonValueKind.False => false, _ => null
    };
}

internal static class AwsJsonExtensions
{
    internal static double TryGetDoubleSafe(this JsonElement value) => value.ValueKind == JsonValueKind.Number && value.TryGetDouble(out var number) ? number : 0;
}
