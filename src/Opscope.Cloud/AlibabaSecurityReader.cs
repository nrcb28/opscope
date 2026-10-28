using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text;
using System.Text.RegularExpressions;

namespace Opscope.Cloud;

/// <summary>Reads scoped disk encryption and ingress rule configuration with fixed CLI projections.</summary>
public sealed class AlibabaSecurityProvider(ICloudCommandRunner? runner = null) : ICloudProvider
{
    private const int MaxReads = 60, MaxGroups = 20, MaxRows = 1000, MaxPages = 10, MaxBytes = 8 * 1024 * 1024;
    private readonly ICloudCommandRunner reader = runner ?? new AlibabaSecurityCommandRunner();
    public string Name => "alibaba";

    public async Task<AnalysisReport> CollectAsync(string operation, IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        var now = DateTimeOffset.UtcNow;
        var findings = new List<Finding>();
        var resources = new List<CloudResource>();
        var warnings = new List<string>();
        var diskState = "not_requested"; var groupState = "not_requested";
        int? diskCount = null, unencrypted = null, unknownEncryption = null;
        int? groupCount = null, ruleCount = null, world = null, admin = null, shadowed = null, unknownRules = null;
        var reads = 0; var bytes = 0; var rows = 0; var throttled = false; var budgetExhausted = false;
        string Get(string key) => options.TryGetValue(key, out var value) ? value.Trim() : "";
        var account = Get("account"); var region = Get("region"); var profile = Get("profile");
        if (operation != "posture") return Result("unsupported", false, "This reader supports the registered posture operation only.");
        var selected = Get("security-groups").Length == 0 ? [] : Get("security-groups").Split(',', StringSplitOptions.TrimEntries);
        if (!AlibabaSecurityCommandRunner.Account(account) || !AlibabaSecurityCommandRunner.Region(region) || !AlibabaSecurityCommandRunner.Profile(profile) ||
            selected.Length > MaxGroups || selected.Any(id => !AlibabaSecurityCommandRunner.Group(id)) || selected.Distinct(StringComparer.Ordinal).Count() != selected.Length)
            return Result("not_configured", false, "Select an explicit numeric Alibaba account, region, existing profile and at most twenty distinct security-group IDs. No provider read was sent.");
        if (Get("resource").Length != 0)
            return Result("not_configured", false, "This configuration reader accepts account/region and optional --security-groups, not an arbitrary resource filter. No provider read was sent.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            var identity = await Read(["identity", account, region, profile]);
            if (Text(identity, "AccountId") != account)
                return Result("permission_denied", false, "The existing Alibaba CLI identity did not match the selected account. No resource reads were sent.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error) when (Failure(error))
        { return Result(State(error), false, "The Alibaba identity read was unavailable. Configure the existing CLI identity outside Opscope; provider error text is omitted."); }

        await Disks();
        if (!throttled && !budgetExhausted) await Groups();
        var states = new[] { diskState, groupState };
        var complete = states.All(state => state is "complete" or "no_data");
        var useful = resources.Count > 0 || states.Any(state => state is "complete" or "no_data");
        var state = complete ? resources.Count == 0 ? "no_data" : "complete" : useful ? "partial" : states.FirstOrDefault(value => value != "not_requested") ?? "failed";
        return Result(state, complete);

        async Task<JsonElement> Read(string[] arguments)
        {
            if (budgetExhausted || ++reads > MaxReads) { budgetExhausted = true; throw new AlibabaSecurityQueryException("partial"); }
            deadline.Token.ThrowIfCancellationRequested();
            var response = await reader.RunAsync("alibaba-security", arguments, deadline.Token);
            if (response.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Invalid projected response.");
            var size = Encoding.UTF8.GetByteCount(response.GetRawText());
            if (size > 4 * 1024 * 1024 || bytes > MaxBytes - size) { budgetExhausted = true; throw new AlibabaSecurityQueryException("partial"); }
            bytes += size;
            return response;
        }

        async Task Disks()
        {
            diskState = "complete";
            var ids = new HashSet<string>(StringComparer.Ordinal);
            int? expected = null;
            var consumed = 0;
            try
            {
                for (var page = 1; page <= MaxPages; page++)
                {
                    var result = await Read(["disks", account, region, profile, page.ToString(CultureInfo.InvariantCulture)]);
                    var items = Array(Property(result, "Disks"), "Disk");
                    var total = Pagination(result, page, items.Length, 100);
                    if (expected is not null && expected != total) throw new InvalidDataException("Changed projected pagination.");
                    expected = total;
                    consumed += items.Length;
                    if (consumed > total) throw new InvalidDataException("Inconsistent projected row count.");
                    diskCount ??= 0; unencrypted ??= 0; unknownEncryption ??= 0;
                    foreach (var disk in items)
                    {
                        if (rows >= MaxRows || resources.Count >= MaxRows) { diskState = "partial"; break; }
                        rows++;
                        var id = Text(disk, "DiskId");
                        if (!AlibabaSecurityCommandRunner.Disk(id) || Text(disk, "RegionId") != region || !ids.Add(id)) { diskState = "partial"; continue; }
                        diskCount++;
                        bool? encrypted = Property(disk, "Encrypted").ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => null };
                        if (encrypted is null) { unknownEncryption++; diskState = "partial"; }
                        if (encrypted == false)
                        {
                            unencrypted++;
                            findings.Add(new(FindingSeverity.Warning, "ALIBABA_DISK_UNENCRYPTED", "Disk encryption is disabled in the observed configuration", id + ": Encrypted=false was observed in the selected account and region.", "Review the disk's encryption requirements and existing configuration before planning changes. Opscope does not modify the disk."));
                        }
                        resources.Add(new("alibaba", account, region, id, "storage.disk", "", new { encrypted }));
                    }
                    if (diskState == "partial" && rows >= MaxRows) break;
                    if (consumed >= total) break;
                    if (items.Length != 100 || page == MaxPages) { diskState = "partial"; break; }
                }
                if (diskCount != expected) diskState = "partial";
                if (diskCount == 0 && diskState == "complete") diskState = "no_data";
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception error) when (Failure(error)) { diskState = diskCount > 0 ? "partial" : State(error); throttled = State(error) == "rate_limited"; Warn(); }
        }

        async Task Groups()
        {
            groupState = "complete";
            var ids = new HashSet<string>(StringComparer.Ordinal);
            var groups = new List<string>();
            int? expected = null;
            var consumed = 0;
            try
            {
                for (var page = 1; page <= MaxPages; page++)
                {
                    var response = await Read(["groups", account, region, profile, page.ToString(CultureInfo.InvariantCulture), JsonSerializer.Serialize(selected)]);
                    if (Text(response, "RegionId") != region) throw new AlibabaSecurityQueryException("permission_denied");
                    var items = Array(Property(response, "SecurityGroups"), "SecurityGroup");
                    var total = Pagination(response, page, items.Length, MaxGroups);
                    if (expected is not null && expected != total) throw new InvalidDataException("Changed projected pagination.");
                    expected = total;
                    consumed += items.Length;
                    if (consumed > total) throw new InvalidDataException("Inconsistent projected row count.");
                    foreach (var item in items)
                    {
                        var id = Text(item, "SecurityGroupId");
                        if (!AlibabaSecurityCommandRunner.Group(id) || !ids.Add(id) || selected.Length > 0 && !selected.Contains(id, StringComparer.Ordinal))
                        { groupState = "partial"; continue; }
                        if (groups.Count >= MaxGroups) { groupState = "partial"; break; }
                        groups.Add(id);
                    }
                    if (groups.Count >= MaxGroups && consumed < total) { groupState = "partial"; break; }
                    if (consumed >= total) break;
                    if (items.Length != MaxGroups || page == MaxPages) { groupState = "partial"; break; }
                }
                if (groups.Count != expected) groupState = "partial";
                if (selected.Any(id => !ids.Contains(id))) groupState = "partial";
                if (groups.Count == 0 && groupState == "complete") { groupCount = 0; ruleCount = 0; world = 0; admin = 0; shadowed = 0; unknownRules = 0; }
                foreach (var id in groups)
                {
                    if (throttled || budgetExhausted || rows >= MaxRows) { groupState = "partial"; break; }
                    await Rules(id);
                }
                if (groupCount > 0 && groupState != "complete") groupState = "partial";
                if (groups.Count == 0 && groupState == "complete") groupState = "no_data";
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception error) when (Failure(error)) { groupState = groupCount > 0 ? "partial" : State(error); throttled = State(error) == "rate_limited"; Warn(); }
        }

        async Task Rules(string id)
        {
            var rules = new List<Rule>(); var seen = new HashSet<string>(StringComparer.Ordinal); var cursor = "";
            var complete = true; var observed = false; var count = 0; var unknown = 0;
            try
            {
                for (var page = 1; page <= MaxPages; page++)
                {
                    var response = await Read(["rules", account, region, profile, id, cursor]);
                    if (Text(response, "RegionId") != region || Text(response, "SecurityGroupId") != id) throw new AlibabaSecurityQueryException("permission_denied");
                    var next = Cursor(response);
                    if (next.Length > 0 && (!AlibabaSecurityCommandRunner.Opaque(next) || !seen.Add(next))) throw new AlibabaSecurityQueryException("partial");
                    var values = Array(Property(response, "Permissions"), "Permission");
                    if (values.Length > 100) throw new AlibabaSecurityQueryException("partial");
                    observed = true;
                    foreach (var value in values)
                    {
                        if (rows >= MaxRows) { complete = false; break; }
                        rows++; count++;
                        var rule = ParseRule(value);
                        if (rule is null) unknown++;
                        else { rules.Add(rule); if (rule.Priority is null) unknown++; }
                    }
                    cursor = next;
                    if (cursor.Length == 0) break;
                    if (rows >= MaxRows || page == MaxPages) { complete = false; break; }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception error) when (Failure(error)) { complete = false; groupState = observed || groupCount > 0 ? "partial" : State(error); throttled = State(error) == "rate_limited"; Warn(); }
            if (!observed) return;
            groupCount ??= 0; ruleCount ??= 0; world ??= 0; admin ??= 0; shadowed ??= 0; unknownRules ??= 0;
            groupCount++; ruleCount += count; unknownRules += unknown;
            var allows = rules.Where(rule => rule.Accept && rule.Families != 0).ToArray();
            var administrative = allows.Where(rule => rule.Administrative).ToArray();
            var uncertain = administrative.Where(rule => !complete || unknown != 0 || rule.Priority is null || Shadowed(rule, rules)).ToArray();
            world += allows.Length; admin += administrative.Length; shadowed += uncertain.Length;
            if (!complete || unknown != 0) groupState = "partial";
            foreach (var rule in administrative)
                findings.Add(new(uncertain.Contains(rule) ? FindingSeverity.Info : FindingSeverity.Warning, "ALIBABA_GLOBAL_ADMIN_INGRESS_RULE", "A global administrative ingress allow rule was observed", id + ": an observed global ingress allow configuration covers TCP port 22 or 3389. " + (uncertain.Contains(rule) ? "Priority, deny interactions or incomplete evidence prevent a stronger assessment." : "No covering higher-priority global deny was observed in these selected rules."), "Review the configured rules, priorities, attachments and intended source ranges. Rule configuration alone does not establish effective network reachability; Opscope performs no connection probe or change."));
            if (resources.Count >= MaxRows) { groupState = "partial"; return; }
            resources.Add(new("alibaba", account, region, id, "network.securityGroup", "", new { rulesRead = count, worldIngressAllowRules = allows.Length, administrativeIngressAllowRules = administrative.Length, possiblyShadowedAdminAllowRules = uncertain.Length, unknownRules = unknown, rulePagesComplete = complete }));
        }

        void Warn() => warnings.Add("A selected Alibaba configuration read was unavailable or exceeded a bound. Verify existing CLI credentials, --cli-query support, scope and read permissions outside Opscope. Provider error text is omitted.");
        AnalysisReport Result(string state, bool succeeded, string? warning = null)
        {
            if (warning is not null) warnings.Add(warning);
            warnings.Add("Configuration observations cover selected disk encryption and security-group ingress rules only. Empty or denied reads do not prove absence, current compliance or application health. Rule attachments, effective reachability, guest encryption and account IAM are outside this assessment; no resource or credential was changed.");
            if (state == "partial") warnings.Add("Configuration coverage is partial because one or more fields, sources, scopes or read/page/row/byte/time bounds were incomplete.");
            return new("cloud.alibaba.posture", now, findings, new
            {
                provider = "alibaba", operation = "posture", resources,
                scope = new { accounts = new[] { account }, region, profile },
                configurationEvidence = new { source = "aliyun-fixed-projections", checks = new object[]
                {
                    new { check = "disks", state = diskState, observedAtUtc = now, observations = new { disksRead = diskCount, unencryptedDisks = unencrypted, unknownEncryption, assessment = "configuration-only" } },
                    new { check = "security-groups", state = groupState, observedAtUtc = now, observations = new { groupsRead = groupCount, rulesRead = ruleCount, worldIngressAllowRules = world, administrativeIngressAllowRules = admin, possiblyShadowedAdminAllowRules = shadowed, unknownRules, assessment = "configuration-only" } }
                } },
                coverage = new { state, observedAtUtc = now, enumeratedResources = resources.Count, expectedScopes = 1, completedScopes = succeeded ? 1 : 0, warnings = warnings.Distinct(StringComparer.Ordinal).ToArray() }
            }, warnings.Distinct(StringComparer.Ordinal).ToArray()) { OperationSucceeded = succeeded };
        }
    }

    private sealed record Rule(bool Accept, int Families, bool Administrative, string Protocol, int Start, int End, int? Priority);
    private static Rule? ParseRule(JsonElement value)
    {
        if (Text(value, "Direction").ToLowerInvariant() != "ingress") return null;
        var policy = Text(value, "Policy").ToLowerInvariant(); var protocol = Text(value, "IpProtocol").ToLowerInvariant();
        if (policy is not ("accept" or "drop") || protocol is not ("tcp" or "udp" or "icmp" or "icmpv6" or "gre" or "all")) return null;
        var range = Text(value, "PortRange").Split('/');
        if (range.Length != 2 || !int.TryParse(range[0], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var start) || !int.TryParse(range[1], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var end)) return null;
        if (start == -1 && end == -1) { start = 0; end = 65535; }
        else if (start < 0 || end > 65535 || start > end) return null;
        var ipv4 = Text(value, "SourceCidrIp"); var ipv6 = Text(value, "Ipv6SourceCidrIp");
        if (!Cidr(ipv4, false) || !Cidr(ipv6, true) || ipv4.Length == 0 && ipv6.Length == 0) return null;
        var families = (ipv4 == "0.0.0.0/0" ? 1 : 0) | (ipv6 == "::/0" ? 2 : 0);
        var priorityText = Text(value, "Priority");
        if (Property(value, "Priority").ValueKind == JsonValueKind.Number) priorityText = Property(value, "Priority").GetRawText();
        int? priority = int.TryParse(priorityText, NumberStyles.None, CultureInfo.InvariantCulture, out var number) && number is >= 1 and <= 100 ? number : null;
        return new(policy == "accept", families, protocol is "tcp" or "all" && (start <= 22 && end >= 22 || start <= 3389 && end >= 3389), protocol, start, end, priority);
    }
    private static bool Shadowed(Rule allow, List<Rule> rules) => rules.Any(deny => !deny.Accept && deny.Priority <= allow.Priority &&
        (deny.Families & allow.Families) != 0 && deny.Protocol is "tcp" or "all" &&
        (Covers(allow, 22) && Covers(deny, 22) || Covers(allow, 3389) && Covers(deny, 3389)));
    private static bool Covers(Rule rule, int port) => rule.Start <= port && rule.End >= port;
    private static bool Cidr(string value, bool ipv6)
    {
        if (value.Length == 0) return true;
        var parts = value.Split('/');
        return parts.Length == 2 && IPAddress.TryParse(parts[0], out var address) && (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) == ipv6 && int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix) && prefix >= 0 && prefix <= (ipv6 ? 128 : 32);
    }
    private static int Pagination(JsonElement value, int page, int rows, int size)
    {
        if (!Property(value, "TotalCount").TryGetInt32(out var total) || total < 0 || !Property(value, "PageNumber").TryGetInt32(out var returnedPage) || returnedPage != page || !Property(value, "PageSize").TryGetInt32(out var returnedSize) || returnedSize != size || rows > size || total < rows)
            throw new InvalidDataException("Invalid projected pagination.");
        if (Cursor(value).Length != 0) throw new InvalidDataException("Unexpected token pagination.");
        return total;
    }
    private static JsonElement Property(JsonElement value, string name) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var found) ? found : default;
    private static string Text(JsonElement value, string name) => Property(value, name) is { ValueKind: JsonValueKind.String } text ? text.GetString() ?? "" : "";
    private static JsonElement[] Array(JsonElement value, string name) => Property(value, name) is { ValueKind: JsonValueKind.Array } array ? array.EnumerateArray().ToArray() : throw new InvalidDataException("Missing projected array.");
    private static string Cursor(JsonElement value) => Property(value, "NextToken").ValueKind is JsonValueKind.Undefined or JsonValueKind.Null ? "" : Property(value, "NextToken").ValueKind == JsonValueKind.String ? Text(value, "NextToken") : throw new InvalidDataException("Invalid projected cursor.");
    private static bool Failure(Exception error) => error is AlibabaSecurityQueryException or AdditionalCloudQueryException or IOException or InvalidDataException or InvalidOperationException or ArgumentException or JsonException or OperationCanceledException or System.ComponentModel.Win32Exception;
    private static string State(Exception error) => error is AlibabaSecurityQueryException classified ? classified.State : error is AdditionalCloudQueryException legacy ? legacy.State : error is OperationCanceledException ? "timed_out" : "failed";
}

/// <summary>Only literal read operations and exact cli-query projections can reach Aliyun CLI.</summary>
public sealed class AlibabaSecurityCommandRunner : ICloudCommandRunner
{
    internal const string IdentityProjection = "{AccountId:AccountId}";
    internal const string GroupProjection = "{RegionId:RegionId,TotalCount:TotalCount,PageNumber:PageNumber,PageSize:PageSize,NextToken:NextToken,SecurityGroups:{SecurityGroup:SecurityGroups.SecurityGroup[].{SecurityGroupId:SecurityGroupId}}}";
    internal const string RuleProjection = "{RegionId:RegionId,SecurityGroupId:SecurityGroupId,NextToken:NextToken,Permissions:{Permission:Permissions.Permission[].{IpProtocol:IpProtocol,PortRange:PortRange,SourceCidrIp:SourceCidrIp,Ipv6SourceCidrIp:Ipv6SourceCidrIp,Policy:Policy,Direction:Direction,Priority:Priority}}}";
    internal const string DiskProjection = "{TotalCount:TotalCount,PageNumber:PageNumber,PageSize:PageSize,Disks:{Disk:Disks.Disk[].{DiskId:DiskId,RegionId:RegionId,Encrypted:Encrypted}}}";
    public async Task<JsonElement> RunAsync(string tool, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        if (tool != "alibaba-security") throw new InvalidOperationException("Unsupported configuration reader.");
        var command = Prepare(arguments);
        var result = await CommandRunner.RunAsync("aliyun", command, TimeSpan.FromSeconds(15), 4 * 1024 * 1024, cancellationToken);
        if (result.TimedOut || result.OutputTruncated) throw new AlibabaSecurityQueryException("partial");
        if (result.ExitCode != 0) throw new AlibabaSecurityQueryException(Classify(result.StandardError + "\n" + result.StandardOutput));
        using var document = JsonDocument.Parse(result.StandardOutput, new JsonDocumentOptions { MaxDepth = 32 });
        return document.RootElement.Clone();
    }
    internal static IReadOnlyList<string> Prepare(IReadOnlyList<string> input)
    {
        if (input.Count is < 4 or > 6 || input.Any(value => value is null || value.Length > 4096 || value.Any(char.IsControl)) || !Account(input[1]) || !Region(input[2]) || !Profile(input[3])) throw new InvalidOperationException("Invalid scoped configuration read.");
        var action = input[0]; var args = new List<string>(); string query;
        if (action == "identity" && input.Count == 4) { args.AddRange(["sts", "GetCallerIdentity"]); query = IdentityProjection; }
        else if (action is "groups" or "disks" && input.Count == (action == "groups" ? 6 : 5) && int.TryParse(input[4], NumberStyles.None, CultureInfo.InvariantCulture, out var page) && page is >= 1 and <= 10)
        {
            args.AddRange(["ecs", action == "groups" ? "DescribeSecurityGroups" : "DescribeDisks", "--RegionId", input[2], "--PageSize", action == "groups" ? "20" : "100", "--PageNumber", input[4]]);
            query = action == "groups" ? GroupProjection : DiskProjection;
            if (action == "groups")
            {
                using var document = JsonDocument.Parse(input[5]);
                if (document.RootElement.ValueKind != JsonValueKind.Array || document.RootElement.GetArrayLength() > 20 || document.RootElement.EnumerateArray().Any(value => value.ValueKind != JsonValueKind.String || !Group(value.GetString() ?? ""))) throw new InvalidOperationException("Invalid selected security groups.");
                var values = document.RootElement.EnumerateArray().Select(value => value.GetString()!).ToArray();
                if (values.Distinct(StringComparer.Ordinal).Count() != values.Length) throw new InvalidOperationException("Duplicate selected security groups.");
                if (values.Length > 0) args.AddRange(["--SecurityGroupIds", input[5]]);
            }
        }
        else if (action == "rules" && input.Count == 6 && Group(input[4]) && (input[5].Length == 0 || Opaque(input[5])))
        {
            args.AddRange(["ecs", "DescribeSecurityGroupAttribute", "--RegionId", input[2], "--SecurityGroupId", input[4], "--Direction", "ingress", "--MaxResults", "100"]);
            if (input[5].Length > 0) args.AddRange(["--NextToken", input[5]]);
            query = RuleProjection;
        }
        else throw new InvalidOperationException("Configuration operation is outside the closed read allowlist.");
        if (input[3].Length != 0) args.AddRange(["--profile", input[3]]);
        args.AddRange(["--cli-query", query]);
        return args;
    }
    internal static bool Account(string value) => Regex.IsMatch(value, "\\A[0-9]{1,32}\\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    internal static bool Region(string value) => Regex.IsMatch(value, "\\A[a-z]{2,10}(?:-[a-z0-9]{1,16}){1,3}\\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    internal static bool Profile(string value) => value.Length == 0 || Regex.IsMatch(value, "\\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    internal static bool Group(string value) => Regex.IsMatch(value, "\\Asg-[A-Za-z0-9]{1,64}\\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    internal static bool Disk(string value) => Regex.IsMatch(value, "\\Ad-[A-Za-z0-9]{1,64}\\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    internal static bool Opaque(string value) => value.Length is > 0 and <= 1024 && !value.StartsWith('-') && !value.StartsWith('@') && !value.Contains("://", StringComparison.Ordinal) && !value.Any(char.IsControl);
    internal static string Classify(string error) => error.Contains("Throttling", StringComparison.OrdinalIgnoreCase) || error.Contains("TooManyRequests", StringComparison.OrdinalIgnoreCase) ? "rate_limited" :
        new[] { "Forbidden", "AccessDenied", "NoPermission", "InvalidAccessKeyId" }.Any(code => error.Contains(code, StringComparison.OrdinalIgnoreCase)) ? "permission_denied" : "failed";
}

internal sealed class AlibabaSecurityQueryException(string state) : IOException("The fixed configuration read was unavailable.")
{
    public string State { get; } = state;
}
