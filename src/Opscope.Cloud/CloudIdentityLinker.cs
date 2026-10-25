using System.Text.Json;

namespace Opscope.Cloud;

public static class CloudIdentityLinker
{
    public static bool Matches(AnalysisReport report, object? identity)
    {
        ArgumentNullException.ThrowIfNull(report);
        if (!report.OperationSucceeded || identity is not (AwsInstanceIdentity or AzureInstanceIdentity)) return false;
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(report.Data));
        var remaining = 100000;
        return VisitData(document.RootElement, identity, 0, ref remaining);
    }

    private static bool VisitData(JsonElement node, object identity, int depth, ref int remaining)
    {
        if (depth > 32 || --remaining < 0 || node.ValueKind != JsonValueKind.Object) return false;
        foreach (var property in node.EnumerateObject())
        {
            if (--remaining < 0) return false;
            // Only normalized resources and successful profile reports establish
            // linkage. Arbitrary extension/evidence objects may contain IDs too.
            if (property.Name.Equals("Resources", StringComparison.OrdinalIgnoreCase) && property.Value.ValueKind == JsonValueKind.Array)
            {
                foreach (var resource in property.Value.EnumerateArray())
                {
                    if (--remaining < 0) return false;
                    if (ResourceMatches(resource, identity)) return true;
                }
            }
            else if (property.Name.Equals("Reports", StringComparison.OrdinalIgnoreCase) && property.Value.ValueKind == JsonValueKind.Array)
            {
                foreach (var report in property.Value.EnumerateArray())
                {
                    if (--remaining < 0) return false;
                    var success = Property(report, "OperationSucceeded");
                    if (success.ValueKind == JsonValueKind.True && VisitData(Property(report, "Data"), identity, depth + 1, ref remaining)) return true;
                }
            }
        }
        return false;
    }

    private static bool ResourceMatches(JsonElement node, object identity)
    {
        if (node.ValueKind != JsonValueKind.Object) return false;
        var id = Value(node, "Id");
        var account = Value(node, "Account");
        var region = Value(node, "Region");
        return identity switch
        {
            AwsInstanceIdentity aws => Value(node, "Provider") == "aws" && Value(node, "Type") == "AWS::EC2::Instance" &&
                id == aws.InstanceId && account == aws.AccountId && region == aws.Region,
            AzureInstanceIdentity azure => Value(node, "Provider") == "azure" && Value(node, "Type").Equals("Microsoft.Compute/virtualMachines", StringComparison.OrdinalIgnoreCase) &&
                id.Equals(azure.ResourceId, StringComparison.OrdinalIgnoreCase) && account.Equals(azure.SubscriptionId, StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    private static JsonElement Property(JsonElement obj, string name)
    {
        if (obj.ValueKind != JsonValueKind.Object) return default;
        foreach (var property in obj.EnumerateObject())
            if (property.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) return property.Value;
        return default;
    }

    private static string Value(JsonElement obj, string name)
    {
        var property = Property(obj, name);
        return property.ValueKind == JsonValueKind.String ? property.GetString() ?? "" : "";
    }
}
