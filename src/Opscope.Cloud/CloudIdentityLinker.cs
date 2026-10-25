using System.Text.Json;

namespace Opscope.Cloud;

public static class CloudIdentityLinker
{
    public static bool Matches(AnalysisReport report, object? identity)
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(report.Data));
        var remaining = 100000;
        return Visit(document.RootElement, identity, 0, ref remaining);
    }

    private static bool Visit(JsonElement node, object? identity, int depth, ref int remaining)
    {
        if (depth > 32 || --remaining < 0) return false;
        if (node.ValueKind == JsonValueKind.Object)
        {
            var id = Value(node, "Id");
            var account = Value(node, "Account");
            var region = Value(node, "Region");
            if (identity is AwsInstanceIdentity aws && Value(node, "Provider") == "aws" && Value(node, "Type") == "AWS::EC2::Instance" &&
                id == aws.InstanceId && account == aws.AccountId && region == aws.Region) return true;
            if (identity is AzureInstanceIdentity azure && Value(node, "Provider") == "azure" &&
                id.Equals(azure.ResourceId, StringComparison.OrdinalIgnoreCase) && account.Equals(azure.SubscriptionId, StringComparison.OrdinalIgnoreCase)) return true;
            foreach (var property in node.EnumerateObject()) if (Visit(property.Value, identity, depth + 1, ref remaining)) return true;
        }
        else if (node.ValueKind == JsonValueKind.Array)
            foreach (var item in node.EnumerateArray()) if (Visit(item, identity, depth + 1, ref remaining)) return true;
        return false;
    }

    private static string Value(JsonElement obj, string name)
    {
        foreach (var property in obj.EnumerateObject())
            if (property.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && property.Value.ValueKind == JsonValueKind.String) return property.Value.GetString() ?? "";
        return "";
    }
}
