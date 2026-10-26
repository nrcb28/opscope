namespace Opscope.Cloud;

/// <summary>Closed provider registry. Registration never discovers credentials or enables a remote service.</summary>
public static class CloudProviderRegistry
{
    private static readonly IReadOnlyList<CloudAdapterDescriptor> Registered = Array.AsReadOnly(new[]
    {
        Descriptor("azure", "Microsoft Azure", "public-cloud", false,
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Posture, CloudOperation.Vm, CloudOperation.Bundle,
             CloudOperation.Drift, CloudOperation.Patches, CloudOperation.Cost, CloudOperation.Arc, CloudOperation.Metadata],
            ["compute.vm", "compute.disk", "network", "hybrid.machine"], ["Azure Reader; additional service read roles may be required"]),
        Descriptor("aws", "Amazon Web Services", "public-cloud", false,
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Posture, CloudOperation.Instance, CloudOperation.Bundle,
             CloudOperation.Drift, CloudOperation.Patches, CloudOperation.Cost, CloudOperation.Metadata],
            ["compute.vm", "compute.disk", "network", "object-storage"], ["AWS service-specific read permissions"]),
        Descriptor("gcp", "Google Cloud", "public-cloud", true,
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Posture, CloudOperation.Vm, CloudOperation.Bundle, CloudOperation.Metrics],
            ["compute.vm", "compute.disk", "network", "managed-service"], ["cloudasset.assets.searchAllResources", "compute.instances.list", "compute.firewalls.list"]),
        Descriptor("oci", "Oracle Cloud", "public-cloud", true,
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Posture], ["compute.vm", "network"], ["OCI inspect/read permissions in selected compartment"]),
        Descriptor("digitalocean", "DigitalOcean", "public-cloud", true,
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Posture, CloudOperation.Metrics], ["compute.vm", "network"], ["DigitalOcean read-only API token"]),
        Descriptor("hetzner", "Hetzner Cloud", "public-cloud", true,
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Posture, CloudOperation.Metrics], ["compute.vm", "network"], ["Hetzner Cloud read-only API token"]),
        Descriptor("cloudflare", "Cloudflare", "edge", true,
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Posture], ["edge.zone"], ["Cloudflare zone read permission"]),
        Descriptor("openstack", "OpenStack", "private-cloud", true,
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Posture], ["compute.vm", "network"], ["OpenStack reader in configured project"]),
        Descriptor("alibaba", "Alibaba Cloud", "public-cloud", true,
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Posture], ["compute.vm", "storage.disk"], ["ECS DescribeInstances and DescribeDisks"]),
        Descriptor("ibm", "IBM Cloud", "public-cloud", true,
            [CloudOperation.Inventory, CloudOperation.Health], ["service.instance"], ["IBM Resource Controller viewer in the configured account and resource group"]),
        Descriptor("scaleway", "Scaleway", "public-cloud", true,
            [CloudOperation.Inventory, CloudOperation.Health], ["compute.vm"], ["Scaleway Instance read permissions"])
    });

    public static IReadOnlyList<CloudAdapterDescriptor> Descriptors => Registered;

    public static bool IsKnownProvider(string? providerId) =>
        Registered.Any(item => string.Equals(item.ProviderId, providerId, StringComparison.Ordinal));

    public static CloudAdapterDescriptor GetDescriptor(string providerId) =>
        Registered.FirstOrDefault(item => string.Equals(item.ProviderId, providerId, StringComparison.Ordinal))
        ?? throw new ArgumentException("Unknown cloud provider. Use a registered lower-case provider ID.", nameof(providerId));

    public static bool SupportsOperation(string providerId, string operation) =>
        IsKnownProvider(providerId) && Enum.TryParse<CloudOperation>(operation, true, out var parsed) &&
        GetDescriptor(providerId).Capabilities.Any(item => item.Operation == parsed) &&
        string.Equals(parsed.ToString(), operation, StringComparison.OrdinalIgnoreCase);

    public static ICloudProvider Create(string providerId, ICloudCommandRunner? runner = null) => providerId switch
    {
        "azure" => new AzureProvider(runner ?? new TrustedCloudCommandRunner()),
        "aws" => new AwsProvider(runner ?? new TrustedCloudCommandRunner()),
        "gcp" => new GcpProvider(runner ?? new TrustedCloudCommandRunner()),
        _ when AdditionalCloudProviders.Supports(providerId) => AdditionalCloudProviders.Create(providerId, runner),
        _ => throw new ArgumentException("Unknown cloud provider. Use a registered lower-case provider ID.", nameof(providerId))
    };

    private static CloudAdapterDescriptor Descriptor(string id, string name, string category, bool experimental,
        CloudOperation[] operations, string[] resourceTypes, string[] permissions) => new(id, name, category, "1",
            Array.AsReadOnly(operations.Select(operation => Capability(id, operation, resourceTypes, permissions, experimental)).ToArray()));

    private static CloudCapability Capability(string id, CloudOperation operation, string[] resourceTypes, string[] permissions, bool experimental)
    {
        if (id == "gcp")
        {
            (string[] ResourceTypes, string[] Permissions) metadata = operation switch
            {
                CloudOperation.Inventory => (["compute.vm", "compute.disk", "network", "managed-service"], ["cloudasset.assets.searchAllResources"]),
                CloudOperation.Posture => (["compute.vm", "network.firewall"], ["compute.instances.list", "compute.firewalls.list"]),
                CloudOperation.Metrics => (["compute.vm.cpu"], ["monitoring.timeSeries.list (ADC)"]),
                CloudOperation.Health => (["compute.vm.state", "compute.vm.cpu"], ["compute.instances.list", "monitoring.timeSeries.list (ADC)"]),
                CloudOperation.Vm => (["compute.vm.state"], ["compute.instances.list"]),
                _ => (["compute.vm.state", "compute.vm.cpu", "network.firewall"], ["compute.instances.list", "compute.firewalls.list", "monitoring.timeSeries.list (ADC)"])
            };
            (resourceTypes, permissions) = metadata;
        }
        else if (operation == CloudOperation.Metrics) resourceTypes = id == "digitalocean" ? ["compute.vm.cpu_seconds_total"] : ["compute.vm.cpu"];
        else if (operation == CloudOperation.Posture && id == "cloudflare") resourceTypes = ["edge.zone.paused"];
        else if (operation == CloudOperation.Posture && id == "alibaba") resourceTypes = ["storage.disk.encryption"];
        else if (id is not ("azure" or "aws") && operation == CloudOperation.Health)
            resourceTypes = id == "cloudflare" ? ["edge.zone.state"] : id == "ibm" ? ["service.instance.state"] : ["compute.vm.state"];
        return new(operation, Array.AsReadOnly(resourceTypes), Array.AsReadOnly(permissions), experimental,
            operation == CloudOperation.Metrics || id == "gcp" && operation is CloudOperation.Health or CloudOperation.Bundle ? TimeSpan.FromSeconds(60) : null);
    }
}
