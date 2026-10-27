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
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Posture, CloudOperation.Vm, CloudOperation.Bundle, CloudOperation.Metrics, CloudOperation.Scc, CloudOperation.Cost, CloudOperation.Services, CloudOperation.Patches, CloudOperation.Drift],
            ["compute.vm", "compute.disk", "network", "managed-service"], ["cloudasset.assets.searchAllResources", "compute.instances.list", "compute.firewalls.list"]),
        Descriptor("oci", "Oracle Cloud", "public-cloud", true,
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Posture, CloudOperation.Metrics], ["compute.vm", "network"], ["OCI inspect/read permissions in selected compartment"]),
        Descriptor("digitalocean", "DigitalOcean", "public-cloud", true,
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Posture, CloudOperation.Metrics], ["compute.vm", "network"], ["DigitalOcean read-only API token"]),
        Descriptor("hetzner", "Hetzner Cloud", "public-cloud", true,
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Posture, CloudOperation.Metrics], ["compute.vm", "network"], ["Hetzner Cloud read-only API token"]),
        Descriptor("cloudflare", "Cloudflare", "edge", true,
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Posture, CloudOperation.Metrics], ["edge.zone"], ["Cloudflare zone read permission"]),
        Descriptor("openstack", "OpenStack", "private-cloud", true,
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Posture, CloudOperation.Metrics], ["compute.vm", "network"], ["OpenStack reader in configured project"]),
        Descriptor("alibaba", "Alibaba Cloud", "public-cloud", true,
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Posture, CloudOperation.Metrics], ["compute.vm", "storage.disk"], ["ECS DescribeInstances and DescribeDisks"]),
        Descriptor("ibm", "IBM Cloud", "public-cloud", true,
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Metrics], ["service.instance"], ["IBM Resource Controller viewer in the configured account and resource group"]),
        Descriptor("scaleway", "Scaleway", "public-cloud", true,
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Metrics], ["compute.vm"], ["Scaleway Instance read permissions"]),
        Descriptor("kubernetes", "Kubernetes", "cluster", true,
            [CloudOperation.Inventory, CloudOperation.Health, CloudOperation.Metrics], ["cluster.workload", "cluster.service"],
            ["Explicit kubeconfig context and namespace allowlist; get/list workload metadata; optional Metrics Server read access"])
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
        "kubernetes" => new KubernetesProvider(runner),
        _ when AdditionalCloudProviders.Supports(providerId) => WithSupplementalMetrics(providerId, runner),
        _ => throw new ArgumentException("Unknown cloud provider. Use a registered lower-case provider ID.", nameof(providerId))
    };

    private static ICloudProvider WithSupplementalMetrics(string providerId, ICloudCommandRunner? runner)
    {
        var provider = AdditionalCloudProviders.Create(providerId, runner);
        return SupplementalCloudMetricsA.Supports(providerId) || SupplementalCloudMetricsB.Supports(providerId)
            ? new SupplementalMetricsProvider(provider, runner) : provider;
    }

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
                CloudOperation.Scc => (["security.finding"], ["resourcemanager.projects.get", "securitycenter.findings.list (ADC)"]),
                CloudOperation.Cost => (["billing.observed-export-rows"], ["bigquery.tables.get", "bigquery.tables.getData (ADC); preconfigured billing export"]),
                CloudOperation.Services => (["gke.cluster", "sql.instance", "run.service", "storage.bucket"], ["resourcemanager.projects.get", "Service-specific configuration list permissions for selected GCP services"]),
                CloudOperation.Patches => (["osconfig.patch-job.observation"], ["resourcemanager.projects.get", "osconfig.patchJobs.list (ADC); existing OS Config jobs"]),
                CloudOperation.Drift => (["inventory.baseline.comparison"], ["cloudasset.assets.searchAllResources; private normalized inventory baseline with matching scopes"]),
                _ => (["compute.vm.state", "compute.vm.cpu", "network.firewall"], ["compute.instances.list", "compute.firewalls.list", "monitoring.timeSeries.list (ADC)"])
            };
            (resourceTypes, permissions) = metadata;
        }
        else if (operation == CloudOperation.Metrics)
        {
            (string[] ResourceTypes, string[] Permissions) metricMetadata = id switch
            {
                "digitalocean" => (["compute.vm.cpu_seconds_total"], ["Project membership and Monitoring read access"]),
                "oci" => (["compute.vm.cpu"], ["OCI Monitoring read-metrics in the selected compartment"]),
                "cloudflare" => (["edge.http.requests", "edge.http.bytes"], ["Zone Read and Analytics Read for explicitly allowed account/zones"]),
                "openstack" => (["compute.vm.metric"], ["Gnocchi resource/metric read in the selected project"]),
                "alibaba" => (["compute.vm.cpu"], ["ECS DescribeInstances and CloudMonitor DescribeMetricList"]),
                "ibm" => (["monitoring.target.up"], ["Resource Controller viewer and read access to the selected Monitoring instance"]),
                "scaleway" => (["monitoring.target.up"], ["Cockpit data-source metadata and metrics read for the selected project/source"]),
                "kubernetes" => (["pod.cpu", "pod.memory"], ["get/list metrics.k8s.io pods in the allowed namespaces"]),
                _ => (["compute.vm.cpu"], permissions)
            };
            (resourceTypes, permissions) = metricMetadata;
        }
        else if (operation == CloudOperation.Posture && id == "cloudflare") resourceTypes = ["edge.zone.paused"];
        else if (operation == CloudOperation.Posture && id == "alibaba") resourceTypes = ["storage.disk.encryption"];
        else if (id is not ("azure" or "aws") && operation == CloudOperation.Health)
            resourceTypes = id == "cloudflare" ? ["edge.zone.state"] : id == "ibm" ? ["service.instance.state"] : id == "kubernetes" ? ["cluster.workload.state"] : ["compute.vm.state"];
        return new(operation, Array.AsReadOnly(resourceTypes), Array.AsReadOnly(permissions), experimental,
            operation == CloudOperation.Metrics || id == "gcp" && operation is CloudOperation.Health or CloudOperation.Bundle ? TimeSpan.FromSeconds(60) : null);
    }
}
