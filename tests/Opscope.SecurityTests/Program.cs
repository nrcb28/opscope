using System.Text.Json;
using Opscope;

var privateFields = new Dictionary<string, object>
{
    ["projectId"] = "private-gcp-project", ["projectNumber"] = 123456789012L,
    ["compartmentId"] = "ocid1.compartment.oc1..private-scope", ["tenancyId"] = "private-oci-tenancy",
    ["cloudName"] = "private-openstack-profile", ["zoneId"] = "private-cloudflare-zone",
    ["dropletId"] = 987654321, ["serviceAccountKey"] = new { private_key = "private-key-material" },
    ["userData"] = "boot script with private-root-password", ["cloudInit"] = "private-cloud-init-content",
    ["context"] = "private-cluster-context", ["namespaces"] = new[] { "private-namespace" },
    ["billingTable"] = "private-billing-export", ["cockpitSource"] = "private-monitoring-source"
};
var messages = "Projects private-gcp-project and 123456789012, droplet 987654321, tenancy private-oci-tenancy";
var report = new AnalysisReport("cloud/read", DateTimeOffset.UtcNow,
    [new(FindingSeverity.Warning, "CLOUD_PARTIAL", "Read incomplete", messages, "Review configured scope and permissions.")],
    new { scope = privateFields, metric = new { unit = "percent", periodSeconds = 60, value = 0.0 }, coverage = new { state = "partial", enumeratedResources = 2 } },
    ["Selected private-openstack-profile could not be read."]);
var json = ReportSecurity.Serialize(report);
foreach (var forbidden in new[] { "private-gcp-project", "123456789012", "ocid1.compartment", "private-oci-tenancy", "private-openstack-profile", "private-cloudflare-zone", "987654321", "private-key-material", "private-root-password", "private-cloud-init-content", "private-cluster-context", "private-namespace", "private-billing-export", "private-monitoring-source" })
    if (json.Contains(forbidden, StringComparison.Ordinal)) throw new InvalidOperationException("Cloud export leaked a private field: " + forbidden);
using var document = JsonDocument.Parse(json);
var data = document.RootElement.GetProperty("data");
if (data.GetProperty("metric").GetProperty("value").GetDouble() != 0 || data.GetProperty("metric").GetProperty("periodSeconds").GetInt32() != 60 ||
    data.GetProperty("coverage").GetProperty("enumeratedResources").GetInt32() != 2 || data.GetProperty("coverage").GetProperty("state").GetString() != "partial")
    throw new InvalidOperationException("Privacy must preserve operational counts, zero measurements, units and coverage states.");
Console.WriteLine("PASS: multicloud scope, numeric identity, boot data and cross-field finding redaction; real zero and coverage preserved.");
