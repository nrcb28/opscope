using System.Net;
using System.Text.Json;

namespace Opscope.Cloud;

/// <summary>Identity-only Azure IMDS access. Calling this method is an explicit opt-in.</summary>
public static class AzureMetadata
{
    private static readonly Uri IdentityEndpoint = new("http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01");
    private const int MaximumBytes = 64 * 1024;

    public static async Task<AzureInstanceIdentity> ReadIdentityAsync(CancellationToken cancellationToken = default)
    {
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(1),
            AutomaticDecompression = DecompressionMethods.None,
            MaxResponseHeadersLength = 8
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(2) };
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(2));
        using var request = new HttpRequestMessage(HttpMethod.Get, IdentityEndpoint);
        request.Headers.Add("Metadata", "true");
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
        if (response.StatusCode != HttpStatusCode.OK) throw new HttpRequestException("Azure identity metadata was unavailable.");
        if (response.Content.Headers.ContentLength > MaximumBytes) throw new InvalidDataException("Azure identity metadata exceeded its size limit.");
        await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token);
        using var bytes = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, deadline.Token);
            if (read == 0) break;
            if (bytes.Length + read > MaximumBytes) throw new InvalidDataException("Azure identity metadata exceeded its size limit.");
            await bytes.WriteAsync(buffer.AsMemory(0, read), deadline.Token);
        }
        using var doc = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions { MaxDepth = 16 });
        var root = doc.RootElement;
        string Read(string key)
        {
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty(key, out var value) || value.ValueKind != JsonValueKind.String) return "";
            return new string((value.GetString() ?? "").Take(1024).Where(c => !char.IsControl(c)).ToArray());
        }
        var subscription = Read("subscriptionId");
        var vmId = Read("vmId");
        if (!Guid.TryParse(subscription, out _) || !Guid.TryParse(vmId, out _)) throw new InvalidDataException("Azure metadata did not identify a VM.");
        return new(subscription, Read("resourceGroupName"), Read("resourceId"), vmId, Read("name"), Read("location"), Read("vmSize"), Read("osType"), Read("zone"), Read("azEnvironment"));
    }
}

public sealed record AzureInstanceIdentity(string SubscriptionId, string ResourceGroup, string ResourceId, string VmId, string Name, string Location, string VmSize, string OsType, string Zone, string Environment);
