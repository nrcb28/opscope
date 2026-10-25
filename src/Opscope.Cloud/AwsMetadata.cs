using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Opscope.Cloud;

/// <summary>Non-credential EC2 identity data obtained from the fixed IMDSv2 identity endpoint.</summary>
public sealed record AwsInstanceIdentity(string AccountId, string Region, string InstanceId, string? Architecture);

/// <summary>
/// Reads EC2 instance identity only after explicit caller opt-in. Tokens are used in memory for one
/// request and never returned. This client never reads the IAM role or credentials metadata paths.
/// </summary>
public sealed class AwsMetadataClient
{
    private static readonly Uri TokenUri = new("http://169.254.169.254/latest/api/token");
    private static readonly Uri IdentityUri = new("http://169.254.169.254/latest/dynamic/instance-identity/document");
    private readonly HttpMessageHandler? testHandler;

    public AwsMetadataClient() { }

    // An assembly-local seam permits deterministic tests without exposing endpoint configuration.
    internal AwsMetadataClient(HttpMessageHandler handler) => testHandler = handler ?? throw new ArgumentNullException(nameof(handler));

    /// <summary>
    /// Returns null without making a request when <paramref name="optIn"/> is false. When opted in,
    /// unreachable metadata, rejected IMDSv2 requests, oversized responses and invalid identity data
    /// fail explicitly; there is no fallback to IMDSv1.
    /// </summary>
    public async Task<AwsInstanceIdentity?> ReadAsync(bool optIn, CancellationToken cancellationToken = default)
    {
        if (!optIn) return null;
        cancellationToken.ThrowIfCancellationRequested();

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(2));
        using var client = new HttpClient(testHandler ?? new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromMilliseconds(700),
            MaxResponseHeadersLength = 8,
            MaxConnectionsPerServer = 1
        }, disposeHandler: testHandler is null)
        {
            Timeout = Timeout.InfiniteTimeSpan,
            DefaultRequestVersion = HttpVersion.Version11,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact
        };

        using var tokenRequest = new HttpRequestMessage(HttpMethod.Put, TokenUri);
        tokenRequest.Headers.Add("X-aws-ec2-metadata-token-ttl-seconds", "60");
        using var tokenResponse = await client.SendAsync(tokenRequest, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
        tokenResponse.EnsureSuccessStatusCode();
        var tokenBytes = await ReadBoundedAsync(tokenResponse.Content, 1024, deadline.Token).ConfigureAwait(false);
        if (tokenBytes.Length == 0 || tokenBytes.Any(value => value < 0x21 || value > 0x7e))
            throw new InvalidDataException("EC2 IMDSv2 returned an invalid session token.");
        var token = Encoding.ASCII.GetString(tokenBytes);

        using var identityRequest = new HttpRequestMessage(HttpMethod.Get, IdentityUri);
        identityRequest.Headers.Add("X-aws-ec2-metadata-token", token);
        using var identityResponse = await client.SendAsync(identityRequest, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
        identityResponse.EnsureSuccessStatusCode();
        var documentBytes = await ReadBoundedAsync(identityResponse.Content, 16 * 1024, deadline.Token).ConfigureAwait(false);

        using var document = JsonDocument.Parse(documentBytes, new JsonDocumentOptions { MaxDepth = 16 });
        var root = document.RootElement;
        var account = RequiredString(root, "accountId");
        var region = RequiredString(root, "region");
        var instance = RequiredString(root, "instanceId");
        if (!Regex.IsMatch(account, "^[0-9]{12}$", RegexOptions.CultureInvariant) ||
            region.Length > 64 || !Regex.IsMatch(region, "^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$", RegexOptions.CultureInvariant) ||
            !Regex.IsMatch(instance, "^i-[0-9a-f]{8,32}$", RegexOptions.CultureInvariant))
            throw new InvalidDataException("EC2 IMDSv2 returned invalid identity fields.");

        string? architecture = null;
        if (root.TryGetProperty("architecture", out var architectureElement) && architectureElement.ValueKind == JsonValueKind.String)
        {
            architecture = architectureElement.GetString();
            if (architecture is null || architecture.Length > 32 ||
                !Regex.IsMatch(architecture, "^[A-Za-z0-9_.-]+$", RegexOptions.CultureInvariant))
                throw new InvalidDataException("EC2 IMDSv2 returned invalid architecture metadata.");
        }
        return new AwsInstanceIdentity(account, region, instance, architecture);
    }

    private static string RequiredString(JsonElement root, string name)
    {
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(value.GetString()))
            throw new InvalidDataException("EC2 IMDSv2 identity document is incomplete.");
        return value.GetString()!;
    }

    private static async Task<byte[]> ReadBoundedAsync(HttpContent content, int limit, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is long length && length > limit)
            throw new InvalidDataException("EC2 IMDSv2 response exceeds the permitted size.");
        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = new byte[Math.Min(4096, limit + 1)];
        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, limit - (int)output.Length + 1)), cancellationToken).ConfigureAwait(false);
            if (read == 0) return output.ToArray();
            if (output.Length + read > limit)
                throw new InvalidDataException("EC2 IMDSv2 response exceeds the permitted size.");
            output.Write(buffer, 0, read);
        }
    }
}
