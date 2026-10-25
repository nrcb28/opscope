using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Opscope;

public sealed record CustodyOptions(string? EncryptPublicKeyPath = null, string? SignPrivateKeyPath = null, IReadOnlyDictionary<string, AnalysisReport>? AdditionalReports = null);
public sealed record BundleVerification(bool IsValid, bool IsSigned, bool SignatureVerified, bool IsEncrypted, IReadOnlyList<string> Errors);
public sealed record CustodyEntry(string Name, long Size, string Sha256);
public sealed record CustodyManifest(string Format, DateTimeOffset CreatedAtUtc, bool Redacted, string? SignatureAlgorithm, string? SignerPublicKeySha256, IReadOnlyList<CustodyEntry> Files);

public static class CustodyBundle
{
    // EN: Hashes establish content integrity; signer identity requires verification against an independently trusted key.
    // ES: Los hashes comprueban integridad; la identidad del firmante exige verificar con una clave confiable obtenida por otro canal.
    private const int MaximumArchiveBytes = 32 * 1024 * 1024;
    private const int MaximumFileBytes = 48 * 1024 * 1024;
    private const string Format = "opscope-custody/v1";
    private const string EnvelopeFormat = "opscope-encrypted/v1";
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, PropertyNameCaseInsensitive = false, WriteIndented = true, MaxDepth = 32, UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow };
    private static readonly HashSet<string> AllowedReports = new(StringComparer.Ordinal) { "evidence", "cloud", "policy", "ioc", "timeline", "security" };
    private sealed record EncryptedEnvelope(string Format, string KeyAlgorithm, string EncryptionAlgorithm, string EncryptedKey, string Nonce, string Tag, string Ciphertext);
    public static async Task<string> WriteAsync(string path, Snapshot snapshot, CustodyOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new();
        using var signingKey = options.SignPrivateKeyPath is null ? null : ReadKey(options.SignPrivateKeyPath);
        using var encryptionKey = options.EncryptPublicKeyPath is null ? null : ReadKey(options.EncryptPublicKeyPath);
        var safe = Reporter.RedactForOutput(snapshot);
        var files = new SortedDictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["snapshot.json"] = Encoding.UTF8.GetBytes(Reporter.ToJson(safe)),
            ["findings.json"] = JsonSerializer.SerializeToUtf8Bytes(safe.Findings, Json),
            ["README.txt"] = Encoding.UTF8.GetBytes("Opscope sealed offline bundle\nFormat: " + Format + "\nRedacted: true\nThe manifest authenticates entry hashes only when its RSA-PSS signature is verified against a separately trusted public key. SHA-256 checksums alone provide integrity, not signer authentication. No keys are included. Collection is read-only.\n")
        };
        if (options.AdditionalReports is not null)
        {
            if (options.AdditionalReports.Count > AllowedReports.Count) throw new InvalidDataException("Too many additional reports.");
            foreach (var report in options.AdditionalReports)
            {
                if (!AllowedReports.Contains(report.Key)) throw new InvalidDataException("Additional report name is not allowlisted.");
                files.Add(report.Key + ".json", Encoding.UTF8.GetBytes(ReportExporter.Export(report.Value, "json")));
            }
        }
        if (files.Values.Sum(bytes => (long)bytes.Length) > MaximumArchiveBytes) throw new InvalidDataException("Bundle content exceeds 32 MiB.");
        var manifest = new CustodyManifest(Format, DateTimeOffset.UtcNow, true, signingKey is null ? null : "RSA-PSS-SHA256", signingKey is null ? null : Hash(signingKey.ExportSubjectPublicKeyInfo()), files.Select(f => new CustodyEntry(f.Key, f.Value.Length, Hash(f.Value))).ToArray());
        var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, Json);
        files.Add("manifest.json", manifestBytes);
        if (signingKey is not null) files.Add("manifest.sig", signingKey.SignData(manifestBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        byte[] archiveBytes;
        using (var memory = new MemoryStream())
        {
            using (var zip = new ZipArchive(memory, ZipArchiveMode.Create, true))
                foreach (var file in files)
                {
                    var entry = zip.CreateEntry(file.Key, CompressionLevel.Fastest);
                    await using var target = entry.Open(); await target.WriteAsync(file.Value, cancellationToken);
                }
            archiveBytes = memory.ToArray();
        }
        if (archiveBytes.Length > MaximumArchiveBytes) throw new InvalidDataException("Bundle archive exceeds 32 MiB.");
        if (encryptionKey is not null) archiveBytes = Encrypt(archiveBytes, encryptionKey);
        await PrivateFiles.WriteAsync(path, archiveBytes, cancellationToken);
        await Reporter.WriteTextAtomicallyAsync(path + ".sha256", Hash(archiveBytes) + "\n", cancellationToken);
        return Path.GetFullPath(path);
    }
    public static async Task<BundleVerification> VerifyAsync(string path, string? verificationPublicKeyPath = null, string? decryptPrivateKeyPath = null, CancellationToken cancellationToken = default)
    {
        var errors = new List<string>(); var signed = false; var signatureVerified = false; var encrypted = false;
        try
        {
            var bytes = await ReadBoundedAsync(path, MaximumFileBytes, cancellationToken);
            if (!File.Exists(path + ".sha256")) errors.Add("Detached SHA-256 file is missing.");
            else
            {
                var detached = Encoding.UTF8.GetString(await ReadBoundedAsync(path + ".sha256", 256, cancellationToken)).Trim();
                if (detached.Length != 64 || !detached.All(Uri.IsHexDigit) || !Hash(bytes).Equals(detached, StringComparison.OrdinalIgnoreCase)) errors.Add("Detached file SHA-256 does not match.");
            }
            if (bytes.Length == 0) throw new InvalidDataException("Bundle is empty.");
            if (bytes[0] != (byte)'P')
            {
                encrypted = true;
                if (decryptPrivateKeyPath is null) throw new InvalidDataException("Encrypted bundle requires an explicit decryption private key.");
                using var key = ReadKey(decryptPrivateKeyPath); bytes = Decrypt(bytes, key);
            }
            if (bytes.Length > MaximumArchiveBytes) throw new InvalidDataException("Archive exceeds 32 MiB.");
            using var memory = new MemoryStream(bytes, false); using var archive = new ZipArchive(memory, ZipArchiveMode.Read);
            if (archive.Entries.Count is < 4 or > 12) throw new InvalidDataException("Unexpected archive entry count.");
            var entries = new Dictionary<string, byte[]>(StringComparer.Ordinal); long total = 0;
            foreach (var entry in archive.Entries)
            {
                if (!IsAllowedName(entry.FullName) || entry.Name != entry.FullName || !entries.TryAdd(entry.FullName, [])) throw new InvalidDataException("Archive contains a duplicate or unsafe entry name.");
                if (entry.Length < 0 || entry.Length > MaximumArchiveBytes || (total += entry.Length) > MaximumArchiveBytes) throw new InvalidDataException("Archive decompressed content exceeds 32 MiB.");
                await using var source = entry.Open(); using var target = new MemoryStream(); var buffer = new byte[8192]; int read;
                while ((read = await source.ReadAsync(buffer, cancellationToken)) > 0) { if (target.Length + read > entry.Length || target.Length + read > MaximumArchiveBytes) throw new InvalidDataException("Archive entry exceeds declared length."); await target.WriteAsync(buffer.AsMemory(0, read), cancellationToken); }
                if (target.Length != entry.Length) throw new InvalidDataException("Archive entry length does not match.");
                entries[entry.FullName] = target.ToArray();
            }
            if (!entries.TryGetValue("manifest.json", out var manifestBytes) || manifestBytes.Length > 128 * 1024) throw new InvalidDataException("Bounded manifest is missing.");
            var manifest = JsonSerializer.Deserialize<CustodyManifest>(manifestBytes, Json) ?? throw new InvalidDataException("Manifest is invalid.");
            if (manifest.Format != Format || !manifest.Redacted || manifest.Files is null || manifest.Files.Count is < 3 or > 9) throw new InvalidDataException("Unsupported custody manifest.");
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var entry in manifest.Files)
            {
                if (entry is null || !IsContentName(entry.Name) || !names.Add(entry.Name) || entry.Size < 0 || entry.Size > MaximumArchiveBytes || entry.Sha256 is null || entry.Sha256.Length != 64 || !entry.Sha256.All(Uri.IsHexDigit)) throw new InvalidDataException("Manifest contains invalid or duplicate content entries.");
                if (!entries.TryGetValue(entry.Name, out var content) || content.LongLength != entry.Size || !Hash(content).Equals(entry.Sha256, StringComparison.OrdinalIgnoreCase)) errors.Add("Manifest content hash or size mismatch: " + entry.Name);
            }
            if (!names.Contains("snapshot.json") || !names.Contains("findings.json") || !names.Contains("README.txt")) errors.Add("Required bundle content is missing from the manifest.");
            if (entries.Keys.Any(name => IsContentName(name) && !names.Contains(name))) errors.Add("Archive contains content absent from the manifest.");
            signed = manifest.SignatureAlgorithm is not null || entries.ContainsKey("manifest.sig");
            if (signed)
            {
                if (manifest.SignatureAlgorithm != "RSA-PSS-SHA256" || !entries.TryGetValue("manifest.sig", out var signature)) errors.Add("Signature metadata is missing or unsupported.");
                else if (verificationPublicKeyPath is null) errors.Add("Signed bundle requires a separately trusted verification public key.");
                else
                {
                    using var key = ReadKey(verificationPublicKeyPath);
                    signatureVerified = key.VerifyData(manifestBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                    if (!signatureVerified || !Hash(key.ExportSubjectPublicKeyInfo()).Equals(manifest.SignerPublicKeySha256, StringComparison.OrdinalIgnoreCase)) { signatureVerified = false; errors.Add("RSA-PSS signature verification failed."); }
                }
            }
            else if (verificationPublicKeyPath is not null) errors.Add("A verification key was supplied but the bundle is unsigned.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException or CryptographicException or JsonException or FormatException or ArgumentException or NotSupportedException)
        {
            // Do not expose key contents or file paths from cryptography/parser exception text.
            errors.Add(exception is InvalidDataException ? exception.Message : "Bundle verification failed: invalid content, inaccessible file, or invalid cryptographic key.");
        }
        return new(errors.Count == 0, signed, signatureVerified, encrypted, errors);
    }
    public static async Task DecryptAsync(string inputPath, string outputPath, string privateKeyPath, CancellationToken cancellationToken = default)
    {
        using var key = ReadKey(privateKeyPath);
        var encrypted = await ReadBoundedAsync(inputPath, MaximumFileBytes, cancellationToken);
        var decrypted = Decrypt(encrypted, key);
        await PrivateFiles.WriteAsync(outputPath, decrypted, cancellationToken);
        await Reporter.WriteTextAtomicallyAsync(outputPath + ".sha256", Hash(decrypted) + "\n", cancellationToken);
    }
    private static bool IsContentName(string name) => name is "snapshot.json" or "findings.json" or "README.txt" || AllowedReports.Any(r => name == r + ".json");
    private static bool IsAllowedName(string name) => IsContentName(name) || name is "manifest.json" or "manifest.sig";
    private static string Hash(byte[] content) => Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
    private static RSA ReadKey(string path)
    {
        var info = new FileInfo(path); if (info.Length is < 32 or > 64 * 1024) throw new InvalidDataException("RSA PEM key exceeds bounds or is empty.");
        using var source = SnapshotIO.OpenRegularRead(Path.GetFullPath(path));
        using var content = new MemoryStream(); var buffer = new byte[4096]; int read;
        while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
        {
            if (content.Length + read > 64 * 1024) throw new InvalidDataException("RSA PEM key exceeds bounds.");
            content.Write(buffer, 0, read);
        }
        var pem = Encoding.UTF8.GetString(content.ToArray());
        var rsa = RSA.Create();
        try { rsa.ImportFromPem(pem); if (rsa.KeySize is < 2048 or > 8192) throw new InvalidDataException("RSA key size must be between 2048 and 8192 bits."); return rsa; }
        catch { rsa.Dispose(); throw; }
    }
    private static byte[] Encrypt(byte[] plaintext, RSA publicKey)
    {
        var key = RandomNumberGenerator.GetBytes(32); var nonce = RandomNumberGenerator.GetBytes(12); var tag = new byte[16]; var ciphertext = new byte[plaintext.Length];
        try
        {
            using var aes = new AesGcm(key, 16); aes.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes(EnvelopeFormat));
            return JsonSerializer.SerializeToUtf8Bytes(new EncryptedEnvelope(EnvelopeFormat, "RSA-OAEP-SHA256", "AES-256-GCM", Convert.ToBase64String(publicKey.Encrypt(key, RSAEncryptionPadding.OaepSHA256)), Convert.ToBase64String(nonce), Convert.ToBase64String(tag), Convert.ToBase64String(ciphertext)), Json);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
    private static byte[] Decrypt(byte[] bytes, RSA privateKey)
    {
        var envelope = JsonSerializer.Deserialize<EncryptedEnvelope>(bytes, Json) ?? throw new InvalidDataException("Encrypted envelope is invalid.");
        if (envelope.Format != EnvelopeFormat || envelope.KeyAlgorithm != "RSA-OAEP-SHA256" || envelope.EncryptionAlgorithm != "AES-256-GCM" || envelope.EncryptedKey is null || envelope.Nonce is null || envelope.Tag is null || envelope.Ciphertext is null) throw new InvalidDataException("Unsupported encrypted envelope.");
        var nonce = Convert.FromBase64String(envelope.Nonce); var tag = Convert.FromBase64String(envelope.Tag); var ciphertext = Convert.FromBase64String(envelope.Ciphertext); var encryptedKey = Convert.FromBase64String(envelope.EncryptedKey);
        if (nonce.Length != 12 || tag.Length != 16 || ciphertext.Length > MaximumArchiveBytes || encryptedKey.Length > 1024) throw new InvalidDataException("Encrypted payload parameters exceed bounds.");
        var key = privateKey.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);
        try
        {
            if (key.Length != 32) throw new InvalidDataException("Invalid AES-256 key length.");
            var plaintext = new byte[ciphertext.Length]; using var aes = new AesGcm(key, 16); aes.Decrypt(nonce, ciphertext, tag, plaintext, Encoding.UTF8.GetBytes(EnvelopeFormat)); return plaintext;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
    private static async Task<byte[]> ReadBoundedAsync(string path, int maximum, CancellationToken ct)
    {
        await using var file = SnapshotIO.OpenRegularRead(Path.GetFullPath(path));
        if (file.Length > maximum) throw new InvalidDataException("Input file exceeds its size limit.");
        using var target = new MemoryStream(); var buffer = new byte[8192]; int read;
        while ((read = await file.ReadAsync(buffer, ct)) > 0) { if (target.Length + read > maximum) throw new InvalidDataException("Input file exceeds its size limit."); await target.WriteAsync(buffer.AsMemory(0, read), ct); }
        return target.ToArray();
    }
}
