using System.Diagnostics;

namespace Opscope;

internal static class ToolInventory
{
    private sealed record Definition(string Name, string Purpose, string Role);

    public static ToolingPosture Collect()
    {
        // Keep the platform matrix explicit so PATH hijacking cannot change what we inspect or execute.
        // Mantenemos explícita la matriz por plataforma para que PATH no pueda alterar lo inspeccionado o ejecutado.
        var definitions = OperatingSystem.IsWindows()
            ? new[]
            {
                new Definition("netstat", "TCP and UDP listener inventory", "core"),
                new Definition("netsh", "Windows firewall posture", "core"),
                new Definition("sc.exe", "Windows service inventory", "core")
            }
            : OperatingSystem.IsLinux()
                ? new[]
                {
                    new Definition("ss", "TCP and UDP listener inventory", "core"),
                    new Definition("systemctl", "systemd service inventory", "core"),
                    new Definition("ip", "Linux address and route enrichment", "enrichment"),
                    new Definition("ufw", "UFW firewall posture", "enrichment"),
                    new Definition("firewall-cmd", "firewalld firewall posture", "enrichment"),
                    new Definition("nft", "nftables firewall posture", "enrichment")
                }
                : Array.Empty<Definition>();

        return new ToolingPosture(definitions.Select(Inspect).ToArray());
    }

    private static ToolInfo Inspect(Definition definition)
    {
        // Missing optional tools reduce coverage; present but unsafe tools are security findings.
        // Las herramientas opcionales ausentes reducen cobertura; las presentes pero inseguras son hallazgos.
        var path = CommandRunner.ResolveExecutable(definition.Name);
        if (!Path.IsPathFullyQualified(path) || !File.Exists(path))
            return new ToolInfo(definition.Name, definition.Purpose, definition.Role, false, null, "missing", null);

        try
        {
            if (!CommandRunner.TryValidateExecutablePath(definition.Name, path, out var failure))
                return new ToolInfo(definition.Name, definition.Purpose, definition.Role, true, path, MapFailureToSecurity(failure), null);

            var version = TryGetVersion(path);
            return new ToolInfo(definition.Name, definition.Purpose, definition.Role, true, path, "secure", version);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException or ArgumentException)
        {
            return new ToolInfo(definition.Name, definition.Purpose, definition.Role, true, path, $"inspection-error:{ex.GetType().Name}", null);
        }
    }

    private static string? TryGetVersion(string path)
    {
        try
        {
            var version = FileVersionInfo.GetVersionInfo(path).FileVersion;
            return string.IsNullOrWhiteSpace(version) ? null : version;
        }
        catch
        {
            return null;
        }
    }

    private static string MapFailureToSecurity(string failure) =>
        failure.Contains("writable", StringComparison.OrdinalIgnoreCase) ? "writable-by-non-owner" :
        failure.Contains("reparse", StringComparison.OrdinalIgnoreCase) ? "reparse-point" :
        failure.Contains("executable", StringComparison.OrdinalIgnoreCase) ? "not-executable" :
        failure.Contains("owner", StringComparison.OrdinalIgnoreCase) ? "owner-unverified" :
        failure.Contains("ACL", StringComparison.OrdinalIgnoreCase) ? "acl-unverified" :
        "untrusted-path";
}

