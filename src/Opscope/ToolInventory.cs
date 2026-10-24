using System.Diagnostics;

namespace Opscope;

internal static class ToolInventory
{
    private sealed record Definition(string Name, string Purpose, string Role);

    public static ToolingPosture Collect()
    {
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
        var path = CommandRunner.ResolveExecutable(definition.Name);
        if (!Path.IsPathFullyQualified(path) || !File.Exists(path))
            return new ToolInfo(definition.Name, definition.Purpose, definition.Role, false, null, "missing", null);

        try
        {
            if (!CommandRunner.IsTrustedExecutablePath(definition.Name, path))
                return new ToolInfo(definition.Name, definition.Purpose, definition.Role, true, path, "untrusted-path", null);

            var attributes = File.GetAttributes(path);
            if (attributes.HasFlag(FileAttributes.ReparsePoint))
                return new ToolInfo(definition.Name, definition.Purpose, definition.Role, true, path, "reparse-point", null);

            if (OperatingSystem.IsLinux())
            {
                var mode = File.GetUnixFileMode(path);
                if (mode.HasFlag(UnixFileMode.GroupWrite) || mode.HasFlag(UnixFileMode.OtherWrite))
                    return new ToolInfo(definition.Name, definition.Purpose, definition.Role, true, path, "writable-by-non-owner", null);

                var executeBits = UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;
                if ((mode & executeBits) == 0)
                    return new ToolInfo(definition.Name, definition.Purpose, definition.Role, true, path, "not-executable", null);
            }

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
}

