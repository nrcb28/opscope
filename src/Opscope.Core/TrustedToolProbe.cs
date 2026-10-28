namespace Opscope;

/// <summary>Reports trusted CLI availability without launching a process or exposing an installation path.</summary>
public static class TrustedToolProbe
{
    private static readonly HashSet<string> CloudTools = new(StringComparer.Ordinal)
        { "az", "aws", "gcloud", "oci", "openstack", "aliyun", "kubectl" };

    public static string Inspect(string tool)
    {
        if (!CloudTools.Contains(tool)) return "unknown";
        var executable = tool == "az" && OperatingSystem.IsWindows() ? "azure-python" : tool;
        try
        {
            var path = CommandRunner.ResolveExecutable(executable);
            if (!File.Exists(path)) return "missing";
            return CommandRunner.IsTrustedExecutablePath(executable, path) ? "available" : "untrusted";
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or System.Security.SecurityException)
        { return "unknown"; }
    }
}
