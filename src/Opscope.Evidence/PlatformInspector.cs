using System.Globalization;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Opscope.Evidence;

public static class PlatformInspector
{
    // EN: Container markers are limited evidence; never export environment values or read cluster credentials.
    // ES: Los marcadores de contenedor son evidencia limitada; no se exportan valores de entorno ni se leen credenciales del clúster.
    private static readonly Regex PageSize = new(@"page size of ([0-9]+) bytes", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly Regex IdleCpu = new(@"CPU usage:.*?([0-9.]+)% idle", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly string[] ContainerEnvironmentNames = ["KUBERNETES_SERVICE_HOST", "container"];

    public static async Task<AnalysisReport> CollectAsync(Snapshot snapshot, CancellationToken cancellationToken = default)
    {
        var warnings = new List<string>();
        var inventory = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["platform"] = snapshot.Host.Platform,
            ["architecture"] = snapshot.Host.Architecture,
            ["operatingSystem"] = snapshot.Host.OsDescription
        };
        string cgroups = string.Empty;
        if (OperatingSystem.IsLinux())
            cgroups = (EvidenceCollector.ReadFixedFile("/proc/self/cgroup", warnings) ?? string.Empty) + "\n" + (EvidenceCollector.ReadFixedFile("/proc/1/cgroup", warnings) ?? string.Empty);
        var environmentNames = ContainerEnvironmentNames.Where(HasEnvironmentName).ToHashSet(StringComparer.OrdinalIgnoreCase);
        // Only names are inspected. Service-account token files and environment values are never opened/read.
        var result = Detect(cgroups, File.Exists("/.dockerenv"), File.Exists("/run/.containerenv"), environmentNames,
            Directory.Exists("/var/run/secrets/kubernetes.io/serviceaccount"), inventory);
        if (OperatingSystem.IsMacOS())
        {
            foreach (var command in new[]
            {
                (Key: "macOSVersion", Tool: "sw_vers", Args: new[] { "-productVersion" }),
                (Key: "macOSBuild", Tool: "sw_vers", Args: new[] { "-buildVersion" }),
                (Key: "hardwareModel", Tool: "sysctl", Args: new[] { "-n", "hw.model" }),
                (Key: "physicalMemoryBytes", Tool: "sysctl", Args: new[] { "-n", "hw.memsize" }),
                (Key: "logicalProcessors", Tool: "sysctl", Args: new[] { "-n", "hw.logicalcpu" })
            })
            {
                var query = await CommandRunner.RunAsync(command.Tool, command.Args, TimeSpan.FromSeconds(3), cancellationToken);
                if (query.ExitCode == 0 && !query.TimedOut) inventory[command.Key] = EvidenceCollector.Safe(snapshot, query.StandardOutput.Trim());
                else warnings.Add($"macOS inventory {command.Key} unavailable or permission denied.");
            }
        }
        warnings.Add("Container signals describe the current execution environment. No Docker/Podman socket, Kubernetes API, network service or service-account token was accessed; cluster-wide inventory is outside these local signals.");
        if (!result.ContainerDetected) warnings.Add("No container marker was observed; absence of local markers does not prove execution on a physical host.");
        return new AnalysisReport("environment", snapshot.CollectedAtUtc, [], result with { Inventory = inventory }, warnings);
    }

    /// <summary>Pure detector for fixtures and offline evidence; strings contain cgroup paths, not environment values.</summary>
    public static RuntimeEnvironment Detect(string cgroups, bool dockerMarker, bool podmanMarker,
        IReadOnlySet<string> environmentNames, bool kubernetesServiceAccountDirectory,
        IReadOnlyDictionary<string, string>? inventory = null)
    {
        var signals = new List<string>();
        var docker = dockerMarker || cgroups.Contains("/docker/", StringComparison.OrdinalIgnoreCase) || cgroups.Contains("docker-", StringComparison.OrdinalIgnoreCase);
        var podman = podmanMarker || cgroups.Contains("libpod", StringComparison.OrdinalIgnoreCase);
        var kubernetes = cgroups.Contains("kubepods", StringComparison.OrdinalIgnoreCase) || environmentNames.Contains("KUBERNETES_SERVICE_HOST") || kubernetesServiceAccountDirectory;
        if (dockerMarker) signals.Add("Docker marker file present.");
        if (podmanMarker) signals.Add("Podman marker file present.");
        if (cgroups.Contains("docker", StringComparison.OrdinalIgnoreCase)) signals.Add("Docker cgroup marker present.");
        if (cgroups.Contains("libpod", StringComparison.OrdinalIgnoreCase)) signals.Add("Podman/libpod cgroup marker present.");
        if (cgroups.Contains("kubepods", StringComparison.OrdinalIgnoreCase)) signals.Add("Kubernetes cgroup marker present.");
        if (environmentNames.Contains("KUBERNETES_SERVICE_HOST")) signals.Add("Kubernetes environment-variable name present; its value was not read.");
        if (kubernetesServiceAccountDirectory) signals.Add("Kubernetes service-account directory present; no token was read.");
        var generic = cgroups.Contains("containerd", StringComparison.OrdinalIgnoreCase) || cgroups.Contains("/lxc/", StringComparison.OrdinalIgnoreCase) || environmentNames.Contains("container");
        if (generic) signals.Add("Generic container cgroup/environment-name marker present; runtime attribution may be incomplete.");
        return new RuntimeEnvironment(docker || podman || kubernetes || generic, docker, podman, kubernetes, signals, inventory ?? new Dictionary<string, string>());
    }

    public static async Task<Snapshot> EnrichSnapshotAsync(Snapshot snapshot, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsMacOS()) return snapshot;
        var warnings = snapshot.CollectionWarnings.ToList();
        var total = await CommandRunner.RunAsync("sysctl", ["-n", "hw.memsize"], TimeSpan.FromSeconds(3), cancellationToken);
        var pages = await CommandRunner.RunAsync("vm_stat", [], TimeSpan.FromSeconds(3), cancellationToken);
        var top = await CommandRunner.RunAsync("top", ["-l", "2", "-n", "0", "-s", "1"], TimeSpan.FromSeconds(4), cancellationToken);
        var memory = snapshot.Memory;
        if (total.ExitCode == 0 && pages.ExitCode == 0 && ulong.TryParse(total.StandardOutput.Trim(), CultureInfo.InvariantCulture, out var totalBytes))
        {
            try { memory = ParseMacMemory(totalBytes, pages.StandardOutput); }
            catch (InvalidDataException ex) { warnings.Add(ex.Message); }
        }
        else warnings.Add("macOS host memory unavailable; runtime fallback is not host-wide memory.");
        var cpu = ParseMacCpu(top.StandardOutput);
        if (top.ExitCode != 0 || cpu is null) warnings.Add("macOS host CPU unavailable; process-based CPU fallback must not be interpreted as host-wide utilization.");
        return snapshot with { Memory = memory, CpuUsedPercent = cpu ?? snapshot.CpuUsedPercent, CollectionWarnings = warnings };
    }

    public static MemoryInfo ParseMacMemory(ulong totalBytes, string vmStat)
    {
        var size = PageSize.Match(vmStat);
        if (!size.Success || !ulong.TryParse(size.Groups[1].Value, CultureInfo.InvariantCulture, out var pageBytes) || pageBytes == 0)
            throw new InvalidDataException("macOS vm_stat did not expose a valid page size.");
        var counts = new Dictionary<string, ulong>(StringComparer.Ordinal);
        foreach (var line in vmStat.Split('\n'))
        {
            var parts = line.Split(':', 2);
            if (parts.Length == 2 && ulong.TryParse(parts[1].Trim().TrimEnd('.'), CultureInfo.InvariantCulture, out var count)) counts[parts[0].Trim()] = count;
        }
        if (!counts.TryGetValue("Pages free", out var free)) throw new InvalidDataException("macOS vm_stat did not report free pages.");
        try
        {
            var available = Math.Min(totalBytes, checked(checked(free + counts.GetValueOrDefault("Pages inactive") + counts.GetValueOrDefault("Pages speculative")) * pageBytes));
            var used = totalBytes - available;
            return new MemoryInfo(totalBytes, available, used, totalBytes == 0 ? 0 : used * 100d / totalBytes, "macOS-vm_stat-free+inactive+speculative-approximation");
        }
        catch (OverflowException) { throw new InvalidDataException("macOS vm_stat page counts overflowed the supported memory range."); }
    }

    public static double? ParseMacCpu(string topOutput)
    {
        var matches = IdleCpu.Matches(topOutput);
        if (matches.Count == 0 || !double.TryParse(matches[^1].Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var idle) || !double.IsFinite(idle) || idle is < 0 or > 100) return null;
        return 100 - idle;
    }

    private static bool HasEnvironmentName(string name)
    {
        // getenv is used only as a presence probe: its value pointer is never dereferenced.
        // Avoid Environment.GetEnvironmentVariables(), which materializes every secret value just to enumerate keys.
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()) return GetEnvironmentPointer(name) != IntPtr.Zero;
        if (OperatingSystem.IsWindows())
            return GetWindowsEnvironmentSize(name, IntPtr.Zero, 0) > 0 || Marshal.GetLastPInvokeError() != 203;
        return false;
    }

    [SuppressMessage("Globalization", "CA2101", Justification = "Only fixed ASCII variable names are passed; UTF-8 matches libc on supported Unix systems.")]
    [DllImport("libc", EntryPoint = "getenv")]
    private static extern IntPtr GetEnvironmentPointer([MarshalAs(UnmanagedType.LPUTF8Str)] string name);

    [DllImport("kernel32.dll", EntryPoint = "GetEnvironmentVariableW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern uint GetWindowsEnvironmentSize(string name, IntPtr buffer, uint size);
}
