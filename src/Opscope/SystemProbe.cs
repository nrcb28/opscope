using System.Diagnostics;
using System.Globalization;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace Opscope;

internal sealed class SystemProbe
{
    internal sealed record FirewallObservation(string State, bool RulesPresent, bool FilteringVerified, IReadOnlyList<string>? Families = null);

    private static readonly Regex Whitespace = new(@"\s+", RegexOptions.Compiled);
    private static readonly Regex WindowsServiceState = new(@"\b(RUNNING|STOPPED|PAUSED|START_PENDING|STOP_PENDING|PAUSE_PENDING|CONTINUE_PENDING)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static async Task<Snapshot> CollectAsync(CollectorOptions options, CancellationToken cancellationToken = default)
    {
        // Collection is best effort: one unavailable platform enrichment should not discard the whole snapshot.
        // La recopilación es tolerante a fallos: una mejora de plataforma ausente no descarta toda la instantánea.
        var started = Stopwatch.GetTimestamp();
        var warnings = new List<string>();

        var host = ReadHostInfo(warnings);
        var tooling = ToolInventory.Collect();
        var cpu = await ReadCpuPercentAsync(options.EffectiveCommandTimeout, warnings, cancellationToken);
        var memory = ReadMemory(warnings);
        var disks = ReadDisks(warnings);
        IReadOnlyList<NetworkAdapter> network = options.IncludeNetwork ? ReadNetwork(warnings) : Array.Empty<NetworkAdapter>();
        var processes = options.IncludeProcesses ? ReadProcesses(options.TopProcesses, warnings, cancellationToken) : Array.Empty<ProcessInfo>();
        var listeners = options.IncludeNetwork ? await ReadListenersAsync(options.EffectiveCommandTimeout, warnings, cancellationToken) : Array.Empty<ListenerInfo>();
        var services = options.IncludeServices ? await ReadServicesAsync(options.EffectiveCommandTimeout, warnings, cancellationToken) : Array.Empty<ServiceInfo>();
        var security = options.IncludeNetwork ? await ReadSecurityAsync(listeners, options.EffectiveCommandTimeout, warnings, cancellationToken) : new SecurityPosture(Array.Empty<FirewallProfile>(), false, false, 0);

        var findings = Evaluate(host, cpu, memory, disks, network, listeners, services, security, tooling, options.IncludeNetwork, options.IncludeServices);
        var duration = Stopwatch.GetElapsedTime(started);
        return new Snapshot(DateTimeOffset.UtcNow, host, cpu, memory, disks, network, processes, listeners, services, security, tooling, findings, warnings, duration);
    }

    private static HostInfo ReadHostInfo(List<string> warnings)
    {
        var uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);
        var boot = DateTimeOffset.UtcNow - uptime;
        var currentUser = Environment.UserName;
        var elevated = false;

        try
        {
            if (OperatingSystem.IsWindows())
            {
                // Ask Windows for the token's actual group membership; do not infer elevation from the username.
                // Consultamos la pertenencia real del token; no inferimos elevación a partir del nombre de usuario.
                using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                elevated = new System.Security.Principal.WindowsPrincipal(identity)
                    .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            else if (OperatingSystem.IsLinux())
            {
                // Read the effective UID from procfs so an environment variable cannot spoof root detection.
                // Leemos el UID efectivo de procfs para que una variable de entorno no pueda falsificar root.
                var uidLine = File.ReadLines("/proc/self/status")
                    .FirstOrDefault(line => line.StartsWith("Uid:", StringComparison.Ordinal));
                var effectiveUid = uidLine?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ElementAtOrDefault(2);
                elevated = effectiveUid == "0";
            }
            else
            {
                elevated = Environment.UserName.Equals("root", StringComparison.OrdinalIgnoreCase);
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Could not determine elevation state: {ex.Message}");
        }

        return new HostInfo(
            Environment.MachineName,
            RuntimeInformation.OSDescription.Trim(),
            OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsLinux() ? "linux" : OperatingSystem.IsMacOS() ? "macos" : "other",
            RuntimeInformation.OSArchitecture.ToString(),
            RuntimeInformation.FrameworkDescription,
            Environment.OSVersion.VersionString,
            boot,
            uptime,
            elevated,
            Environment.ProcessorCount,
            currentUser);
    }

    private static async Task<double> ReadCpuPercentAsync(TimeSpan timeout, List<string> warnings, CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsLinux())
        {
            // Linux exposes aggregate CPU counters in /proc/stat; sample two points to calculate utilization.
            // Linux expone contadores agregados en /proc/stat; tomamos dos muestras para calcular el uso.
            try
            {
                var first = ReadProcStat();
                await Task.Delay(TimeSpan.FromMilliseconds(150), cancellationToken);
                var second = ReadProcStat();
                var idle = second.Idle - first.Idle;
                var total = second.Total - first.Total;
                return total <= 0 ? 0 : Math.Clamp((1 - (double)idle / total) * 100, 0, 100);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                warnings.Add($"CPU sampling via /proc/stat failed: {ex.Message}");
            }
        }

        if (OperatingSystem.IsWindows())
        {
            // GetSystemTimes measures host-wide CPU use, unlike Process.TotalProcessorTime which measures only us.
            // GetSystemTimes mide el uso del host, no solo el tiempo de CPU de opscope.
            try
            {
                if (GetSystemTimes(out var firstIdle, out var firstKernel, out var firstUser))
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(150), cancellationToken);
                    if (GetSystemTimes(out var secondIdle, out var secondKernel, out var secondUser))
                    {
                        var idleDelta = secondIdle.ToUInt64() - firstIdle.ToUInt64();
                        var totalDelta = (secondKernel.ToUInt64() + secondUser.ToUInt64()) -
                                         (firstKernel.ToUInt64() + firstUser.ToUInt64());
                        return totalDelta == 0 ? 0 : Math.Clamp((1 - (double)idleDelta / totalDelta) * 100, 0, 100);
                    }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                warnings.Add($"CPU sampling via GetSystemTimes failed: {ex.Message}");
            }
        }

        try
        {
            using var process = Process.GetCurrentProcess();
            var before = process.TotalProcessorTime;
            var started = Stopwatch.GetTimestamp();
            await Task.Delay(TimeSpan.FromMilliseconds(150), cancellationToken);
            process.Refresh();
            var elapsed = Stopwatch.GetElapsedTime(started);
            var delta = process.TotalProcessorTime - before;
            return Math.Clamp(delta.TotalMilliseconds / (elapsed.TotalMilliseconds * Environment.ProcessorCount) * 100, 0, 100);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            warnings.Add($"CPU sampling failed: {ex.Message}");
            return 0;
        }
    }

    private static (ulong Idle, ulong Total) ReadProcStat()
    {
        var line = File.ReadLines("/proc/stat").First(l => l.StartsWith("cpu ", StringComparison.Ordinal));
        var values = line.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1).Select(ulong.Parse).ToArray();
        var idle = values.ElementAtOrDefault(3) + values.ElementAtOrDefault(4);
        return (idle, values.Aggregate(0UL, (sum, value) => sum + value));
    }

    private static MemoryInfo ReadMemory(List<string> warnings)
    {
        try
        {
            if (OperatingSystem.IsLinux() && File.Exists("/proc/meminfo"))
            {
                var values = File.ReadLines("/proc/meminfo")
                    .Select(line => line.Split(':', 2))
                    .Where(parts => parts.Length == 2)
                    .ToDictionary(parts => parts[0], parts => ParseKilobytes(parts[1]));
                var total = values.GetValueOrDefault("MemTotal");
                var available = values.GetValueOrDefault("MemAvailable", values.GetValueOrDefault("MemFree"));
                return CreateMemory(total, available, "procfs");
            }

            if (OperatingSystem.IsWindows())
            {
                var status = new MEMORYSTATUSEX { Length = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
                if (GlobalMemoryStatusEx(ref status))
                {
                    return CreateMemory(status.TotalPhys, status.AvailPhys, "GlobalMemoryStatusEx");
                }
            }

            var gcInfo = GC.GetGCMemoryInfo();
            var fallbackTotal = gcInfo.TotalAvailableMemoryBytes > 0 ? (ulong)gcInfo.TotalAvailableMemoryBytes : 0;
            var fallbackUsed = (ulong)Math.Max(0, GC.GetTotalMemory(false));
            return CreateMemory(fallbackTotal, fallbackTotal > fallbackUsed ? fallbackTotal - fallbackUsed : 0, "runtime-fallback");
        }
        catch (Exception ex)
        {
            warnings.Add($"Memory collection failed: {ex.Message}");
            return new MemoryInfo(0, 0, 0, 0, "unavailable");
        }
    }

    private static ulong ParseKilobytes(string value)
    {
        var number = ulong.Parse(Whitespace.Replace(value, string.Empty).Replace("kB", string.Empty, StringComparison.OrdinalIgnoreCase), CultureInfo.InvariantCulture);
        return number * 1024;
    }

    private static MemoryInfo CreateMemory(ulong total, ulong available, string source)
    {
        var used = total > available ? total - available : 0;
        return new MemoryInfo(total, available, used, total == 0 ? 0 : used * 100d / total, source);
    }

    private static List<DiskInfo> ReadDisks(List<string> warnings)
    {
        var result = new List<DiskInfo>();
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                try
                {
                    if (!drive.IsReady)
                    {
                        result.Add(new DiskInfo(drive.Name, drive.RootDirectory.FullName, string.Empty, 0, 0, 0, false));
                        continue;
                    }

                    var used = drive.TotalSize - drive.AvailableFreeSpace;
                    result.Add(new DiskInfo(drive.Name, drive.RootDirectory.FullName, drive.DriveFormat, drive.TotalSize, drive.AvailableFreeSpace,
                        drive.TotalSize == 0 ? 0 : used * 100d / drive.TotalSize, true));
                }
                catch (Exception ex)
                {
                    warnings.Add($"Disk {drive.Name} unavailable: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Disk enumeration failed: {ex.Message}");
        }
        return result;
    }

    private static List<NetworkAdapter> ReadNetwork(List<string> warnings)
    {
        var result = new List<NetworkAdapter>();
        try
        {
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                var addresses = adapter.GetIPProperties().UnicastAddresses.Select(address => address.Address.ToString()).ToArray();
                result.Add(new NetworkAdapter(adapter.Name, adapter.Description, adapter.NetworkInterfaceType.ToString(), adapter.OperationalStatus.ToString(), addresses, adapter.Speed));
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Network enumeration failed: {ex.Message}");
        }
        return result;
    }

    private static ProcessInfo[] ReadProcesses(int top, List<string> warnings, CancellationToken cancellationToken)
    {
        var rows = new List<ProcessInfo>();
        try
        {
            foreach (var process in Process.GetProcesses())
            {
                cancellationToken.ThrowIfCancellationRequested();
                using (process)
                {
                    try
                    {
                        var commandLine = TryGetCommandLine(process);
                        var user = TryGetProcessUser(process);
                        var memory = process.WorkingSet64;
                        rows.Add(new ProcessInfo(process.Id, process.ProcessName, user, memory, memory / 1024d / 1024d, process.TotalProcessorTime, commandLine, false));
                    }
                    catch (Exception)
                    {
                        rows.Add(new ProcessInfo(process.Id, SafeProcessName(process), "?", 0, 0, TimeSpan.Zero, null, true));
                    }
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            warnings.Add($"Process enumeration failed: {ex.Message}");
        }
        return rows.OrderByDescending(row => row.WorkingSetBytes).Take(Math.Max(1, top)).ToArray();
    }

    private static string SafeProcessName(Process process)
    {
        try { return process.ProcessName; } catch { return "<unknown>"; }
    }

    private static string TryGetProcessUser(Process process)
    {
        if (OperatingSystem.IsLinux())
        {
            try
            {
                var uidLine = File.ReadLines($"/proc/{process.Id}/status").FirstOrDefault(line => line.StartsWith("Uid:", StringComparison.Ordinal));
                var uid = uidLine?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ElementAtOrDefault(1);
                return string.IsNullOrWhiteSpace(uid) ? "?" : $"uid:{uid}";
            }
            catch { return "?"; }
        }
        return "?";
    }

    private static string? TryGetCommandLine(Process process)
    {
        try
        {
            if (OperatingSystem.IsLinux())
            {
                var path = $"/proc/{process.Id}/cmdline";
                if (File.Exists(path))
                {
                    using var stream = File.OpenRead(path);
                    var buffer = new byte[8192];
                    var read = stream.Read(buffer, 0, buffer.Length);
                    var value = Encoding.UTF8.GetString(buffer, 0, read).Replace('\0', ' ').Trim();
                    return stream.Position < stream.Length ? $"{value} …[truncated]" : value;
                }
            }
            // Reading another process' command line on Windows requires either
            // WMI or a native NtQueryInformationProcess implementation. Keep
            // the core binary dependency-free and report it as best effort.
        }
        catch { /* command line is best effort */ }
        return null;
    }

    private static async Task<IReadOnlyList<ListenerInfo>> ReadListenersAsync(TimeSpan timeout, List<string> warnings, CancellationToken cancellationToken)
    {
        var result = new List<ListenerInfo>();
        if (OperatingSystem.IsLinux())
        {
            var command = await CommandRunner.RunAsync("ss", ["-lntupH"], timeout, cancellationToken);
            AddCommandDiagnostics("ss", command, warnings);
            if (command.ExitCode == 0)
            {
                foreach (var line in command.StandardOutput.SplitLines())
                {
                    var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (fields.Length >= 5) result.Add(new ListenerInfo(fields[0], fields[4], fields.Length >= 7 ? string.Join(' ', fields.Skip(6)) : "-", "ss"));
                }
            }

            if (result.Count == 0)
            {
                // lsof is an optional, read-only fallback when ss is unavailable or cannot map sockets.
                // lsof es un fallback opcional y de solo lectura cuando ss no puede mapear sockets.
                var fallback = await CommandRunner.RunAsync("lsof", ["-nP", "-iTCP", "-sTCP:LISTEN", "-iUDP"], timeout, cancellationToken);
                AddCommandDiagnostics("lsof", fallback, warnings, reportExitFailure: false);
                if (fallback.ExitCode == 0 && !fallback.OutputTruncated)
                    AddLsofListeners(fallback.StandardOutput, result);
            }
        }
        else if (OperatingSystem.IsWindows())
        {
            var command = await CommandRunner.RunAsync("netstat", ["-ano"], timeout, cancellationToken);
            AddCommandDiagnostics("netstat", command, warnings);
            if (command.ExitCode == 0)
            {
                foreach (var line in command.StandardOutput.SplitLines())
                {
                    var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (fields.Length >= 5 && fields[0].Equals("TCP", StringComparison.OrdinalIgnoreCase) && fields[3].Equals("LISTENING", StringComparison.OrdinalIgnoreCase))
                        result.Add(new ListenerInfo(fields[0], fields[1], $"pid={fields[^1]}", "netstat"));
                    else if (fields.Length >= 4 && fields[0].Equals("UDP", StringComparison.OrdinalIgnoreCase))
                        result.Add(new ListenerInfo(fields[0], fields[1], $"pid={fields[^1]}", "netstat"));
                }
            }
        }
        return result;
    }

    internal static void AddLsofListeners(string output, List<ListenerInfo> result)
    {
        foreach (var line in output.SplitLines())
        {
            var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 9 || fields[0].Equals("COMMAND", StringComparison.OrdinalIgnoreCase)) continue;

            var protocol = fields[7].StartsWith("TCP", StringComparison.OrdinalIgnoreCase) ? "TCP" :
                fields[7].StartsWith("UDP", StringComparison.OrdinalIgnoreCase) ? "UDP" : string.Empty;
            if (string.IsNullOrEmpty(protocol)) continue;
            var name = string.Join(' ', fields.Skip(8));
            if (protocol == "TCP" && !name.Contains("(LISTEN)", StringComparison.OrdinalIgnoreCase)) continue;

            result.Add(new ListenerInfo(protocol, fields[8], $"{fields[0]} pid={fields[1]}", "lsof"));
        }
    }

    private static async Task<IReadOnlyList<ServiceInfo>> ReadServicesAsync(TimeSpan timeout, List<string> warnings, CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsLinux())
        {
            var command = await CommandRunner.RunAsync("systemctl", ["list-units", "--type=service", "--all", "--no-legend", "--plain"], timeout, cancellationToken);
            AddCommandDiagnostics("systemctl", command, warnings);
            if (command.ExitCode == 0)
            {
                return command.StandardOutput.SplitLines()
                    .Select(line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                    .Where(fields => fields.Length >= 4)
                    .Select(fields => new ServiceInfo(fields[0], $"{fields[2]}/{fields[3]}", fields.Length > 4 ? string.Join(' ', fields.Skip(4)) : null, "systemctl"))
                    .ToArray();
            }
        }
        else if (OperatingSystem.IsWindows())
        {
            var command = await CommandRunner.RunAsync("sc.exe", ["query", "state=", "all"], timeout, cancellationToken);
            AddCommandDiagnostics("sc.exe", command, warnings);
            if (command.ExitCode == 0)
            {
                var services = new List<ServiceInfo>();
                string? name = null;
                foreach (var line in command.StandardOutput.SplitLines())
                {
                    var trimmed = line.Trim();
                    var colon = trimmed.IndexOf(':');
                    if (colon < 1) continue;
                    var key = trimmed[..colon];
                    var value = trimmed[(colon + 1)..].Trim();
                    if (key.Contains("SERVICE", StringComparison.OrdinalIgnoreCase) || key.Contains("SERVICIO", StringComparison.OrdinalIgnoreCase)) name = value;
                    else if (name is not null && (key.Contains("STATE", StringComparison.OrdinalIgnoreCase) || key.Contains("ESTADO", StringComparison.OrdinalIgnoreCase)))
                    {
                        var state = ParseWindowsServiceState(value);
                        services.Add(new ServiceInfo(name, state, null, "sc.exe"));
                        name = null;
                    }
                }
                return services;
            }
        }
        return Array.Empty<ServiceInfo>();
    }

    private static async Task<SecurityPosture> ReadSecurityAsync(IReadOnlyList<ListenerInfo> listeners, TimeSpan timeout, List<string> warnings, CancellationToken cancellationToken)
    {
        // These commands only query firewall state; opscope never changes firewall policy.
        // Estos comandos solo consultan el estado; opscope nunca modifica la política del firewall.
        var firewalls = new List<FirewallProfile>();
        if (OperatingSystem.IsWindows())
        {
            var command = await CommandRunner.RunAsync("netsh", ["advfirewall", "show", "allprofiles", "state"], timeout, cancellationToken);
            AddCommandDiagnostics("netsh", command, warnings);
            if (command.ExitCode == 0)
            {
                string? profile = null;
                foreach (var line in command.StandardOutput.SplitLines())
                {
                    var trimmed = line.Trim();
                    if (trimmed.Contains("Profile Settings", StringComparison.OrdinalIgnoreCase) ||
                        (trimmed.Contains("Configuración", StringComparison.OrdinalIgnoreCase) && trimmed.Contains("Perfil", StringComparison.OrdinalIgnoreCase)))
                    {
                        profile = Regex.Replace(trimmed, @"^Configuración\s+de\s+Perfil\s*|^Configuración\s+del\s+Perfil\s*", string.Empty, RegexOptions.IgnoreCase).Trim(' ', ':');
                        profile = Regex.Replace(profile, @"\s*Profile Settings\s*:?[ ]*$", string.Empty, RegexOptions.IgnoreCase).Trim(' ', ':');
                    }
                    else if (profile is not null && (trimmed.StartsWith("State", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("Estado", StringComparison.OrdinalIgnoreCase)))
                    {
                        var fields = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                        var state = fields.Length == 0 ? "UNKNOWN" : NormalizeFirewallState(fields[^1]);
                        firewalls.Add(new FirewallProfile(profile, state, "netsh", RulesPresent: false, FilteringVerified: state == "ACTIVE"));
                        profile = null;
                    }
                }
            }
        }
        else if (OperatingSystem.IsLinux())
        {
            var candidates = new (string Name, string[] Arguments)[]
            {
                ("ufw", ["status"]),
                ("firewall-cmd", ["--state"]),
                ("nft", ["list", "ruleset"])
            };
            var successfulInspection = false;
            foreach (var candidate in candidates)
            {
                var command = await CommandRunner.RunAsync(candidate.Name, candidate.Arguments, timeout, cancellationToken);
                AddCommandDiagnostics(candidate.Name, command, warnings, reportExitFailure: false);
                if (command.ExitCode != 0) continue;
                if (command.OutputTruncated) continue;
                var output = command.StandardOutput.Trim();
                var observation = candidate.Name switch
                {
                    "ufw" => ParseUfwState(output),
                    "firewall-cmd" => ParseFirewallCmdState(output),
                    "nft" => ParseNftablesState(output),
                    _ => new FirewallObservation("UNKNOWN", false, false)
                };
                if (!observation.State.Equals("UNKNOWN", StringComparison.OrdinalIgnoreCase)) successfulInspection = true;
                firewalls.Add(new FirewallProfile(candidate.Name, observation.State, candidate.Name, observation.RulesPresent, observation.FilteringVerified, observation.Families));
            }

            if (!successfulInspection)
                warnings.Add("Firewall posture could not be verified: no supported Linux firewall inspector returned a usable state.");
        }

        var known = firewalls.Any(profile => !profile.State.Equals("UNKNOWN", StringComparison.OrdinalIgnoreCase));
        var active = firewalls.Any(profile => profile.State.Equals("ACTIVE", StringComparison.OrdinalIgnoreCase));
        var verifiedFamilies = firewalls
            .Where(profile => profile.FilteringVerified && profile.RulesPresent)
            .SelectMany(profile => profile.Families ?? Array.Empty<string>())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var protectionVerified = verifiedFamilies.Contains("inet") || (verifiedFamilies.Contains("ip") && verifiedFamilies.Contains("ip6"));
        var exposed = listeners.Count(IsExposedListener);
        return new SecurityPosture(firewalls, known, active, exposed, protectionVerified);
    }

    private static void AddCommandDiagnostics(string name, CommandResult command, List<string> warnings, bool reportExitFailure = true)
    {
        if (command.TimedOut)
            warnings.Add($"{name} timed out before completing.");
        if (command.OutputTruncated)
            warnings.Add($"{name} output exceeded the safety limit and was truncated.");
        if (reportExitFailure && command.ExitCode != 0)
        {
            var detail = string.IsNullOrWhiteSpace(command.StandardError) ? $"exit code {command.ExitCode}" : command.StandardError.Trim();
            warnings.Add($"{name} unavailable: {detail}");
        }
    }

    internal static FirewallObservation ParseUfwState(string output)
    {
        foreach (var line in output.SplitLines())
        {
            var colon = line.IndexOf(':');
            if (colon < 1) continue;
            var key = line[..colon].Trim();
            if (!key.Equals("Status", StringComparison.OrdinalIgnoreCase) && !key.Equals("Estado", StringComparison.OrdinalIgnoreCase)) continue;

            return line[(colon + 1)..].Trim().ToUpperInvariant() switch
            {
                "ACTIVE" or "ACTIVO" => new FirewallObservation("ACTIVE", false, false),
                "INACTIVE" or "INACTIVO" => new FirewallObservation("INACTIVE", false, false),
                _ => new FirewallObservation("UNKNOWN", false, false)
            };
        }

        return new FirewallObservation("UNKNOWN", false, false);
    }

    internal static FirewallObservation ParseFirewallCmdState(string output) =>
        output.Trim().ToUpperInvariant() switch
        {
            "RUNNING" => new FirewallObservation("ACTIVE", false, false),
            "NOT RUNNING" or "STOPPED" => new FirewallObservation("INACTIVE", false, false),
            _ => new FirewallObservation("UNKNOWN", false, false)
        };

    internal static FirewallObservation ParseNftablesState(string output)
    {
        if (string.IsNullOrWhiteSpace(output)) return new FirewallObservation("INACTIVE", false, false);

        var currentFamily = string.Empty;
        var currentTableSupported = false;
        var currentHook = string.Empty;
        var hasSupportedFilterTable = false;
        var hasInputHook = false;
        var hasRule = false;
        var filteringVerified = false;
        var effectiveFamilies = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in output.SplitLines())
        {
            var trimmed = line.Trim();
            var table = Regex.Match(trimmed, @"^table\s+(?<family>\w+)\s+", RegexOptions.IgnoreCase);
            if (table.Success)
            {
                currentFamily = table.Groups["family"].Value.ToLowerInvariant();
                currentTableSupported = currentFamily is "ip" or "ip6" or "inet";
                hasSupportedFilterTable |= currentTableSupported;
                currentHook = string.Empty;
                continue;
            }

            if (trimmed.StartsWith("chain ", StringComparison.OrdinalIgnoreCase))
            {
                currentHook = string.Empty;
                continue;
            }

            var hook = Regex.Match(trimmed, @"\btype\s+filter\s+hook\s+(?<hook>\w+)\b", RegexOptions.IgnoreCase);
            if (hook.Success)
            {
                currentHook = hook.Groups["hook"].Value.ToLowerInvariant();
                if (currentTableSupported && currentHook.Equals("input", StringComparison.OrdinalIgnoreCase)) hasInputHook = true;
            }

            // Only an input hook in an IP-capable family can protect local TCP/UDP listeners.
            // Solo un hook input en una familia IP puede proteger listeners TCP/UDP locales.
            if (!currentTableSupported || !currentHook.Equals("input", StringComparison.OrdinalIgnoreCase)) continue;
            if (Regex.IsMatch(trimmed, @"\bpolicy\s+(drop|reject)\b", RegexOptions.IgnoreCase))
            {
                hasRule = true;
                filteringVerified = true;
                effectiveFamilies.Add(currentFamily);
            }
            else if (Regex.IsMatch(trimmed, @"\b(drop|reject)\b", RegexOptions.IgnoreCase))
            {
                hasRule = true;
                if (AppliesToNonLoopback(trimmed))
                {
                    filteringVerified = true;
                    effectiveFamilies.Add(currentFamily);
                }
            }
        }

        if (!hasSupportedFilterTable) return new FirewallObservation("UNKNOWN", false, false);
        if (!hasInputHook || !hasRule) return new FirewallObservation("UNVERIFIED", false, false);
        return new FirewallObservation(filteringVerified ? "ACTIVE" : "UNVERIFIED", true, filteringVerified, effectiveFamilies.ToArray());
    }

    private static bool AppliesToNonLoopback(string rule)
    {
        var onlyLoopbackInterface = Regex.IsMatch(rule, @"\b(?:iif|iifname|oif|oifname)\s+(?:""lo""|'lo'|lo)(?:\s|;|$)", RegexOptions.IgnoreCase) &&
                                    !Regex.IsMatch(rule, @"\b(?:iif|iifname|oif|oifname)\s+(?:!=|not\s+in)\b", RegexOptions.IgnoreCase) &&
                                    !Regex.IsMatch(rule, @"\b(?:iif|iifname|oif|oifname)\s+\{[^}]*\b(?:eth|en|wl|bond|br)", RegexOptions.IgnoreCase);
        if (onlyLoopbackInterface) return false;

        var onlyLoopbackAddress = Regex.IsMatch(rule, @"\b(?:ip\s+(?:saddr|daddr)\s+127\.0\.0\.0/8|ip6\s+(?:saddr|daddr)\s+::1)\b", RegexOptions.IgnoreCase);
        return !onlyLoopbackAddress;
    }

    private static string ParseWindowsServiceState(string value)
    {
        // Service state numbers are stable across Windows locales, so prefer them over translated text.
        // Los códigos numéricos son estables entre idiomas de Windows, así que preferimos esos códigos al texto.
        foreach (var token in value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out var code)) continue;
            return code switch
            {
                1 => "STOPPED",
                2 => "START_PENDING",
                3 => "STOP_PENDING",
                4 => "RUNNING",
                5 => "CONTINUE_PENDING",
                6 => "PAUSE_PENDING",
                7 => "PAUSED",
                _ => "UNKNOWN"
            };
        }

        var stateMatch = WindowsServiceState.Match(value);
        return stateMatch.Success ? stateMatch.Value.ToUpperInvariant() : value;
    }

    // Normalize common localized netsh values into the stable schema used by findings and automation.
    // Normalizamos valores localizados de netsh al esquema estable usado por hallazgos y automatización.
    private static string NormalizeFirewallState(string value) => value.Trim().ToUpperInvariant() switch
    {
        "ON" or "ACTIVE" or "RUNNING" or "ACTIVATED" or "ACTIVADO" or "ACTIVAR" or "ENABLED" or "HABILITADO" or "1" => "ACTIVE",
        "OFF" or "INACTIVE" or "STOPPED" or "DEACTIVATED" or "DESACTIVATED" or "DESACTIVADO" or "DESACTIVAR" or "DISABLED" or "DESHABILITADO" or "0" => "INACTIVE",
        _ => "UNKNOWN"
    };

    private static bool IsExposedListener(ListenerInfo listener)
    {
        var address = listener.LocalAddress.Trim();
        if (address.Equals("*", StringComparison.OrdinalIgnoreCase) ||
            address.StartsWith("*:", StringComparison.OrdinalIgnoreCase) ||
            address.StartsWith(":::", StringComparison.OrdinalIgnoreCase))
            return true;

        string host;
        if (address.StartsWith('['))
        {
            var closingBracket = address.IndexOf(']');
            host = closingBracket > 1 ? address[1..closingBracket] : address;
        }
        else
        {
            var lastColon = address.LastIndexOf(':');
            host = lastColon > 0 ? address[..lastColon] : address;
        }

        return host.Equals("0.0.0.0", StringComparison.OrdinalIgnoreCase) ||
               host.Equals("::", StringComparison.OrdinalIgnoreCase) ||
               host.Equals("*", StringComparison.OrdinalIgnoreCase);
    }

    private static List<Finding> Evaluate(HostInfo host, double cpu, MemoryInfo memory, IReadOnlyList<DiskInfo> disks,
        IReadOnlyList<NetworkAdapter> network, IReadOnlyList<ListenerInfo> listeners, IReadOnlyList<ServiceInfo> services, SecurityPosture security,
        ToolingPosture tooling,
        bool networkRequested, bool servicesRequested)
    {
        var findings = new List<Finding>();
        if (cpu >= 95) findings.Add(new(FindingSeverity.Critical, "CPU_HIGH", "CPU saturation", $"CPU usage is {cpu:F1}%.", "Identify the top CPU consumers and check whether the load is expected."));
        else if (cpu >= 80) findings.Add(new(FindingSeverity.Warning, "CPU_ELEVATED", "Elevated CPU usage", $"CPU usage is {cpu:F1}%.", "Review the process list and correlate with workload or scheduled jobs."));

        if (memory.UsedPercent >= 95) findings.Add(new(FindingSeverity.Critical, "MEMORY_PRESSURE", "Severe memory pressure", $"Memory usage is {memory.UsedPercent:F1}%.", "Inspect top processes, swap/pagefile activity and recent workload changes."));
        else if (memory.UsedPercent >= 85) findings.Add(new(FindingSeverity.Warning, "MEMORY_ELEVATED", "Elevated memory usage", $"Memory usage is {memory.UsedPercent:F1}%.", "Review top processes and verify that available memory is recovering."));

        foreach (var disk in disks.Where(disk => disk.IsReady && disk.UsedPercent >= 95))
            findings.Add(new(FindingSeverity.Critical, "DISK_FULL", $"Disk nearly full: {disk.Root}", $"{disk.UsedPercent:F1}% used with {FormatBytes(disk.AvailableBytes)} free.", "Free space or extend the volume before writes fail."));
        foreach (var disk in disks.Where(disk => disk.IsReady && disk.UsedPercent >= 85 && disk.UsedPercent < 95))
            findings.Add(new(FindingSeverity.Warning, "DISK_ELEVATED", $"Disk usage elevated: {disk.Root}", $"{disk.UsedPercent:F1}% used.", "Review growth and retention before the volume reaches a critical level."));

        if (networkRequested && !network.Any(adapter => adapter.Status.Equals("Up", StringComparison.OrdinalIgnoreCase) && adapter.Addresses.Any(address => !address.Equals("127.0.0.1") && !address.Equals("::1"))))
            findings.Add(new(FindingSeverity.Warning, "NETWORK_DOWN", "No active non-loopback adapter", "No active adapter with a non-loopback address was found.", "Check link state, DHCP/IP configuration and routing."));
        if (servicesRequested && services.Count == 0)
            findings.Add(new(FindingSeverity.Info, "SERVICES_UNAVAILABLE", "Service inventory unavailable", "No running-service records were returned by the platform collector.", "Install or enable the native service inspection tool if service data is required."));
        var failedServices = services.Where(service => service.State.Contains("failed", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (servicesRequested && failedServices.Length > 0)
            findings.Add(new(FindingSeverity.Warning, "SERVICE_FAILED", "Failed services detected", $"{failedServices.Length} service(s) report a failed state.", "Inspect the failed units and their recent logs before treating the host as healthy."));

        var allProfilesInactive = security.Firewalls.Count > 0 && security.Firewalls.All(profile => profile.State.Equals("INACTIVE", StringComparison.OrdinalIgnoreCase));
        if (security.FirewallStatusKnown && allProfilesInactive)
            findings.Add(new(FindingSeverity.Warning, "FIREWALL_INACTIVE", "No active host firewall detected", "The platform firewall inspection reports all detected profiles as inactive.", "Verify the host firewall policy before exposing services to an untrusted network."));
        if (security.FirewallStatusKnown && security.HasActiveFirewall && !security.ProtectionVerified)
            findings.Add(new(FindingSeverity.Warning, "FIREWALL_UNVERIFIED", "Firewall filtering is not fully verified", "A firewall is enabled, but the collector could not verify effective filtering rules for the exposed interfaces.", "Review the active profile, ruleset and interface bindings before relying on the firewall assessment."));
        if (security.FirewallStatusKnown && allProfilesInactive && security.ExposedListeners > 0)
            findings.Add(new(FindingSeverity.Critical, "EXPOSED_LISTENERS", "Listeners exposed without an active firewall", $"{security.ExposedListeners} listener(s) are bound to a wildcard address while the host firewall appears inactive.", "Restrict bindings, enable the intended firewall policy and confirm access from a trusted network."));
        else if (security.ExposedListeners > 0 && security.FirewallStatusKnown && !security.ProtectionVerified)
            findings.Add(new(FindingSeverity.Warning, "EXPOSED_LISTENERS_UNVERIFIED", "Listener protection could not be verified", $"{security.ExposedListeners} listener(s) are bound to wildcard addresses, but effective firewall filtering was not verified.", "Review firewall rules and interface bindings before exposing these listeners to an untrusted network."));
        else if (security.ExposedListeners >= 10)
            findings.Add(new(FindingSeverity.Info, "LISTENER_SURFACE", "Large listening surface", $"{security.ExposedListeners} listeners are bound to wildcard addresses.", "Review each exposed service and remove listeners that are not required."));

        var insecureTools = tooling.Tools.Where(tool => tool.Available && !tool.Security.Equals("secure", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (insecureTools.Length > 0)
        {
            var names = string.Join(", ", insecureTools.Select(tool => tool.Name));
            var severe = insecureTools.Any(tool => tool.Security is "writable-by-non-owner" or "untrusted-path" or "reparse-point" or "not-executable");
            findings.Add(new(severe ? FindingSeverity.Critical : FindingSeverity.Warning, "TOOL_SECURITY", "System tool trust check failed", $"Tool(s) failed the trusted-path or file-permission check: {names}.", "Do not run diagnostics with modified system utilities; restore trusted ownership and permissions before collecting evidence."));
        }

        var missingCore = tooling.Tools.Where(tool => tool.Role.Equals("core", StringComparison.OrdinalIgnoreCase) && !tool.Available).Select(tool => tool.Name).ToArray();
        if (missingCore.Length > 0)
            findings.Add(new(FindingSeverity.Warning, "TOOLING_CORE_GAP", "Core diagnostic tooling is missing", $"Missing tool(s): {string.Join(", ", missingCore)}.", "Install the platform package that provides the missing utility or expect reduced listener/service/firewall coverage."));

        var missingEnrichment = tooling.Tools.Where(tool => tool.Role.Equals("enrichment", StringComparison.OrdinalIgnoreCase) && !tool.Available).Select(tool => tool.Name).ToArray();
        if (missingEnrichment.Length > 0 && missingEnrichment.Length == tooling.Tools.Count(tool => tool.Role.Equals("enrichment", StringComparison.OrdinalIgnoreCase)))
            findings.Add(new(FindingSeverity.Info, "TOOLING_ENRICHMENT_GAP", "Optional security enrichment tooling is missing", $"No optional firewall/network enrichment tool was found; checked: {string.Join(", ", missingEnrichment)}.", "Install one supported firewall inspection utility to improve posture coverage."));

        if (host.Uptime > TimeSpan.FromDays(180))
            findings.Add(new(FindingSeverity.Info, "LONG_UPTIME", "Long host uptime", $"The host has been up for {host.Uptime.TotalDays:F0} days.", "Consider a maintenance window if kernel, driver or platform updates are pending."));

        return findings;
    }

    private static string FormatBytes(long bytes) => bytes switch
    {
        >= 1_000_000_000 => $"{bytes / 1_000_000_000d:F1} GB",
        >= 1_000_000 => $"{bytes / 1_000_000d:F1} MB",
        _ => $"{bytes / 1_000d:F1} KB"
    };

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct MEMORYSTATUSEX
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhys;
        public ulong AvailPhys;
        public ulong TotalPageFile;
        public ulong AvailPageFile;
        public ulong TotalVirtual;
        public ulong AvailVirtual;
        public ulong AvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

    [StructLayout(LayoutKind.Sequential)]
    private struct KernelFileTime
    {
        public uint Low;
        public uint High;

        public ulong ToUInt64() => ((ulong)High << 32) | Low;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetSystemTimes(out KernelFileTime idleTime, out KernelFileTime kernelTime, out KernelFileTime userTime);

}

internal static class StringExtensions
{
    public static IEnumerable<string> SplitLines(this string value) => value.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}

