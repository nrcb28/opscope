using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace Opscope;

public static class CommandRunner
{
    // EN: Trusted fixed paths and argument arrays keep execution independent of PATH and shell parsing.
    // ES: Las rutas fijas confiables y los argumentos separados evitan depender de PATH o de un shell.
    // Bound child-process output to avoid memory exhaustion from a broken or hostile utility.
    // Limitamos la salida de procesos hijos para evitar agotamiento de memoria por una herramienta defectuosa u hostil.
    private const int MaxOutputChars = 256 * 1024;
    private static readonly string UnavailableExecutable = OperatingSystem.IsWindows()
        ? Path.Combine(Environment.SystemDirectory, "opscope-unavailable.exe")
        : "/opscope-unavailable";

    public static Task<CommandResult> RunAsync(string fileName, IEnumerable<string> arguments, TimeSpan timeout, CancellationToken cancellationToken = default) =>
        RunAsync(fileName, arguments, timeout, MaxOutputChars, cancellationToken);

    public static async Task<CommandResult> RunAsync(string fileName, IEnumerable<string> arguments, TimeSpan timeout, int outputLimit, CancellationToken cancellationToken = default)
    {
        if (outputLimit is < 1024 or > 8 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(outputLimit));
        // Execute argument arrays directly: no shell means no shell expansion or command injection.
        // Ejecutamos arrays de argumentos directamente: sin shell no hay expansión ni inyección de comandos.
        var executable = ResolveExecutable(fileName);
        if (!TryValidateExecutablePath(fileName, executable, out var rejection))
            return new CommandResult(-1, string.Empty, $"Executable rejected: {rejection}", false);

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executable,
                WorkingDirectory = OperatingSystem.IsWindows() ? Environment.SystemDirectory : Path.DirectorySeparatorChar.ToString(),
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            },
            EnableRaisingEvents = true
        };

        foreach (var variable in new[] { "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "PYTHONPATH", "PYTHONHOME", "SYSTEMD_PAGER", "PAGER" })
            process.StartInfo.Environment.Remove(variable);
        process.StartInfo.Environment["SYSTEMD_PAGER"] = string.Empty;
        process.StartInfo.Environment["AWS_PAGER"] = string.Empty;
        process.StartInfo.Environment["AWS_CLI_AUTO_PROMPT"] = "off";
        if (fileName is "az" or "azure-python")
        {
            process.StartInfo.Environment["AZURE_EXTENSION_USE_DYNAMIC_INSTALL"] = "no";
            process.StartInfo.Environment["AZURE_CORE_COLLECT_TELEMETRY"] = "0";
            process.StartInfo.Environment["AZURE_AUTO_UPGRADE_ENABLE"] = "no";
            process.StartInfo.Environment["PYTHONDONTWRITEBYTECODE"] = "1";
        }
        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        using var readerCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        readerCts.CancelAfter(timeout);
        Task<(string Text, bool Truncated)>? stdoutTask = null;
        Task<(string Text, bool Truncated)>? stderrTask = null;
        try
        {
            if (!process.Start())
            {
                return new CommandResult(-1, string.Empty, "Process did not start", false);
            }

            stdoutTask = ReadLimitedAsync(process.StandardOutput, outputLimit, readerCts.Token);
            stderrTask = ReadLimitedAsync(process.StandardError, outputLimit, readerCts.Token);
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(timeout);

            try
            {
                await process.WaitForExitAsync(timeoutCts.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                try { process.Kill(entireProcessTree: true); } catch { /* best effort / mejor esfuerzo */ }
                readerCts.Cancel();
                var timedOutStdout = await stdoutTask;
                var timedOutStderr = await stderrTask;
                return new CommandResult(-1, timedOutStdout.Text, timedOutStderr.Text, true, timedOutStdout.Truncated || timedOutStderr.Truncated);
            }

            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            return new CommandResult(process.ExitCode, stdout.Text, stderr.Text, false, stdout.Truncated || stderr.Truncated);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best effort / mejor esfuerzo */ }
            readerCts.Cancel();
            if (stdoutTask is not null) await stdoutTask;
            if (stderrTask is not null) await stderrTask;
            throw;
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException or ArgumentException or PlatformNotSupportedException)
        {
            return new CommandResult(-1, string.Empty, ex.Message, false);
        }
    }

    private static async Task<(string Text, bool Truncated)> ReadLimitedAsync(StreamReader reader, int outputLimit, CancellationToken cancellationToken)
    {
        var buffer = new char[8192];
        var output = new StringBuilder(Math.Min(outputLimit, 32 * 1024));
        var truncated = false;
        int read;
        try
        {
            while ((read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken)) > 0)
            {
                if (output.Length >= outputLimit)
                {
                    truncated = true;
                    continue;
                }

                var remaining = outputLimit - output.Length;
                output.Append(buffer, 0, Math.Min(read, remaining));
                if (read > remaining) truncated = true;
            }
        }
        catch (OperationCanceledException)
        {
            truncated = true;
        }
        return (output.ToString(), truncated);
    }

    internal static string ResolveExecutable(string fileName)
    {
        if (Path.IsPathFullyQualified(fileName)) return fileName;

        if (OperatingSystem.IsWindows())
        {
            var windows = TrustedWindowsCandidates(fileName);
            return windows.FirstOrDefault(File.Exists) ?? UnavailableExecutable;
        }

        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            var candidates = OperatingSystem.IsMacOS() ? TrustedMacCandidates(fileName) : TrustedLinuxCandidates(fileName);
            var resolved = candidates.FirstOrDefault(File.Exists);
            if (resolved is not null) return ResolveFinalPath(resolved);
            if (candidates.Length > 0) return UnavailableExecutable;
        }

        // Never fall back to PATH for an unrecognised relative command. A future
        // collector must opt into an explicit trusted path before it can spawn.
        // Nunca usamos PATH para comandos relativos desconocidos; cualquier futuro colector debe declarar una ruta confiable.
        return UnavailableExecutable;
    }

    internal static bool IsTrustedExecutablePath(string fileName, string resolvedPath)
    {
        return TryValidateExecutablePath(fileName, resolvedPath, out _);
    }

    public static FileStream CreatePrivateFile(string path)
    {
        // Create the temporary file private from the first filesystem operation, not after writing data.
        // Creamos el temporal como privado desde la primera operación, no después de escribir datos.
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            BufferSize = 8192,
            Options = FileOptions.Asynchronous | FileOptions.SequentialScan
        };
        if (!OperatingSystem.IsWindows()) options = SetUnixPrivateMode(options);
        var stream = new FileStream(path, options);

        try
        {
            if (OperatingSystem.IsWindows()) ApplyPrivateWindowsAcl(path);
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    internal static bool TryValidateExecutablePath(string fileName, string resolvedPath, out string failure)
    {
        failure = "unknown validation failure";
        if (!Path.IsPathFullyQualified(resolvedPath))
        {
            failure = "path is not absolute";
            return false;
        }

        if (!File.Exists(resolvedPath))
        {
            failure = "file is missing";
            return false;
        }

        if (OperatingSystem.IsWindows())
        {
            var finalPath = ResolveFinalPath(resolvedPath);
            if (!TrustedWindowsCandidates(fileName).Select(ResolveFinalPath).Contains(finalPath, StringComparer.OrdinalIgnoreCase))
            {
                failure = "outside the trusted Windows tool locations";
                return false;
            }

            if (!ValidateNoReparsePoints(finalPath, out failure)) return false;
            return ValidateWindowsAclChain(finalPath, out failure);
        }

        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            var finalPath = ResolveFinalPath(resolvedPath);
            var trustedCandidates = (OperatingSystem.IsMacOS() ? TrustedMacCandidates(fileName) : TrustedLinuxCandidates(fileName))
                .Select(ResolveFinalPath)
                .ToArray();
            if (!trustedCandidates.Contains(finalPath, StringComparer.Ordinal))
            {
                failure = "outside the trusted Linux system locations";
                return false;
            }

            return ValidateUnixPath(finalPath, out failure);
        }

        failure = "unsupported operating system";
        return false;
    }

    private static string[] TrustedLinuxCandidates(string fileName) => Path.GetFileName(fileName) switch
    {
        "aws" => ["/usr/local/bin/aws", "/usr/bin/aws", "/opt/aws-cli/bin/aws"],
        "gcloud" => ["/usr/bin/gcloud", "/usr/local/bin/gcloud", "/opt/google-cloud-sdk/bin/gcloud", "/usr/lib/google-cloud-sdk/bin/gcloud"],
        "oci" => ["/usr/local/bin/oci", "/usr/bin/oci", "/opt/oci/bin/oci"],
        "openstack" => ["/usr/bin/openstack", "/usr/local/bin/openstack"],
        "aliyun" => ["/usr/local/bin/aliyun", "/usr/bin/aliyun"],
        "azcmagent" => ["/opt/azcmagent/bin/azcmagent", "/usr/bin/azcmagent"],
        "az" => ["/usr/bin/az", "/usr/local/bin/az", "/opt/az/bin/az"],
        "dpkg-query" => ["/usr/bin/dpkg-query", "/bin/dpkg-query"],
        "apt" => ["/usr/bin/apt"],
        "dnf" => ["/usr/bin/dnf"],
        "passwd" => ["/usr/bin/passwd", "/bin/passwd"],
        "rpm" => ["/usr/bin/rpm", "/bin/rpm"],
        "getent" => ["/usr/bin/getent", "/bin/getent"],
        "id" => ["/usr/bin/id", "/bin/id"],
        "crontab" => ["/usr/bin/crontab", "/bin/crontab"],
        "openssl" => ["/usr/bin/openssl", "/bin/openssl"],
        "ss" => ["/usr/bin/ss", "/usr/sbin/ss", "/bin/ss"],
        "systemctl" => ["/usr/bin/systemctl", "/bin/systemctl"],
        "ip" => ["/usr/bin/ip", "/usr/sbin/ip", "/bin/ip"],
        "lsof" => ["/usr/bin/lsof", "/usr/sbin/lsof", "/bin/lsof"],
        "journalctl" => ["/usr/bin/journalctl", "/bin/journalctl"],
        "resolvectl" => ["/usr/bin/resolvectl", "/bin/resolvectl"],
        "ufw" => ["/usr/sbin/ufw", "/usr/bin/ufw"],
        "firewall-cmd" => ["/usr/bin/firewall-cmd", "/bin/firewall-cmd"],
        "nft" => ["/usr/sbin/nft", "/usr/bin/nft"],
        _ => []
    };

    private static string[] TrustedWindowsCandidates(string name)
    {
        var binary = Path.GetFileName(name);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (binary is "gcloud" or "oci" or "openstack" or "aliyun")
            return [Path.Combine(programFiles, "Opscope", "CloudTools", binary + ".exe")];
        if (binary is "aws" or "aws.exe") return [Path.Combine(programFiles, "Amazon", "AWSCLIV2", "aws.exe")];
        if (binary is "azcmagent" or "azcmagent.exe") return [Path.Combine(programFiles, "AzureConnectedMachineAgent", "azcmagent.exe")];
        if (binary == "azure-python") return [Path.Combine(programFiles, "Microsoft SDKs", "Azure", "CLI2", "python.exe")];
        var systemTools = new[] { "netstat", "netsh", "sc.exe", "tasklist.exe", "wevtutil.exe", "schtasks.exe", "net.exe", "systeminfo.exe", "certutil.exe", "reg.exe" };
        return systemTools.Contains(binary, StringComparer.OrdinalIgnoreCase)
            ? [Path.Combine(Environment.SystemDirectory, binary.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? binary : binary + ".exe")]
            : [];
    }

    private static string[] TrustedMacCandidates(string name) => Path.GetFileName(name) switch
    {
        "top" => ["/usr/bin/top"], "log" => ["/usr/bin/log"], "vm_stat" => ["/usr/bin/vm_stat"], "socketfilterfw" => ["/usr/libexec/ApplicationFirewall/socketfilterfw"], "pfctl" => ["/sbin/pfctl"], "sysctl" => ["/usr/sbin/sysctl"], "ps" => ["/bin/ps"],
        "lsof" => ["/usr/sbin/lsof"], "launchctl" => ["/bin/launchctl"], "sw_vers" => ["/usr/bin/sw_vers"],
        "system_profiler" => ["/usr/sbin/system_profiler"], "pkgutil" => ["/usr/sbin/pkgutil"], "softwareupdate" => ["/usr/sbin/softwareupdate"],
        "dscl" => ["/usr/bin/dscl"], "crontab" => ["/usr/bin/crontab"], "openssl" => ["/usr/bin/openssl"],
        "gcloud" => ["/usr/local/bin/gcloud", "/opt/homebrew/bin/gcloud", "/opt/google-cloud-sdk/bin/gcloud"],
        "oci" => ["/usr/local/bin/oci", "/opt/homebrew/bin/oci"],
        "openstack" => ["/usr/local/bin/openstack", "/opt/homebrew/bin/openstack"],
        "aliyun" => ["/usr/local/bin/aliyun", "/opt/homebrew/bin/aliyun"],
        "aws" => ["/usr/local/bin/aws", "/opt/homebrew/bin/aws"], "az" => ["/usr/local/bin/az", "/opt/homebrew/bin/az"],
        _ => []
    };

    private static string ResolveFinalPath(string path)
    {
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            var canonical = RealPath(path, IntPtr.Zero);
            if (canonical != IntPtr.Zero)
            {
                try { return Marshal.PtrToStringUTF8(canonical) ?? Path.GetFullPath(path); }
                finally { Free(canonical); }
            }
        }
        return Path.GetFullPath(path);
    }

    [SuppressMessage("Globalization", "CA2101", Justification = "libc filesystem paths use UTF-8, explicitly marshalled as LPUTF8Str.")]
    [DllImport("libc", EntryPoint = "realpath", SetLastError = true)]
    private static extern IntPtr RealPath([MarshalAs(UnmanagedType.LPUTF8Str)] string path, IntPtr resolvedPath);
    [DllImport("libc", EntryPoint = "free")]
    private static extern void Free(IntPtr value);

    [UnsupportedOSPlatform("windows")]
    private static bool ValidateUnixPath(string path, out string failure)
    {
        failure = string.Empty;
        if (!TryGetUnixOwner(path, out var owner) || owner != 0)
        {
            failure = "file is not owned by root or ownership could not be verified";
            return false;
        }

        var mode = File.GetUnixFileMode(path);
        if (mode.HasFlag(UnixFileMode.GroupWrite) || mode.HasFlag(UnixFileMode.OtherWrite))
        {
            failure = "file is writable by a non-owner";
            return false;
        }

        var executeBits = UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;
        if ((mode & executeBits) == 0)
        {
            failure = "file is not executable";
            return false;
        }

        for (var directory = Directory.GetParent(path); directory is not null; directory = directory.Parent)
        {
            if (!TryGetUnixOwner(directory.FullName, out var directoryOwner) || directoryOwner != 0)
            {
                failure = $"parent directory is not owned by root: {directory.FullName}";
                return false;
            }

            var directoryMode = File.GetUnixFileMode(directory.FullName);
            if (directoryMode.HasFlag(UnixFileMode.GroupWrite) || directoryMode.HasFlag(UnixFileMode.OtherWrite))
            {
                failure = $"parent directory is writable by a non-owner: {directory.FullName}";
                return false;
            }

            if (directory.FullName == directory.Root.FullName) break;
        }

        return true;
    }

    private static bool ValidateNoReparsePoints(string path, out string failure)
    {
        failure = string.Empty;
        for (var current = new FileInfo(path).Directory; current is not null; current = current.Parent)
        {
            if (current.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                failure = $"reparse point in trusted path: {current.FullName}";
                return false;
            }

            if (current.Parent is null) break;
        }

        if (File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
        {
            failure = "executable is a reparse point";
            return false;
        }

        return true;
    }

    [SupportedOSPlatform("windows")]
    private static bool ValidateWindowsAcl(string path, out string failure)
    {
        failure = string.Empty;
        try
        {
            return ValidateWindowsSecurity(new FileInfo(path).GetAccessControl(), isDirectory: false, out failure);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SystemException)
        {
            failure = $"ACL inspection failed: {ex.Message}";
            return false;
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool ValidateWindowsAclChain(string path, out string failure)
    {
        if (!ValidateWindowsAcl(path, out failure)) return false;
        for (var directory = new FileInfo(path).Directory; directory is not null; directory = directory.Parent)
        {
            try
            {
                if (!ValidateWindowsSecurity(directory.GetAccessControl(), isDirectory: true, out failure))
                {
                    failure = $"Parent directory {directory.FullName}: {failure}";
                    return false;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SystemException)
            {
                failure = $"Parent directory ACL inspection failed: {ex.Message}";
                return false;
            }

            if (directory.Parent is null) break;
        }

        return true;
    }

    [SupportedOSPlatform("windows")]
    private static bool ValidateWindowsSecurity(FileSystemSecurity security, bool isDirectory, out string failure)
    {
        failure = string.Empty;
        try
        {
            var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (owner is null)
            {
                failure = "file owner could not be verified";
                return false;
            }

            var trustedInstaller = new SecurityIdentifier("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
            if (!owner.IsWellKnown(WellKnownSidType.LocalSystemSid) && !owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) && !owner.Equals(trustedInstaller))
            {
                failure = "owner is not a privileged system identity";
                return false;
            }
            var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
            var privileged = new[]
            {
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                owner
            };
            // For directories, creating a sibling is not enough to replace a trusted child; deletion or ACL changes are.
            // En directorios, crear un hermano no basta para sustituir un hijo confiable; borrar o cambiar ACL sí.
            var writeRights = isDirectory
                ? FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership
                : FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
                  FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType == AccessControlType.Allow &&
                    !rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly) &&
                    ((rule.FileSystemRights & writeRights) != 0 || rule.FileSystemRights.HasFlag(FileSystemRights.FullControl)) &&
                    rule.IdentityReference is SecurityIdentifier sid &&
                    !privileged.Any(principal => principal.Equals(sid)))
                {
                    failure = $"ACL grants write access to non-privileged identity: {sid.Value}";
                    return false;
                }
            }

            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SystemException)
        {
            failure = $"ACL inspection failed: {ex.Message}";
            return false;
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ApplyPrivateWindowsAcl(string path)
    {
        var identity = WindowsIdentity.GetCurrent().User ?? throw new UnauthorizedAccessException("Current Windows identity is unavailable.");
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl, AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }

    [UnsupportedOSPlatform("windows")]
    private static FileStreamOptions SetUnixPrivateMode(FileStreamOptions options)
    {
        options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        return options;
    }

    [SuppressMessage("Globalization", "CA2101", Justification = "libc filesystem paths use UTF-8, explicitly marshalled as LPUTF8Str.")]
    [DllImport("libc", EntryPoint = "statx", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    private static extern int Statx(int dirfd, [MarshalAs(UnmanagedType.LPUTF8Str)] string pathname, int flags, uint mask, ref LinuxStatx buffer);

    [SuppressMessage("Globalization", "CA2101", Justification = "Darwin filesystem paths use UTF-8, explicitly marshalled as LPUTF8Str.")]
    [DllImport("libc", EntryPoint = "lstat", SetLastError = true)]
    private static extern int DarwinLstat([MarshalAs(UnmanagedType.LPUTF8Str)] string path, IntPtr buffer);

    private static bool TryGetUnixOwner(string path, out uint owner)
    {
        owner = uint.MaxValue;
        if (OperatingSystem.IsMacOS())
        {
            var buffer = Marshal.AllocHGlobal(256);
            try
            {
                if (DarwinLstat(path, buffer) != 0) return false;
                owner = unchecked((uint)Marshal.ReadInt32(buffer, 16));
                return true;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        var stat = new LinuxStatx { Spare = new ulong[14] };
        if (Statx(-100, path, 0x100, 0x1F, ref stat) != 0) return false;
        owner = stat.Uid;
        return true;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxStatx
    {
        public uint Mask;
        public uint BlockSize;
        public ulong Attributes;
        public uint LinkCount;
        public uint Uid;
        public uint Gid;
        public ushort Mode;
        public ushort Padding;
        public ulong Inode;
        public ulong Size;
        public ulong Blocks;
        public ulong AttributesMask;
        public LinuxStatxTimestamp AccessTime;
        public LinuxStatxTimestamp BirthTime;
        public LinuxStatxTimestamp ChangeTime;
        public LinuxStatxTimestamp ModifyTime;
        public uint DeviceMajor;
        public uint DeviceMinor;
        public uint MountMajor;
        public uint MountMinor;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 14)]
        public ulong[] Spare;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxStatxTimestamp
    {
        public long Seconds;
        public uint Nanoseconds;
        public int Padding;
    }
}

