using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace Opscope;

internal static class CommandRunner
{
    // Bound child-process output to avoid memory exhaustion from a broken or hostile utility.
    // Limitamos la salida de procesos hijos para evitar agotamiento de memoria por una herramienta defectuosa u hostil.
    private const int MaxOutputChars = 256 * 1024;
    private static readonly string UnavailableExecutable = OperatingSystem.IsWindows()
        ? Path.Combine(Environment.SystemDirectory, "opscope-unavailable.exe")
        : "/opscope-unavailable";

    public static async Task<CommandResult> RunAsync(string fileName, IEnumerable<string> arguments, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
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

        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        using var readerCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task<(string Text, bool Truncated)>? stdoutTask = null;
        Task<(string Text, bool Truncated)>? stderrTask = null;
        try
        {
            if (!process.Start())
            {
                return new CommandResult(-1, string.Empty, "Process did not start", false);
            }

            stdoutTask = ReadLimitedAsync(process.StandardOutput, readerCts.Token);
            stderrTask = ReadLimitedAsync(process.StandardError, readerCts.Token);
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

    private static async Task<(string Text, bool Truncated)> ReadLimitedAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        var buffer = new char[8192];
        var output = new StringBuilder(Math.Min(MaxOutputChars, 32 * 1024));
        var truncated = false;
        int read;
        try
        {
            while ((read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken)) > 0)
            {
                if (output.Length >= MaxOutputChars)
                {
                    truncated = true;
                    continue;
                }

                var remaining = MaxOutputChars - output.Length;
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

        if (OperatingSystem.IsWindows() && fileName is "netstat" or "netsh" or "sc.exe" or "tasklist.exe" or "wevtutil.exe")
            return Path.Combine(Environment.SystemDirectory, fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? fileName : $"{fileName}.exe");

        if (OperatingSystem.IsLinux())
        {
            var candidates = TrustedLinuxCandidates(fileName);
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

    internal static FileStream CreatePrivateFile(string path)
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
        if (OperatingSystem.IsLinux()) options = SetUnixPrivateMode(options);
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
            var systemDirectory = Path.GetFullPath(Environment.SystemDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var expectedName = fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? fileName : $"{fileName}.exe";
            var finalPath = ResolveFinalPath(resolvedPath);
            if (!finalPath.StartsWith(systemDirectory, StringComparison.OrdinalIgnoreCase) ||
                !Path.GetFileName(finalPath).Equals(expectedName, StringComparison.OrdinalIgnoreCase))
            {
                failure = "outside the trusted Windows system directory";
                return false;
            }

            if (!ValidateNoReparsePoints(finalPath, out failure)) return false;
            return ValidateWindowsAclChain(finalPath, out failure);
        }

        if (OperatingSystem.IsLinux())
        {
            var finalPath = ResolveFinalPath(resolvedPath);
            var trustedCandidates = TrustedLinuxCandidates(fileName)
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

    private static string ResolveFinalPath(string path)
    {
        try
        {
            return File.ResolveLinkTarget(path, returnFinalTarget: true)?.FullName ?? Path.GetFullPath(path);
        }
        catch
        {
            return Path.GetFullPath(path);
        }
    }

    [SupportedOSPlatform("linux")]
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

    [SupportedOSPlatform("linux")]
    private static FileStreamOptions SetUnixPrivateMode(FileStreamOptions options)
    {
        options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        return options;
    }

    [DllImport("libc", EntryPoint = "statx", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    private static extern int Statx(int dirfd, string pathname, int flags, uint mask, ref LinuxStatx buffer);

    private static bool TryGetUnixOwner(string path, out uint owner)
    {
        owner = uint.MaxValue;
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

