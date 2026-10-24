using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace Opscope;

internal static class CommandRunner
{
    private const int MaxOutputChars = 256 * 1024;

    public static async Task<CommandResult> RunAsync(string fileName, IEnumerable<string> arguments, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = ResolveExecutable(fileName),
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
                try { process.Kill(entireProcessTree: true); } catch { /* best effort */ }
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
            try { process.Kill(entireProcessTree: true); } catch { /* best effort */ }
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

    private static string ResolveExecutable(string fileName)
    {
        if (Path.IsPathFullyQualified(fileName)) return fileName;

        if (OperatingSystem.IsWindows() && fileName is "netstat" or "netsh" or "sc.exe")
            return Path.Combine(Environment.SystemDirectory, fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? fileName : $"{fileName}.exe");

        if (OperatingSystem.IsLinux())
        {
            var candidates = fileName switch
            {
                "ss" => new[] { "/usr/bin/ss", "/usr/sbin/ss", "/bin/ss" },
                "systemctl" => new[] { "/usr/bin/systemctl", "/bin/systemctl" },
                "ufw" => new[] { "/usr/sbin/ufw", "/usr/bin/ufw" },
                "firewall-cmd" => new[] { "/usr/bin/firewall-cmd", "/bin/firewall-cmd" },
                "nft" => new[] { "/usr/sbin/nft", "/usr/bin/nft" },
                _ => Array.Empty<string>()
            };
            var resolved = candidates.FirstOrDefault(File.Exists);
            if (resolved is not null) return resolved;
            if (candidates.Length > 0) return $"/opscope-unavailable/{fileName}";
        }

        return fileName;
    }
}

