using System.Reflection;
using System.Text;

namespace Opscope;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            // Keep command dispatch centralized so every mode shares the same cancellation and error policy.
            // Centralizamos el despacho para que todos los modos compartan cancelación y tratamiento de errores.
            var options = CliOptions.Parse(args);
            if (options.ShowHelp)
            {
                Console.WriteLine(CliOptions.Usage);
                return 0;
            }

            if (options.Command.Equals("version", StringComparison.OrdinalIgnoreCase))
            {
                PrintVersion();
                return 0;
            }

            if (options.Command.Equals("tools", StringComparison.OrdinalIgnoreCase))
            {
                var tooling = ToolInventory.Collect();
                if (options.Json) Console.WriteLine(Reporter.ToJson(tooling, options.Redact));
                else Reporter.PrintTools(options.Redact ? Reporter.RedactForOutput(tooling) : tooling);
                return tooling.Tools.Any(tool => tool.Available && !tool.Security.Equals("secure", StringComparison.OrdinalIgnoreCase)) ? 1 : 0;
            }

            using var cancellation = new CancellationTokenSource();
            Console.CancelKeyPress += (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                cancellation.Cancel();
            };

            if (options.Command.Equals("watch", StringComparison.OrdinalIgnoreCase))
                return await WatchAsync(options, cancellation.Token);

            if (options.Command.Equals("diff", StringComparison.OrdinalIgnoreCase))
            {
                var baselineJson = await ReadSnapshotTextAsync(options.BaselinePath!, cancellation.Token);
                var baseline = Reporter.ParseSnapshot(baselineJson);
                var current = await SystemProbe.CollectAsync(options.ToCollectorOptions(), cancellation.Token);
                var report = DiffEngine.Compare(
                    options.Redact ? Reporter.RedactForOutput(baseline) : baseline,
                    options.Redact ? Reporter.RedactForOutput(current) : current);
                if (options.OutputPath is not null)
                {
                    var fullPath = Path.GetFullPath(options.OutputPath);
                    await Reporter.WriteTextAtomicallyAsync(fullPath, Reporter.ToJson(report), cancellation.Token);
                    Console.Error.WriteLine($"Wrote {fullPath}");
                }
                if (options.Json) Console.WriteLine(Reporter.ToJson(report));
                else Reporter.PrintDiff(report);
                return report.Significant ? 1 : 0;
            }

            var snapshot = await SystemProbe.CollectAsync(options.ToCollectorOptions(), cancellation.Token);
            return options.Command.ToLowerInvariant() switch
            {
                "snapshot" => await SnapshotAsync(snapshot, options, cancellation.Token),
                "doctor" => await DoctorAsync(snapshot, options, cancellation.Token),
                "bundle" => await BundleAsync(snapshot, options, cancellation.Token),
                _ => throw new CliException($"Unknown command '{options.Command}'. Use --help for usage.")
            };
        }
        catch (CliException ex)
        {
            Console.Error.WriteLine($"error: {Reporter.SafeDisplay(ex.Message)}");
            Console.Error.WriteLine("Use 'opscope --help' for usage.");
            return 2;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Collection cancelled.");
            return 2;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"fatal: {Reporter.SafeDisplay(ex.Message)}");
            return 2;
        }
    }

    private static async Task<int> SnapshotAsync(Snapshot snapshot, CliOptions options, CancellationToken cancellationToken)
    {
        var outputSnapshot = options.Redact ? Reporter.RedactForOutput(snapshot) : snapshot;
        if (options.OutputPath is not null)
        {
            await Reporter.WriteJsonAsync(options.OutputPath, outputSnapshot, redact: false, cancellationToken);
            Console.Error.WriteLine($"Wrote {Reporter.SafeDisplay(Path.GetFullPath(options.OutputPath))}");
        }
        if (options.Json) Console.WriteLine(Reporter.ToJson(outputSnapshot));
        else Reporter.PrintSnapshot(outputSnapshot);
        return Reporter.ExitCode(snapshot);
    }

    private static Task<int> DoctorAsync(Snapshot snapshot, CliOptions options, CancellationToken cancellationToken)
    {
        var outputSnapshot = options.Redact ? Reporter.RedactForOutput(snapshot) : snapshot;
        if (options.OutputPath is not null)
            return WriteDoctorOutputAsync(outputSnapshot, options.OutputPath, options.Json, cancellationToken);
        if (options.Json) Console.WriteLine(Reporter.ToDoctorJson(outputSnapshot));
        else
        {
            Console.WriteLine($"opscope doctor | {Reporter.SafeDisplay(outputSnapshot.Host.Hostname)} | {DateTimeOffset.UtcNow:O}");
            Reporter.PrintFindings(outputSnapshot.Findings, outputSnapshot.CollectionWarnings);
        }
        return Task.FromResult(Reporter.ExitCode(snapshot));
    }

    private static async Task<int> WriteDoctorOutputAsync(Snapshot snapshot, string path, bool json, CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(parent)) Directory.CreateDirectory(parent);
        await Reporter.WriteTextAtomicallyAsync(fullPath, Reporter.ToDoctorJson(snapshot), cancellationToken);
        Console.Error.WriteLine($"Wrote {Reporter.SafeDisplay(fullPath)}");
        if (!json) Reporter.PrintFindings(snapshot.Findings, snapshot.CollectionWarnings);
        return Reporter.ExitCode(snapshot);
    }

    private static async Task<int> BundleAsync(Snapshot snapshot, CliOptions options, CancellationToken cancellationToken)
    {
        var path = options.OutputPath ?? $"opscope-{DateTime.UtcNow:yyyyMMdd-HHmmss}.zip";
        var fullPath = await Reporter.WriteBundleAsync(path, snapshot, cancellationToken);
        if (options.Json)
            Console.WriteLine($"{{\"bundle\":{System.Text.Json.JsonSerializer.Serialize(fullPath)},\"findings\":{snapshot.Findings.Count}}}");
        else
        {
            Console.WriteLine($"Bundle written: {Reporter.SafeDisplay(fullPath)}");
            Reporter.PrintFindings(snapshot.Findings, snapshot.CollectionWarnings);
        }
        return Reporter.ExitCode(snapshot);
    }

    private static async Task<int> WatchAsync(CliOptions options, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var snapshot = await SystemProbe.CollectAsync(options.ToCollectorOptions(), cancellationToken);
            if (!Console.IsOutputRedirected) Console.Clear();
            Reporter.PrintDashboard(options.Redact ? Reporter.RedactForOutput(snapshot) : snapshot);
            try { await Task.Delay(options.Interval, cancellationToken); }
            catch (OperationCanceledException) { break; }
        }
        return 0;
    }

    private static async Task<string> ReadSnapshotTextAsync(string path, CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
        // Baselines are untrusted input: cap their size before parsing to limit resource consumption.
        // Las líneas base son entradas no confiables: limitamos su tamaño antes de analizarlas.
        const long maxSnapshotBytes = 16 * 1024 * 1024;
        if (!File.Exists(fullPath)) throw new CliException($"Baseline snapshot was not found: {fullPath}");
        await using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read, 8192, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length > maxSnapshotBytes) throw new CliException($"Baseline snapshot exceeds the {maxSnapshotBytes / 1024 / 1024} MiB safety limit.");

        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var content = new StringBuilder((int)Math.Min(stream.Length, maxSnapshotBytes));
        var buffer = new char[8192];
        int read;
        while ((read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken)) > 0)
        {
            if (content.Length + read > maxSnapshotBytes) throw new CliException($"Baseline snapshot exceeds the {maxSnapshotBytes / 1024 / 1024} MiB safety limit.");
            content.Append(buffer, 0, read);
        }
        return content.ToString();
    }

    private static void PrintVersion()
    {
        var assembly = Assembly.GetExecutingAssembly();
        Console.WriteLine($"opscope {assembly.GetName().Version?.ToString(3) ?? "0.1.0"}");
        Console.WriteLine($"runtime {Environment.Version} | {System.Runtime.InteropServices.RuntimeInformation.OSDescription.Trim()}");
    }
}

internal sealed class CliException(string message) : Exception(message);

internal sealed class CliOptions
{
    public const string Usage = """
opscope — cross-platform systems operations CLI

Usage:
  opscope snapshot [options]       Full host snapshot
  opscope doctor [options]         Actionable findings and exit status
  opscope bundle [options]         Redacted ZIP support bundle
  opscope watch [options]          Live health dashboard
  opscope diff <snapshot.json>     Compare a baseline against the current host
  opscope tools [options]          Inspect diagnostic tools and trust status
  opscope version                  Build/runtime information

Options:
  --json                  Emit machine-readable JSON
  --redact                Omit command lines and redact host/user/network/path data
  --out <path>            Write JSON or ZIP to this path
  --top <n>               Number of processes to retain (default: 20)
  --interval <seconds>    Watch refresh interval (default: 5)
  --no-processes          Skip process collection
  --no-network            Skip adapters and listeners
  --no-services           Skip service inventory
  --help                  Show this help

Exit codes: 0 healthy, 1 warning/critical finding, 2 CLI/collection error.
""";

    public string Command { get; private set; } = "snapshot";
    public bool Json { get; private set; }
    public bool Redact { get; private set; }
    public bool ShowHelp { get; private set; }
    public string? OutputPath { get; private set; }
    public string? BaselinePath { get; private set; }
    public int TopProcesses { get; private set; } = 20;
    public TimeSpan Interval { get; private set; } = TimeSpan.FromSeconds(5);
    public bool IncludeProcesses { get; private set; } = true;
    public bool IncludeNetwork { get; private set; } = true;
    public bool IncludeServices { get; private set; } = true;

    public static CliOptions Parse(string[] args)
    {
        // Parse only known options; rejecting unknown flags avoids silently changing collection behavior.
        // Solo aceptamos opciones conocidas para no cambiar silenciosamente el comportamiento de recopilación.
        var result = new CliOptions();
        var index = 0;
        if (args.Length > 0 && !args[0].StartsWith('-')) result.Command = args[index++];
        if (result.Command.Equals("diff", StringComparison.OrdinalIgnoreCase) && index < args.Length && !args[index].StartsWith('-'))
            result.BaselinePath = args[index++];
        while (index < args.Length)
        {
            switch (args[index++])
            {
                case "--help": case "-h": result.ShowHelp = true; break;
                case "--version": result.Command = "version"; break;
                case "--json": result.Json = true; break;
                case "--redact": result.Redact = true; break;
                case "--no-processes": result.IncludeProcesses = false; break;
                case "--no-network": result.IncludeNetwork = false; break;
                case "--no-services": result.IncludeServices = false; break;
                case "--out": result.OutputPath = Next(args, ref index, "--out"); break;
                case "--top": result.TopProcesses = ParsePositiveInt(Next(args, ref index, "--top"), "--top", 200); break;
                case "--interval":
                    var seconds = ParsePositiveInt(Next(args, ref index, "--interval"), "--interval", 3600);
                    result.Interval = TimeSpan.FromSeconds(seconds);
                    break;
                default: throw new CliException($"Unknown option '{args[index - 1]}'.");
            }
        }
        if (result.Command is not ("snapshot" or "doctor" or "bundle" or "watch" or "diff" or "tools" or "version"))
            throw new CliException($"Unknown command '{result.Command}'.");
        if (!result.ShowHelp && result.Command.Equals("diff", StringComparison.OrdinalIgnoreCase) && string.IsNullOrWhiteSpace(result.BaselinePath))
            throw new CliException("diff requires a baseline snapshot path.");
        return result;
    }

    public CollectorOptions ToCollectorOptions() => new(IncludeProcesses, IncludeNetwork, IncludeServices, TopProcesses);

    private static string Next(string[] args, ref int index, string option)
    {
        if (index >= args.Length || args[index].StartsWith('-')) throw new CliException($"{option} requires a value.");
        return args[index++];
    }

    private static int ParsePositiveInt(string value, string option, int max)
    {
        if (!int.TryParse(value, out var parsed) || parsed < 1 || parsed > max) throw new CliException($"{option} must be an integer between 1 and {max}.");
        return parsed;
    }
}

