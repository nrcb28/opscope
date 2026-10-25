using Opscope;

internal static class Program
{
    private static async Task<int> Main()
    {
        Assert(SystemProbe.ParseUfwState("Status: active\n").State == "ACTIVE", "English UFW active state");
        Assert(SystemProbe.ParseUfwState("Status: inactive\n").State == "INACTIVE", "English UFW inactive state");
        Assert(SystemProbe.ParseUfwState("Estado: activo\n").State == "ACTIVE", "Spanish UFW active state");
        Assert(SystemProbe.ParseUfwState("Estado: inactivo\n").State == "INACTIVE", "Spanish UFW inactive state");
        Assert(SystemProbe.ParseUfwState("Status: pending\n").State == "UNKNOWN", "Unknown UFW state");

        var nft = SystemProbe.ParseNftablesState("""
            table inet filter {
                chain input {
                    type filter hook input priority filter; policy drop;
                }
            }
            """);
        Assert(nft.State == "ACTIVE" && nft.RulesPresent && nft.FilteringVerified, "nftables filtering verification");
        var outputOnlyNft = SystemProbe.ParseNftablesState("""
            table inet filter {
                chain output {
                    type filter hook output priority filter; policy drop;
                }
            }
            """);
        Assert(outputOnlyNft.State == "UNVERIFIED" && !outputOnlyNft.FilteringVerified, "nftables output-only rules are not inbound protection");
        var loopbackOnlyNft = SystemProbe.ParseNftablesState("""
            table inet filter {
                chain input {
                    type filter hook input priority filter; policy accept;
                    iifname "lo" drop;
                }
            }
            """);
        Assert(loopbackOnlyNft.State == "UNVERIFIED" && !loopbackOnlyNft.FilteringVerified, "nftables loopback-only rules are not inbound protection");

        var lsofListeners = new List<ListenerInfo>();
        SystemProbe.AddLsofListeners("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nsshd 123 root 3u IPv4 123 0t0 TCP *:22 (LISTEN)\n", lsofListeners);
        Assert(lsofListeners.Count == 1 && lsofListeners[0].Protocol == "TCP" && lsofListeners[0].LocalAddress == "*:22", "lsof listener fallback parser");

        var unsafePath = Path.GetTempFileName();
        try
        {
            Assert(!CommandRunner.TryValidateExecutablePath(OperatingSystem.IsWindows() ? "netsh" : "ss", unsafePath, out _), "unsafe executable is blocked");
            var blocked = await CommandRunner.RunAsync(unsafePath, Array.Empty<string>(), TimeSpan.FromSeconds(1));
            Assert(blocked.ExitCode == -1 && blocked.StandardError.Contains("rejected", StringComparison.OrdinalIgnoreCase), "unsafe executable is not started");
        }
        finally
        {
            File.Delete(unsafePath);
        }

        var outputPath = Path.Combine(Path.GetTempPath(), $"opscope-test-{Guid.NewGuid():N}.json");
        try
        {
            await Reporter.WriteTextAtomicallyAsync(outputPath, "private evidence", CancellationToken.None);
            if (OperatingSystem.IsLinux())
            {
                var mode = File.GetUnixFileMode(outputPath);
                Assert((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.OtherRead | UnixFileMode.OtherWrite)) == 0, "private Unix output mode");
            }
            else if (OperatingSystem.IsWindows())
            {
                Assert(new FileInfo(outputPath).GetAccessControl().AreAccessRulesProtected, "private Windows output ACL");
            }
        }
        finally
        {
            File.Delete(outputPath);
        }

        var baseline = CreateSnapshot("host-a", "customer-backend", "10.20.30.40", "/srv/clientes/acme");
        var current = CreateSnapshot("host-b", "customer-backend", "10.20.30.41", "/srv/clientes/acme");
        var diff = DiffEngine.Compare(baseline, current);
        var safeDiff = Reporter.RedactForOutput(diff);
        Assert(diff.Significant && safeDiff.Significant, "redaction preserves diff significance");
        var safeDiffJson = Reporter.ToJson(safeDiff);
        Assert(!safeDiffJson.Contains("host-b", StringComparison.Ordinal), "diff redaction removes prior hostnames");
        Assert(!safeDiffJson.Contains("10.20.30.41", StringComparison.Ordinal), "diff redaction removes listener addresses");
        Assert(!safeDiffJson.Contains("customer-backend", StringComparison.Ordinal), "diff redaction removes service identities");
        var safeJson = Reporter.ToJson(Reporter.RedactForOutput(current));
        Assert(!safeJson.Contains("10.20.30.41", StringComparison.Ordinal), "redaction removes IP addresses");
        Assert(!safeJson.Contains("/srv/clientes/acme", StringComparison.Ordinal), "redaction removes Unix paths");
        Assert(!safeJson.Contains("customer-backend", StringComparison.Ordinal), "redaction removes free-text service identifiers");
        Assert(safeJson.Contains("ss timed out", StringComparison.Ordinal), "redaction preserves collection warnings");
        Assert(Reporter.ToDoctorJson(current, redact: true).Contains("\"status\": \"incomplete\"", StringComparison.Ordinal), "redacted doctor preserves incomplete state");

        Console.WriteLine("Opscope regression tests passed");
        return 0;
    }

    private static Snapshot CreateSnapshot(string hostName, string serviceName, string address, string description) =>
        new(
            DateTimeOffset.UtcNow,
            new HostInfo(hostName, "Linux", "linux", "X64", ".NET 8", "kernel", DateTimeOffset.UtcNow, TimeSpan.Zero, false, 1, "operator"),
            1,
            new MemoryInfo(100, 50, 50, 50, "test"),
            Array.Empty<DiskInfo>(),
            Array.Empty<NetworkAdapter>(),
            [new ProcessInfo(1, "opscope", "operator", 1, 1, TimeSpan.Zero, $"--backend={address} {description}", false)],
            [new ListenerInfo("TCP", address, "pid=1", "test")],
            [new ServiceInfo(serviceName, "failed/failed", description, "systemctl")],
            new SecurityPosture(Array.Empty<FirewallProfile>(), false, false, 0),
            new ToolingPosture(Array.Empty<ToolInfo>()),
            [new Finding(FindingSeverity.Warning, "TEST", "Backend 10.20.30.41", description, "password=secret")],
            [$"ss timed out on {hostName} while reading /data/clientes/acme"],
            TimeSpan.Zero);

    private static void Assert(bool condition, string name)
    {
        if (!condition) throw new InvalidOperationException($"Regression test failed: {name}");
    }
}
