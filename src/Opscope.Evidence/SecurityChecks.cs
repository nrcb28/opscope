using System.Globalization;
using System.Net;
using Microsoft.Win32;

namespace Opscope.Evidence;

public static partial class EvidenceCollector
{
    public static AnalysisReport EvaluateSnapshotSecurity(Snapshot snapshot)
    {
        var findings = new List<Finding>();
        var coverage = new List<CheckCoverage>();
        foreach (var port in new[] { 22, 3389 })
        {
            var listeners = snapshot.Listeners.Where(listener => TryGetEndpoint(listener.LocalAddress, out var address, out var number)
                && number == port && !IsLoopback(address)).ToArray();
            var code = port == 22 ? "SSH_NON_LOOPBACK_LISTENER" : "RDP_NON_LOOPBACK_LISTENER";
            if (listeners.Length > 0)
                findings.Add(new Finding(FindingSeverity.Warning, code, $"{(port == 22 ? "SSH" : "RDP")} listens outside loopback",
                    $"{listeners.Length} listener(s) on port {port}. This observes binding only; Internet reachability and firewall rules are not inferred.",
                    "Review intended management networks, host firewall and cloud security rules before changing exposure."));
            coverage.Add(new CheckCoverage(code, snapshot.Host.Platform, listeners.Length > 0 ? "fail" : "not_evaluated",
                listeners.Length > 0 ? "Non-loopback binding observed in snapshot." : "No matching listener observed; a limited snapshot does not establish absence."));
        }
        var firewallState = !snapshot.Security.FirewallStatusKnown ? "not_evaluated" : snapshot.Security.ProtectionVerified ? "pass" : !snapshot.Security.HasActiveFirewall ? "fail" : "not_evaluated";
        coverage.Add(new CheckCoverage("CIS_SUBSET_HOST_FIREWALL", snapshot.Host.Platform, firewallState,
            "Uses observed host firewall status and inbound filtering verification only.", "CIS-inspired subset; no benchmark edition or full certification claimed."));
        if (firewallState == "fail") findings.Add(new Finding(FindingSeverity.Warning, "CIS_SUBSET_HOST_FIREWALL", "No active host firewall observed",
            "The snapshot reports known firewall state without an active firewall.", "Review the applicable host firewall policy and intended inbound restrictions."));
        return new AnalysisReport("security", snapshot.CollectedAtUtc, findings, new EvidenceData([], coverage),
            ["These are selected exposure and CIS-inspired controls, not a full CIS benchmark or an Internet reachability assessment."]);
    }

    /// <summary>Static config analysis refuses to infer effective settings across Include or Match directives.</summary>
    public static CheckCoverage InspectSshConfiguration(string configuration, string platform = "linux")
    {
        var directives = configuration.Split('\n').Select(line => line.Split('#', 2)[0].Trim())
            .Where(line => line.Length > 0).Select(line => line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)).ToArray();
        if (directives.Any(parts => parts[0].Equals("Include", StringComparison.OrdinalIgnoreCase) || parts[0].Equals("Match", StringComparison.OrdinalIgnoreCase)))
            return new CheckCoverage("CIS_SUBSET_SSH_ROOT_LOGIN", platform, "not_evaluated", "Include/Match directives require effective-configuration evaluation; static analysis does not guess.");
        var directive = directives.FirstOrDefault(parts => parts[0].Equals("PermitRootLogin", StringComparison.OrdinalIgnoreCase));
        if (directive is null || directive.Length < 2)
            return new CheckCoverage("CIS_SUBSET_SSH_ROOT_LOGIN", platform, "not_evaluated", "PermitRootLogin is not explicitly configured in the inspected file.");
        return new CheckCoverage("CIS_SUBSET_SSH_ROOT_LOGIN", platform, directive[1].Equals("no", StringComparison.OrdinalIgnoreCase) ? "pass" : "fail",
            $"Static PermitRootLogin={directive[1]}; runtime flags and daemon state are outside this check.", "CIS-inspired control, static configuration only.");
    }

    private static async Task CollectSecurityAsync(Snapshot snapshot, List<EvidenceRecord> records, List<CheckCoverage> coverage,
        List<Finding> findings, List<string> warnings, CancellationToken ct)
    {
        var baseline = EvaluateSnapshotSecurity(snapshot);
        findings.AddRange(baseline.Findings);
        coverage.AddRange(((EvidenceData)baseline.Data!).Coverage);
        warnings.AddRange(baseline.Warnings ?? []);
        if (OperatingSystem.IsLinux())
        {
            var passwd = await RunAsync(snapshot, "passwd", ["-Sa"], warnings, ct);
            if (passwd.ExitCode == 0)
            {
                var empty = Lines(passwd.StandardOutput, 1000).Select(line => line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
                    .Where(parts => parts.Length > 1 && parts[1] == "NP").Select(parts => parts[0]).ToArray();
                coverage.Add(new CheckCoverage("EMPTY_PASSWORD_ACCOUNTS", "linux", empty.Length > 0 ? "fail" : "pass", $"passwd status query observed {empty.Length} accounts with NP status; no password hashes were read."));
                foreach (var account in empty)
                {
                    findings.Add(new Finding(FindingSeverity.Critical, "EMPTY_PASSWORD_ACCOUNT", "Account has no password",
                        "passwd reports NP status for a local account; the identity is in protected user metadata.", "Review whether the account can authenticate and apply the organization's account policy."));
                    records.Add(new EvidenceRecord("security", "passwd-status", "collected", "Local account password status: NP (no password).", Metadata: new Dictionary<string, string> { ["user"] = account }));
                }
            }
            else coverage.Add(new CheckCoverage("EMPTY_PASSWORD_ACCOUNTS", "linux", "not_evaluated", "passwd status unavailable or requires privilege; /etc/shadow was not read."));

            var audit = snapshot.Services.FirstOrDefault(service => service.Name.Equals("auditd", StringComparison.OrdinalIgnoreCase) || service.Name.Equals("auditd.service", StringComparison.OrdinalIgnoreCase));
            var auditActive = audit is not null && IsRunning(audit.State);
            coverage.Add(new CheckCoverage("AUDITD_SERVICE", "linux", audit is null ? "not_evaluated" : auditActive ? "pass" : "fail",
                audit is null ? "auditd not present in this snapshot." : $"Observed state: {audit.State}; audit rule coverage was not assessed."));
            if (audit is not null && !auditActive) findings.Add(new Finding(FindingSeverity.Warning, "AUDITD_NOT_RUNNING", "auditd is not running", Safe(snapshot, audit.State), "Review auditd service status and audit policy; this tool does not start services."));
            var ssh = ReadFixedFile("/etc/ssh/sshd_config", warnings);
            var sshCheck = ssh is null ? new CheckCoverage("CIS_SUBSET_SSH_ROOT_LOGIN", "linux", "not_evaluated", "sshd_config unavailable.") : InspectSshConfiguration(ssh);
            coverage.Add(sshCheck);
            if (sshCheck.State == "fail") findings.Add(new Finding(FindingSeverity.Warning, sshCheck.Code, "Root SSH login is not explicitly disabled", sshCheck.Evidence, "Review the effective SSH configuration and applicable benchmark before changing it."));
            var samba = ReadFixedFile("/etc/samba/smb.conf", warnings);
            var smb = InspectSmbConfiguration(samba);
            coverage.Add(smb);
            if (smb.State == "fail") findings.Add(new Finding(FindingSeverity.Critical, "SMB1_ENABLED", "Samba minimum protocol permits SMB1", smb.Evidence,
                "Review the effective Samba configuration, clients and supported protocol minimum; no configuration was changed."));
            await CollectLinuxPatchesAsync(snapshot, records, coverage, findings, warnings, ct);
            coverage.Add(new CheckCoverage("DEFENDER_HEALTH", "linux", "not_evaluated", "Windows Defender health is platform-specific; Linux security products are not inferred from process names."));
        }
        else if (OperatingSystem.IsWindows())
        {
            CollectWindowsSecurity(snapshot, records, coverage, findings, warnings);
            var native = await WindowsNativeSecurity.CollectAsync(snapshot, ct);
            var nativeData = (EvidenceData)native.Data!;
            records.AddRange(nativeData.Records);
            coverage.AddRange(nativeData.Coverage);
            findings.AddRange(native.Findings);
            warnings.AddRange(native.Warnings ?? []);
            coverage.Add(new CheckCoverage("AUDITD_SERVICE", "windows", "not_evaluated", "Linux-specific auditd check; Windows event evidence is available in the logs group."));
        }
        else if (OperatingSystem.IsMacOS())
        {
            var ssh = ReadFixedFile("/etc/ssh/sshd_config", warnings);
            coverage.Add(ssh is null ? new CheckCoverage("CIS_SUBSET_SSH_ROOT_LOGIN", "macos", "not_evaluated", "sshd_config unavailable.") : InspectSshConfiguration(ssh, "macos"));
            foreach (var code in new[] { "EMPTY_PASSWORD_ACCOUNTS", "SMB1", "DEFENDER_HEALTH", "AUDITD_SERVICE", "PENDING_PATCHES" })
                coverage.Add(new CheckCoverage(code, "macos", "not_evaluated", "No reliable supported offline source implemented for this control on macOS; no package-manager refresh or remote query was performed."));
        }
        else coverage.Add(new CheckCoverage("PLATFORM_SECURITY", snapshot.Host.Platform, "not_evaluated", "Unsupported platform."));
    }

    public static CheckCoverage InspectSmbConfiguration(string? configuration)
    {
        if (string.IsNullOrWhiteSpace(configuration)) return new CheckCoverage("SMB1", "linux", "not_evaluated", "Samba configuration unavailable; no default protocol version inferred.");
        var lines = configuration.Split('\n').Select(line => line.Split('#', 2)[0].Trim()).ToArray();
        if (lines.Any(line => line.StartsWith("include", StringComparison.OrdinalIgnoreCase)))
            return new CheckCoverage("SMB1", "linux", "not_evaluated", "Samba includes require effective-configuration analysis.");
        var value = lines.Where(line => line.StartsWith("server min protocol", StringComparison.OrdinalIgnoreCase)).Select(line => line.Split('=', 2)).LastOrDefault();
        if (value?.Length != 2) return new CheckCoverage("SMB1", "linux", "not_evaluated", "No explicit server min protocol found; Samba defaults are not assumed.");
        var protocol = value[1].Trim().ToUpperInvariant();
        var legacy = protocol is "NT1" or "LANMAN1" or "LANMAN2" or "CORE" or "COREPLUS";
        var modern = protocol.StartsWith("SMB2", StringComparison.Ordinal) || protocol.StartsWith("SMB3", StringComparison.Ordinal);
        return new CheckCoverage("SMB1", "linux", legacy ? "fail" : modern ? "pass" : "not_evaluated", $"Static Samba server min protocol={protocol}; active daemon configuration not queried.");
    }

    private static async Task CollectLinuxPatchesAsync(Snapshot snapshot, List<EvidenceRecord> records, List<CheckCoverage> coverage,
        List<Finding> findings, List<string> warnings, CancellationToken ct)
    {
        var apt = await RunAsync(snapshot, "apt", ["list", "--upgradable"], warnings, ct, warnOnFailure: false);
        if (apt.ExitCode == 0)
        {
            var updates = Lines(apt.StandardOutput, 1500).Where(line => line.Contains("[upgradable from:", StringComparison.OrdinalIgnoreCase)).ToArray();
            coverage.Add(new CheckCoverage("PENDING_PATCHES", "linux", updates.Length > 0 ? "fail" : "not_evaluated", $"apt local metadata contains {updates.Length} upgradable packages. Metadata was not refreshed; absence is not proof of current patch compliance."));
            AddLines(snapshot, records, "security", "apt-cached-updates", string.Join('\n', updates), 1000);
            if (updates.Length > 0) findings.Add(new Finding(FindingSeverity.Warning, "PENDING_PATCHES", "Pending package updates in local metadata", $"{updates.Length} apt packages have candidate updates in existing metadata.", "Review the package manager's update policy and metadata freshness; no refresh or installation was performed."));
            return;
        }
        var dnf = await RunAsync(snapshot, "dnf", ["--cacheonly", "--quiet", "check-update"], warnings, ct);
        if (dnf.ExitCode is 0 or 100)
        {
            coverage.Add(new CheckCoverage("PENDING_PATCHES", "linux", dnf.ExitCode == 100 ? "fail" : "not_evaluated", "dnf checked existing cached metadata only. No update refresh or package installation performed."));
            AddLines(snapshot, records, "security", "dnf-cached-updates", dnf.StandardOutput, 1000);
            if (dnf.ExitCode == 100) findings.Add(new Finding(FindingSeverity.Warning, "PENDING_PATCHES", "Pending package updates in cached metadata", "dnf check-update returned 100 using --cacheonly.", "Review candidate updates and metadata freshness under the normal patch process."));
        }
        else coverage.Add(new CheckCoverage("PENDING_PATCHES", "linux", "not_evaluated", "No readable apt/dnf cached update assessment is available."));
        warnings.Add("Patch status uses cached package metadata and may be incomplete or stale.");
    }

    private static void CollectWindowsSecurity(Snapshot snapshot, List<EvidenceRecord> records, List<CheckCoverage> coverage,
        List<Finding> findings, List<string> warnings)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            using var smb = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", writable: false);
            var setting = smb?.GetValue("SMB1");
            var state = setting is int value ? value == 0 ? "pass" : "fail" : "not_evaluated";
            coverage.Add(new CheckCoverage("SMB1", "windows", state, setting is null ? "SMB1 registry value absent; OS defaults and feature state are not inferred." : $"LanmanServer SMB1 setting={setting}."));
            if (state == "fail") findings.Add(new Finding(FindingSeverity.Critical, "SMB1_ENABLED", "SMB1 is explicitly enabled", "LanmanServer Parameters\\SMB1 is nonzero.", "Review legacy SMB dependencies and the applicable hardening policy; Opscope did not change the feature."));
            var defender = snapshot.Services.FirstOrDefault(service => service.Name.Equals("WinDefend", StringComparison.OrdinalIgnoreCase));
            coverage.Add(new CheckCoverage("DEFENDER_SERVICE", "windows", defender is not null && !IsRunning(defender.State) ? "fail" : "not_evaluated",
                defender is null ? "WinDefend not in snapshot; product health unavailable." : $"WinDefend state={defender.State}; running service alone does not establish engine/signature health."));
            if (defender is not null && !IsRunning(defender.State)) findings.Add(new Finding(FindingSeverity.Warning, "DEFENDER_NOT_RUNNING", "Defender service is not running", Safe(snapshot, defender.State), "Review endpoint protection status and third-party security products; do not assume an inactive Defender means no protection."));
            using var policy = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows Defender", writable: false);
            if (policy?.GetValue("DisableAntiSpyware") is int disabled)
                records.Add(new EvidenceRecord("security", "Defender-policy", "collected", $"DisableAntiSpyware={disabled}; a policy value alone is not effective protection status."));
            foreach (var path in new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending", @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" })
            {
                using var reboot = Registry.LocalMachine.OpenSubKey(path, writable: false);
                if (reboot is not null)
                {
                    records.Add(new EvidenceRecord("security", "Windows-reboot-indicator", "collected", "A servicing/update reboot-pending registry key is present."));
                    findings.Add(new Finding(FindingSeverity.Warning, "REBOOT_PENDING", "Windows servicing reports a pending reboot", "A read-only query found a reboot-pending registry key; this is not a complete pending-patch assessment.", "Review the maintenance plan and update status before scheduling a reboot."));
                    break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            warnings.Add(Safe(snapshot, $"Windows security registry unavailable: {ex.Message}"));
            coverage.Add(new CheckCoverage("WINDOWS_REGISTRY_SECURITY", "windows", "not_evaluated", "Registry query denied or unavailable."));
        }
    }

    internal static bool IsRunning(string state) => state.Equals("running", StringComparison.OrdinalIgnoreCase) || state.Equals("active", StringComparison.OrdinalIgnoreCase)
        || state.StartsWith("active/", StringComparison.OrdinalIgnoreCase) || state.Equals("4", StringComparison.Ordinal);

    internal static bool TryGetEndpoint(string text, out string address, out int port)
    {
        address = string.Empty;
        port = 0;
        var colon = text.LastIndexOf(':');
        if (colon < 0 || !int.TryParse(text.AsSpan(colon + 1), NumberStyles.None, CultureInfo.InvariantCulture, out port) || port is < 1 or > 65535) return false;
        address = text[..colon].Trim('[', ']');
        return address.Length > 0;
    }

    internal static bool IsLoopback(string address) => address.Equals("localhost", StringComparison.OrdinalIgnoreCase)
        || IPAddress.TryParse(address.Split('%')[0], out var ip) && IPAddress.IsLoopback(ip);
}
