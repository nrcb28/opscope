using System.Collections;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Opscope.Evidence;

public sealed record WindowsDefenderStatus(bool? ServiceEnabled, bool? AntivirusEnabled, bool? RealTimeProtectionEnabled,
    string? EngineVersion, string? SignatureVersion, DateTimeOffset? SignatureUpdatedUtc, int? SignatureAgeDays, bool? SignaturesOutOfDate);

public sealed record WindowsLocalAccountStatus(string Name, bool? Disabled, bool? PasswordRequired, string? Status);

public sealed record WindowsCachedUpdate(string Title, IReadOnlyList<string> KnowledgeBaseArticles, bool? Downloaded);

public sealed record WindowsCachedPatchStatus(IReadOnlyList<WindowsCachedUpdate> Updates, bool QuerySucceeded, bool Truncated = false);

/// <summary>Pure, fixture-testable evaluations. A password policy flag is never treated as proof of an empty password.</summary>
public static class WindowsSecurityEvaluator
{
    public static AnalysisReport EvaluateDefender(Snapshot snapshot, WindowsDefenderStatus? status)
    {
        var findings = new List<Finding>();
        var records = new List<EvidenceRecord>();
        var coverage = new List<CheckCoverage>();
        var warnings = new List<string>();
        if (status is null)
        {
            coverage.Add(new CheckCoverage("DEFENDER_HEALTH", "windows", "not_evaluated", "MSFT_MpComputerStatus unavailable, unsupported or access denied."));
            return Result(snapshot, records, coverage, findings, warnings);
        }
        double? age = status.SignatureUpdatedUtc.HasValue ? (snapshot.CollectedAtUtc - status.SignatureUpdatedUtc.Value).TotalDays : status.SignatureAgeDays;
        var invalidAge = age is < -1 or > 36500;
        if (invalidAge) { age = null; warnings.Add("Defender signature timestamp/age is outside the supported observation window."); }
        var disabled = status.ServiceEnabled == false || status.AntivirusEnabled == false || status.RealTimeProtectionEnabled == false;
        var stale = status.SignaturesOutOfDate == true || age > 7;
        var complete = status.ServiceEnabled.HasValue && status.AntivirusEnabled.HasValue && status.RealTimeProtectionEnabled.HasValue
            && status.SignaturesOutOfDate.HasValue && age.HasValue && !string.IsNullOrWhiteSpace(status.EngineVersion) && !string.IsNullOrWhiteSpace(status.SignatureVersion);
        coverage.Add(new CheckCoverage("DEFENDER_HEALTH", "windows", disabled || stale ? "fail" : complete ? "pass" : "not_evaluated",
            $"Local MSFT_MpComputerStatus: serviceEnabled={status.ServiceEnabled}, antivirusEnabled={status.AntivirusEnabled}, realTimeProtectionEnabled={status.RealTimeProtectionEnabled}; signature age warning threshold=7 days. This describes Defender, not all endpoint security products."));
        records.Add(new EvidenceRecord("security", "WMI:MSFT_MpComputerStatus", "collected", "Read-only local Defender engine/signature/real-time protection metadata.", Metadata:
            new Dictionary<string, string>
            {
                ["engineVersion"] = Safe(snapshot, status.EngineVersion ?? "unknown"),
                ["signatureVersion"] = Safe(snapshot, status.SignatureVersion ?? "unknown"),
                ["signatureUpdatedUtc"] = status.SignatureUpdatedUtc?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture) ?? "unknown",
                ["signatureAgeDays"] = age?.ToString("F1", CultureInfo.InvariantCulture) ?? "unknown",
                ["signaturesOutOfDate"] = status.SignaturesOutOfDate?.ToString() ?? "unknown"
            }));
        if (disabled) findings.Add(new Finding(FindingSeverity.Warning, "DEFENDER_PROTECTION_DISABLED", "Defender reports disabled protection",
            "At least one of AMServiceEnabled, AntivirusEnabled or RealTimeProtectionEnabled is false in local Defender status.",
            "Review intended protection mode and third-party endpoint security. No protection preference or service was changed."));
        if (stale) findings.Add(new Finding(FindingSeverity.Warning, "DEFENDER_SIGNATURES_STALE", "Defender signatures may be outdated",
            "Defender reports outdated signatures or signature age exceeds the documented seven-day threshold.", "Review signature health and the managed update policy; no update was requested."));
        return Result(snapshot, records, coverage, findings, warnings);
    }

    public static AnalysisReport EvaluateAccounts(Snapshot snapshot, IReadOnlyList<WindowsLocalAccountStatus>? accounts, bool truncated = false)
    {
        var findings = new List<Finding>();
        var records = new List<EvidenceRecord>();
        var coverage = new List<CheckCoverage>
        {
            new("EMPTY_PASSWORD_ACCOUNTS", "windows", "not_evaluated", "PasswordRequired=False is a local-account policy flag, not proof of a blank password. No authentication attempt, SAM access or password/hash read is performed.")
        };
        var warnings = new List<string>();
        if (accounts is null)
        {
            coverage.Add(new CheckCoverage("PASSWORD_REQUIRED_POLICY", "windows", "not_evaluated", "Local Win32_UserAccount metadata unavailable, unsupported or access denied."));
            return Result(snapshot, records, coverage, findings, warnings);
        }
        if (accounts.Count > 512) truncated = true;
        var limited = accounts.Take(512).ToArray();
        foreach (var account in limited)
        {
            records.Add(new EvidenceRecord("security", "WMI:Win32_UserAccount", "collected", "Local account policy metadata; actual password content and emptiness are unknown.", Metadata:
                new Dictionary<string, string>
                {
                    ["user"] = Safe(snapshot, account.Name), ["disabled"] = account.Disabled?.ToString() ?? "unknown",
                    ["passwordRequiredPolicy"] = account.PasswordRequired?.ToString() ?? "unknown", ["status"] = Safe(snapshot, account.Status ?? "unknown")
                }));
            if (account.PasswordRequired == false)
                findings.Add(new Finding(account.Disabled == true ? FindingSeverity.Info : FindingSeverity.Warning, "WINDOWS_PASSWORD_NOT_REQUIRED",
                    "Local account policy does not require a password", "Win32_UserAccount reports PasswordRequired=False; this does not establish that the account has a blank password. Identity is in protected user metadata.",
                    "Review account purpose, disabled state and password policy. Opscope does not attempt authentication or inspect credential databases."));
        }
        var activeWithoutRequirement = limited.Any(account => account.PasswordRequired == false && account.Disabled != true);
        var complete = limited.Length > 0 && !truncated && limited.All(account => account.Disabled.HasValue && account.PasswordRequired.HasValue);
        coverage.Add(new CheckCoverage("PASSWORD_REQUIRED_POLICY", "windows", activeWithoutRequirement ? "fail" : complete ? "pass" : "not_evaluated",
            $"Read local-account policy flags for {limited.Length} accounts; disabled accounts do not fail the enabled-account policy check. This does not prove absence of blank passwords."));
        if (truncated) warnings.Add("Windows local-account enumeration was limited to 512 entries; remaining accounts were not evaluated.");
        return Result(snapshot, records, coverage, findings, warnings);
    }

    public static AnalysisReport EvaluateCachedPatches(Snapshot snapshot, WindowsCachedPatchStatus? status)
    {
        var updates = status?.Updates.Take(256).ToArray() ?? [];
        var truncated = status is not null && (status.Truncated || status.Updates.Count > 256);
        var coverage = new List<CheckCoverage>
        {
            new("PENDING_PATCHES", "windows", updates.Length > 0 ? "fail" : "not_evaluated",
                status is null ? "Windows Update Agent cached assessment unavailable, unsupported, timed out or access denied."
                : $"Windows Update Agent Online=false returned {updates.Length} cached not-installed/non-hidden updates; querySucceeded={status.QuerySucceeded}; truncated={truncated}. No cached updates is not evidence of current patch compliance.")
        };
        var records = updates.Select(update => new EvidenceRecord("security", "WUA:cached-update-search", "collected", Safe(snapshot, update.Title), Metadata:
            new Dictionary<string, string>
            {
                ["knowledgeBaseArticles"] = string.Join(',', update.KnowledgeBaseArticles.Take(32).Select(value => Safe(snapshot, value))),
                ["downloaded"] = update.Downloaded?.ToString() ?? "unknown", ["source"] = "local cached metadata; Online=false"
            })).ToList();
        var findings = updates.Length == 0 ? new List<Finding>() :
            [new Finding(FindingSeverity.Warning, "PENDING_PATCHES", "Windows cached metadata lists pending updates", $"{(truncated ? "At least " : string.Empty)}{updates.Length} not-installed/non-hidden updates are present in the local WUA cache; metadata may be stale or incomplete.",
                "Review update applicability and metadata freshness through the normal patch process. No online search, download, installation or reboot was performed.")];
        var warnings = new List<string> { "Windows patch assessment uses existing cached WUA metadata only (Online=false); it performs no online scan, download, install, source change or reboot." };
        if (status?.QuerySucceeded != true) warnings.Add("Cached Windows Update search did not report a fully successful result; available entries may be partial.");
        if (truncated) warnings.Add("Cached Windows Update enumeration was limited to 256 updates; remaining entries were not evaluated.");
        return Result(snapshot, records, coverage, findings, warnings);
    }

    public static DateTimeOffset? ParseWmiDateTime(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var iso)) return iso.ToUniversalTime();
        if (value.Length != 25 || value[14] != '.' || value[21] is not ('+' or '-') ||
            !DateTime.TryParseExact(value[..14], "yyyyMMddHHmmss", CultureInfo.InvariantCulture, DateTimeStyles.None, out var time) ||
            !int.TryParse(value.AsSpan(15, 6), NumberStyles.None, CultureInfo.InvariantCulture, out var microseconds) ||
            !int.TryParse(value.AsSpan(22, 3), NumberStyles.None, CultureInfo.InvariantCulture, out var offset) || offset > 840) return null;
        try { return new DateTimeOffset(time.AddTicks(microseconds * 10L), TimeSpan.FromMinutes(value[21] == '-' ? -offset : offset)).ToUniversalTime(); }
        catch (ArgumentException) { return null; }
    }

    private static string Safe(Snapshot snapshot, string text) => EvidenceCollector.Safe(snapshot, text);
    private static AnalysisReport Result(Snapshot snapshot, List<EvidenceRecord> records, List<CheckCoverage> coverage, List<Finding> findings, List<string> warnings) =>
        new("windows-security", snapshot.CollectedAtUtc, findings, new EvidenceData(records, coverage), warnings);
}

internal sealed record WorkerResult<T>(T? Value, Exception? Error);

/// <summary>A timed-out COM call can remain blocked in its provider. Never create a second worker while that call is alive.</summary>
internal sealed class SingleFlightWorker<T>
{
    private readonly object _gate = new();
    private Task<WorkerResult<T>>? _active;

    public bool TryStart(Func<T> operation, out Task<WorkerResult<T>> task)
    {
        lock (_gate)
        {
            if (_active is { IsCompleted: false }) { task = _active; return false; }
            var completion = new TaskCompletionSource<WorkerResult<T>>(TaskCreationOptions.RunContinuationsAsynchronously);
            _active = task = completion.Task;
            var thread = new Thread(() =>
            {
                try { completion.TrySetResult(new WorkerResult<T>(operation(), null)); }
                catch (Exception exception) { completion.TrySetResult(new WorkerResult<T>(default, exception)); }
            }) { IsBackground = true, Name = "Opscope bounded local COM evidence" };
            if (OperatingSystem.IsWindows()) thread.SetApartmentState(ApartmentState.MTA);
            try { thread.Start(); }
            catch (Exception exception) { completion.TrySetResult(new WorkerResult<T>(default, exception)); }
            return true;
        }
    }
}

internal static class WindowsNativeSecurity
{
    private static readonly SingleFlightWorker<AnalysisReport> Worker = new();
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(6);
    private const string DefenderProjection = "SELECT AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AMEngineVersion,AntivirusSignatureVersion,AntivirusSignatureLastUpdated,AntivirusSignatureAge,DefenderSignaturesOutOfDate FROM MSFT_MpComputerStatus";
    private const string AccountsProjection = "SELECT Name,Disabled,PasswordRequired,Status FROM Win32_UserAccount WHERE LocalAccount=True";
    private const string CachedUpdateCriteria = "IsInstalled=0 and IsHidden=0";

    public static async Task<AnalysisReport> CollectAsync(Snapshot snapshot, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows()) return Unavailable(snapshot, "Windows COM collectors are runtime-gated and were not invoked on this platform.");
        if (!Worker.TryStart(() => ReadWindowsGuarded(snapshot, cancellationToken), out var task))
            return Unavailable(snapshot, "An earlier local COM collector is still running after its deadline; no additional worker was started.");
        try
        {
            var result = await task.WaitAsync(Deadline, cancellationToken);
            return result.Value ?? Unavailable(snapshot, $"Local COM evidence unavailable ({result.Error?.GetType().Name ?? "unknown error"}).");
        }
        catch (TimeoutException)
        {
            return Unavailable(snapshot, "Local COM evidence exceeded its six-second caller deadline. The single background worker is not forcibly aborted; further workers are blocked until it finishes.");
        }
    }

    private static AnalysisReport ReadWindowsGuarded(Snapshot snapshot, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows security metadata requires Windows.");
        return ReadWindows(snapshot, cancellationToken);
    }

    [SupportedOSPlatform("windows")]
    private static AnalysisReport ReadWindows(Snapshot snapshot, CancellationToken cancellationToken)
    {
        var reports = new List<AnalysisReport>();
        var warnings = new List<string>();
        var watch = Stopwatch.StartNew();
        WindowsDefenderStatus? defender = null;
        List<WindowsLocalAccountStatus>? accounts = null;
        WindowsCachedPatchStatus? patches = null;
        var accountsTruncated = false;
        bool CanContinue() => !cancellationToken.IsCancellationRequested && watch.Elapsed < Deadline;
        if (CanContinue())
        {
            try
            {
                ReadWmi(@"root\Microsoft\Windows\Defender", DefenderProjection, 1, () => CanContinue(), row =>
                {
                    defender = new WindowsDefenderStatus(BooleanProperty(row, "AMServiceEnabled"), BooleanProperty(row, "AntivirusEnabled"), BooleanProperty(row, "RealTimeProtectionEnabled"),
                        TextProperty(row, "AMEngineVersion"), TextProperty(row, "AntivirusSignatureVersion"), WindowsSecurityEvaluator.ParseWmiDateTime(TextProperty(row, "AntivirusSignatureLastUpdated")),
                        IntegerProperty(row, "AntivirusSignatureAge"), BooleanProperty(row, "DefenderSignaturesOutOfDate"));
                });
            }
            catch (Exception ex) when (IsProviderFailure(ex)) { warnings.Add(ProviderError("Defender WMI", ex)); }
        }
        if (CanContinue())
        {
            try
            {
                accounts = [];
                accountsTruncated = ReadWmi(@"root\cimv2", AccountsProjection, 512, () => CanContinue(), row =>
                    accounts.Add(new WindowsLocalAccountStatus(TextProperty(row, "Name") ?? "[unknown-account]", BooleanProperty(row, "Disabled"), BooleanProperty(row, "PasswordRequired"), TextProperty(row, "Status"))));
            }
            catch (Exception ex) when (IsProviderFailure(ex)) { accounts = null; warnings.Add(ProviderError("Local account WMI", ex)); }
        }
        if (CanContinue())
        {
            try { patches = ReadCachedUpdates(() => CanContinue()); }
            catch (Exception ex) when (IsProviderFailure(ex)) { warnings.Add(ProviderError("Windows Update cached search", ex)); }
        }
        if (!CanContinue()) warnings.Add("The shared Windows COM deadline/cancellation stopped further queries; unfinished controls are not evaluated.");
        reports.Add(WindowsSecurityEvaluator.EvaluateDefender(snapshot, defender));
        reports.Add(WindowsSecurityEvaluator.EvaluateAccounts(snapshot, accounts, accountsTruncated));
        reports.Add(WindowsSecurityEvaluator.EvaluateCachedPatches(snapshot, patches));
        return Merge(snapshot, reports, warnings);
    }

    [SupportedOSPlatform("windows")]
    private static bool ReadWmi(string localNamespace, string projection, int maximum, Func<bool> canContinue, Action<object> accept)
    {
        object? locator = null, service = null, rows = null;
        try
        {
            locator = Activate("WbemScripting.SWbemLocator");
            service = ((dynamic)locator).ConnectServer(".", localNamespace);
            rows = ((dynamic)service).ExecQuery(projection, "WQL", 48); // Forward-only and return-immediately; no methods or writes.
            var count = 0;
            foreach (object row in (IEnumerable)rows)
            {
                try
                {
                    if (count >= maximum || !canContinue()) return true;
                    accept(row);
                    count++;
                }
                finally { Release(row); }
            }
            return false;
        }
        finally { Release(rows); Release(service); Release(locator); }
    }

    [SupportedOSPlatform("windows")]
    private static WindowsCachedPatchStatus ReadCachedUpdates(Func<bool> canContinue)
    {
        object? session = null, searcher = null, result = null, updates = null;
        var values = new List<WindowsCachedUpdate>();
        try
        {
            session = Activate("Microsoft.Update.Session");
            ((dynamic)session).ClientApplicationID = "Opscope read-only cached assessment";
            searcher = ((dynamic)session).CreateUpdateSearcher();
            ((dynamic)searcher).Online = false;
            if (!canContinue()) return new WindowsCachedPatchStatus([], false);
            result = ((dynamic)searcher).Search(CachedUpdateCriteria);
            var succeeded = Convert.ToInt32(((dynamic)result).ResultCode, CultureInfo.InvariantCulture) == 2;
            updates = ((dynamic)result).Updates;
            var count = Convert.ToInt32(((dynamic)updates).Count, CultureInfo.InvariantCulture);
            var truncated = count > 256;
            for (var index = 0; index < Math.Min(count, 256); index++)
            {
                if (!canContinue()) { truncated = true; break; }
                object? update = null, articles = null;
                try
                {
                    update = ((dynamic)updates).Item(index);
                    var title = Limit(Convert.ToString(((dynamic)update).Title, CultureInfo.InvariantCulture));
                    var downloaded = (bool?)((dynamic)update).IsDownloaded;
                    articles = ((dynamic)update).KBArticleIDs;
                    var articleCount = Math.Min(32, Convert.ToInt32(((dynamic)articles).Count, CultureInfo.InvariantCulture));
                    var ids = new List<string>();
                    for (var article = 0; article < articleCount; article++) ids.Add(Limit(Convert.ToString(((dynamic)articles).Item(article), CultureInfo.InvariantCulture)));
                    values.Add(new WindowsCachedUpdate(title, ids, downloaded));
                }
                finally { Release(articles); Release(update); }
            }
            return new WindowsCachedPatchStatus(values, succeeded, truncated);
        }
        finally { Release(updates); Release(result); Release(searcher); Release(session); }
    }

    [SupportedOSPlatform("windows")]
    private static object Activate(string progId)
    {
        var type = Type.GetTypeFromProgID(progId, throwOnError: false) ?? throw new PlatformNotSupportedException("Required local COM provider is not registered.");
        return Activator.CreateInstance(type) ?? throw new InvalidOperationException("Required local COM provider could not be created.");
    }

    [SupportedOSPlatform("windows")]
    private static object? Property(object row, string name)
    {
        object? properties = null, property = null;
        try
        {
            properties = ((dynamic)row).Properties_;
            property = ((dynamic)properties).Item(name, 0);
            object? value = ((dynamic)property).Value;
            return value is DBNull ? null : value;
        }
        finally { Release(property); Release(properties); }
    }

    [SupportedOSPlatform("windows")]
    private static string? TextProperty(object row, string name) => Property(row, name) is { } value ? Limit(Convert.ToString(value, CultureInfo.InvariantCulture)) : null;
    [SupportedOSPlatform("windows")]
    private static bool? BooleanProperty(object row, string name) => Property(row, name) is { } value ? Convert.ToBoolean(value, CultureInfo.InvariantCulture) : null;
    [SupportedOSPlatform("windows")]
    private static int? IntegerProperty(object row, string name) => Property(row, name) is { } value ? Convert.ToInt32(value, CultureInfo.InvariantCulture) : null;
    private static string Limit(string? text) => text is null ? string.Empty : text[..Math.Min(text.Length, 1024)];
    private static bool IsProviderFailure(Exception exception) => exception is COMException or UnauthorizedAccessException or InvalidOperationException or ArgumentException
        or InvalidCastException or NotSupportedException or System.Reflection.TargetInvocationException or MissingMethodException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException
        or FormatException or OverflowException;
    private static string ProviderError(string provider, Exception exception) => $"{provider} unavailable ({exception.GetType().Name}, HRESULT 0x{exception.HResult:X8}); no provider output or credentials were recorded.";
    private static void Release(object? value)
    {
        if (OperatingSystem.IsWindows() && value is not null && Marshal.IsComObject(value))
        {
            try { Marshal.FinalReleaseComObject(value); }
            catch (InvalidComObjectException) { /* Provider already disconnected; do not repeat its query. */ }
        }
    }

    private static AnalysisReport Unavailable(Snapshot snapshot, string warning) => Merge(snapshot,
        [WindowsSecurityEvaluator.EvaluateDefender(snapshot, null), WindowsSecurityEvaluator.EvaluateAccounts(snapshot, null), WindowsSecurityEvaluator.EvaluateCachedPatches(snapshot, null)], [warning]);

    private static AnalysisReport Merge(Snapshot snapshot, IReadOnlyList<AnalysisReport> reports, IReadOnlyList<string> warnings) =>
        new("windows-security", snapshot.CollectedAtUtc, reports.SelectMany(report => report.Findings).ToArray(),
            new EvidenceData(reports.SelectMany(report => ((EvidenceData)report.Data!).Records).ToArray(), reports.SelectMany(report => ((EvidenceData)report.Data!).Coverage).ToArray()),
            reports.SelectMany(report => report.Warnings ?? []).Concat(warnings).Distinct().ToArray());
}
