using Microsoft.Data.Sqlite;

namespace Opscope.Api;

public sealed record HistoryEntry(long Id, DateTimeOffset CollectedAtUtc, double CpuUsedPercent, double MemoryUsedPercent, int FindingCount);

/// <summary>Versioned, size-bounded local SQLite history. Only redacted evidence enters the store.</summary>
public sealed class HistoryStore : IDisposable
{
    // EN: Store only redacted bounded evidence; dispose SQLite before inspecting its file on Windows.
    // ES: Solo se guarda evidencia redactada y acotada; en Windows se cierra SQLite antes de inspeccionar su archivo.
    private readonly SqliteConnection connection;
    private readonly object gate = new();
    private readonly int retentionCount;
    private readonly int retentionDays;
    public const int MaximumSnapshotBytes = 2 * 1024 * 1024;
    public const int MaximumHistoryBytes = 64 * 1024 * 1024;

    public HistoryStore(string path, int retentionCount = 100, int retentionDays = 30)
    {
        if (retentionCount is < 1 or > 1000 || retentionDays is < 1 or > 3650)
            throw new ArgumentOutOfRangeException(nameof(retentionCount), "Retention must be 1–1000 snapshots and 1–3650 days.");
        this.retentionCount = retentionCount;
        this.retentionDays = retentionDays;
        path = NormalizeSystemPath(Path.GetFullPath(path));
        RejectLinks(path);
        var parent = Path.GetDirectoryName(path)!;
        var existed = Directory.Exists(parent);
        Directory.CreateDirectory(parent);
        if (!OperatingSystem.IsWindows() && !existed) File.SetUnixFileMode(parent, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        if (!File.Exists(path))
        {
            using var created = CommandRunner.CreatePrivateFile(path);
        }
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadWrite, Pooling = false }.ToString());
        connection.Open();
        Execute("PRAGMA journal_mode=DELETE; PRAGMA secure_delete=ON; PRAGMA max_page_count=65536; PRAGMA busy_timeout=2000;");
        using var version = connection.CreateCommand();
        version.CommandText = "PRAGMA user_version";
        var schema = Convert.ToInt32(version.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
        if (schema is not (0 or 1)) { connection.Dispose(); throw new InvalidDataException("Unsupported history schema version."); }
        Execute("CREATE TABLE IF NOT EXISTS snapshots(id INTEGER PRIMARY KEY AUTOINCREMENT, created_utc TEXT NOT NULL, cpu REAL NOT NULL, memory REAL NOT NULL, findings INTEGER NOT NULL, payload TEXT NOT NULL); PRAGMA user_version=1;");
        Prune();
    }

    public void Add(Snapshot snapshot)
    {
        var redacted = Reporter.RedactForOutput(snapshot);
        var json = Reporter.ToJson(redacted);
        if (System.Text.Encoding.UTF8.GetByteCount(json) > MaximumSnapshotBytes)
            throw new InvalidDataException("Snapshot exceeds the 2 MiB history limit.");
        lock (gate)
        {
            using var transaction = connection.BeginTransaction();
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO snapshots(created_utc,cpu,memory,findings,payload) VALUES($time,$cpu,$memory,$findings,$payload)";
            command.Parameters.AddWithValue("$time", redacted.CollectedAtUtc.ToUniversalTime().ToString("O"));
            command.Parameters.AddWithValue("$cpu", redacted.CpuUsedPercent);
            command.Parameters.AddWithValue("$memory", redacted.Memory.UsedPercent);
            command.Parameters.AddWithValue("$findings", redacted.Findings.Count);
            command.Parameters.AddWithValue("$payload", json);
            command.ExecuteNonQuery();
            transaction.Commit();
            Prune();
        }
    }

    public IReadOnlyList<HistoryEntry> List()
    {
        lock (gate)
        {
            Prune();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT id,created_utc,cpu,memory,findings FROM snapshots ORDER BY id DESC LIMIT $limit";
            command.Parameters.AddWithValue("$limit", retentionCount);
            using var reader = command.ExecuteReader();
            var result = new List<HistoryEntry>();
            while (reader.Read()) result.Add(new(reader.GetInt64(0), DateTimeOffset.Parse(reader.GetString(1), System.Globalization.CultureInfo.InvariantCulture), reader.GetDouble(2), reader.GetDouble(3), reader.GetInt32(4)));
            return result;
        }
    }

    public Snapshot? Get(long id)
    {
        lock (gate)
        {
            Prune();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT payload FROM snapshots WHERE id=$id";
            command.Parameters.AddWithValue("$id", id);
            return command.ExecuteScalar() is string json ? Reporter.ParseSnapshot(json) : null;
        }
    }

    public void Prune()
    {
        lock (gate)
        {
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM snapshots WHERE id NOT IN (SELECT id FROM snapshots ORDER BY id DESC LIMIT $count) OR created_utc < $cutoff OR id IN (SELECT id FROM (SELECT id, SUM(length(CAST(payload AS BLOB))) OVER (ORDER BY id DESC) AS retained_bytes FROM snapshots) WHERE retained_bytes > $bytes)";
            command.Parameters.AddWithValue("$count", retentionCount);
            command.Parameters.AddWithValue("$cutoff", DateTimeOffset.UtcNow.AddDays(-retentionDays).ToString("O"));
            command.Parameters.AddWithValue("$bytes", MaximumHistoryBytes);
            command.ExecuteNonQuery();
        }
    }
    private void Execute(string sql) { using var command = connection.CreateCommand(); command.CommandText = sql; command.ExecuteNonQuery(); }
    private static string NormalizeSystemPath(string path)
    {
        if (!OperatingSystem.IsMacOS()) return path;
        // macOS exposes its protected system directories through these standard aliases.
        // Resolve only the expected direct system link; user-created links remain forbidden.
        foreach (var alias in new[] { "/var", "/tmp", "/etc" })
        {
            if (!path.StartsWith(alias + "/", StringComparison.Ordinal)) continue;
            var directory = new DirectoryInfo(alias);
            if (directory.LinkTarget is null) return path;
            var expected = "/private" + alias;
            if (!string.Equals(directory.ResolveLinkTarget(false)?.FullName, expected, StringComparison.Ordinal))
                throw new IOException("Unexpected macOS system directory alias.");
            return expected + path[alias.Length..];
        }
        return path;
    }
    private static void RejectLinks(string path)
    {
        for (var item = new FileInfo(path); item is not null; item = item.Directory is { } parent ? new FileInfo(parent.FullName) : null)
            if (item.LinkTarget is not null) throw new IOException("History paths must not contain symbolic links.");
    }
    public void Dispose() => connection.Dispose();
}
