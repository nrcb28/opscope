using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Opscope;

public static class SnapshotIO
{
    public const int MaximumBytes = 16 * 1024 * 1024;

    public static async Task<Snapshot> ReadAsync(string path, CancellationToken cancellationToken = default) =>
        Reporter.ParseSnapshot(await ReadTextAsync(path, cancellationToken));

    public static async Task<string> ReadTextAsync(string path, CancellationToken cancellationToken = default)
    {
        var fullPath = Path.GetFullPath(path);
        await using var stream = OpenRegularRead(fullPath);
        if (stream.Length > MaximumBytes) throw new InvalidDataException("Input exceeds the 16 MiB limit.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        using var data = new MemoryStream();
        var buffer = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(buffer, timeout.Token)) > 0)
        {
            if (data.Length + read > MaximumBytes) throw new InvalidDataException("Input exceeds the 16 MiB limit.");
            await data.WriteAsync(buffer.AsMemory(0, read), timeout.Token);
        }
        return new UTF8Encoding(false, true).GetString(data.GetBuffer(), 0, (int)data.Length).TrimStart('\uFEFF');
    }

    public static void ValidateJson(string json)
    {
        if (Encoding.UTF8.GetByteCount(json) > MaximumBytes) throw new InvalidDataException("Input exceeds the 16 MiB limit.");
        var bytes = Encoding.UTF8.GetBytes(json);
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = 64 });
        string? property = null;
        string? collection = null;
        var count = 0;
        var tokens = 0;
        var arrayCounts = new Dictionary<int, int>();
        while (reader.Read())
        {
            if (++tokens > 500000) throw new InvalidDataException("Input exceeds the JSON complexity limit.");
            if (reader.TokenType is not (JsonTokenType.EndArray or JsonTokenType.EndObject or JsonTokenType.PropertyName) && arrayCounts.TryGetValue(reader.CurrentDepth - 1, out var parentCount))
            {
                if (parentCount >= 10000) throw new InvalidDataException("Input array exceeds 10000 elements.");
                arrayCounts[reader.CurrentDepth - 1] = parentCount + 1;
            }
            if (reader.TokenType == JsonTokenType.StartArray) arrayCounts[reader.CurrentDepth] = 0;
            if (reader.TokenType == JsonTokenType.EndArray) arrayCounts.Remove(reader.CurrentDepth);

            if (reader.TokenType is JsonTokenType.String or JsonTokenType.PropertyName && reader.ValueSpan.Length > 65536)
                throw new InvalidDataException("Input contains a text field larger than 64 KiB.");
            if (reader.TokenType == JsonTokenType.PropertyName && reader.CurrentDepth == 1) property = reader.GetString();
            if (reader.TokenType == JsonTokenType.StartArray && reader.CurrentDepth == 1)
            {
                collection = property;
                count = 0;
            }
            if (collection is not null && reader.CurrentDepth == 2 && reader.TokenType is not (JsonTokenType.EndObject or JsonTokenType.EndArray or JsonTokenType.PropertyName))
            {
                var maximum = collection switch
                {
                    "disks" => 1024, "network" => 4096, "processes" or "findings" or "collectionWarnings" => 1000,
                    "listeners" or "services" => 10000, _ => 10000
                };
                if (++count > maximum) throw new InvalidDataException($"Input contains too many {collection}; maximum is {maximum}.");
            }
            if (reader.TokenType == JsonTokenType.EndArray && reader.CurrentDepth == 1) collection = null;
        }
    }

    public static FileStream OpenRegularRead(string path)
    {
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            var flags = OperatingSystem.IsLinux() ? 0x800 | 0x80000 : 0x4 | 0x1000000;
            var descriptor = Open(path, flags);
            if (descriptor < 0) throw new IOException("Unable to open input file.");
            var handle = new SafeFileHandle((IntPtr)descriptor, true);
            try
            {
                ushort mode;
                if (OperatingSystem.IsLinux())
                {
                    var status = new FileStatus();
                    if (Statx(descriptor, string.Empty, 0x1000, 0x201, ref status) != 0) throw new IOException("Unable to inspect input file.");
                    mode = status.Mode;
                }
                else
                {
                    var buffer = Marshal.AllocHGlobal(256);
                    try
                    {
                        if (Fstat(descriptor, buffer) != 0) throw new IOException("Unable to inspect input file.");
                        mode = unchecked((ushort)Marshal.ReadInt16(buffer, 4));
                    }
                    finally { Marshal.FreeHGlobal(buffer); }
                }
                if ((mode & 0xF000) != 0x8000) throw new InvalidDataException("Only regular input files are supported.");
                return new FileStream(handle, FileAccess.Read, 8192, false);
            }
            catch { handle.Dispose(); throw; }
        }
        if (path.StartsWith("\\\\", StringComparison.Ordinal)) throw new InvalidDataException("Only local regular input files are supported.");
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 8192, FileOptions.Asynchronous);
        if (!stream.CanSeek) { stream.Dispose(); throw new InvalidDataException("Only regular input files are supported."); }
        return stream;
    }

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct FileStatus { [FieldOffset(28)] public ushort Mode; }

    [SuppressMessage("Globalization", "CA2101", Justification = "libc uses UTF-8 file paths.")]
    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);
    [SuppressMessage("Globalization", "CA2101", Justification = "libc uses UTF-8 file paths.")]
    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int Statx(int descriptor, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, ref FileStatus status);
    [DllImport("libc", EntryPoint = "fstat", SetLastError = true)]
    private static extern int Fstat(int descriptor, IntPtr buffer);
}
