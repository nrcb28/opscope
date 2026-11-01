using System.Diagnostics;
using System.Runtime.InteropServices;
using Opscope;

internal static class SnapshotIOTests
{
    public static async Task RunAsync()
    {
        CheckDarwinStatFixtures();
        var directory = Path.Combine(Path.GetTempPath(), $"opscope-input-security-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var regular = Path.Combine(directory, "regular.txt");
            const string contents = "regular input \u2713\n";
            await File.WriteAllTextAsync(regular, contents);
            Check(await SnapshotIO.ReadTextAsync(regular) == contents, "Native regular file contents were not read.");

            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                await RejectSpecialFileAsync(directory);
                await RejectSpecialFileAsync("/dev/null");

                var regularLink = Path.Combine(directory, "regular-link");
                File.CreateSymbolicLink(regularLink, regular);
                Check(await SnapshotIO.ReadTextAsync(regularLink) == contents, "A symlink to a regular file did not retain its existing behavior.");
                var directoryLink = Path.Combine(directory, "directory-link");
                Directory.CreateSymbolicLink(directoryLink, directory);
                await RejectSpecialFileAsync(directoryLink);

                var fifo = Path.Combine(directory, "input.fifo");
                var start = new ProcessStartInfo("/usr/bin/mkfifo") { UseShellExecute = false };
                start.ArgumentList.Add(fifo);
                using (var process = Process.Start(start) ?? throw new InvalidOperationException("Unable to create FIFO fixture."))
                {
                    await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2));
                    Check(process.ExitCode == 0, "FIFO fixture creation failed.");
                }
                await RejectSpecialFileAsync(fifo);
                var fifoLink = Path.Combine(directory, "fifo-link");
                File.CreateSymbolicLink(fifoLink, fifo);
                await RejectSpecialFileAsync(fifoLink);
            }
        }
        finally { Directory.Delete(directory, true); }
        Console.WriteLine("PASS: Darwin X64/Arm64 stat ABI fixtures; native regular input and nonblocking special-file rejection.");
    }

    private static void CheckDarwinStatFixtures()
    {
        // Apple XNU stat.h inode64 layout: dev_t at 0, mode_t at 4, nlink_t at 6, ino64_t at 8.
        // The inode bytes at 8 deliberately resemble a non-regular mode in the legacy layout.
        (string Name, byte[] Header)[] fixtures =
        [
            ("Darwin X64 fstat$INODE64", [0x12, 0x00, 0x00, 0x00, 0xa4, 0x81, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
            ("Darwin Arm64 fstat", [0x34, 0x00, 0x00, 0x00, 0xa4, 0x81, 0x01, 0x00, 0x00, 0x40, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00])
        ];
        Check(Marshal.SizeOf<SnapshotIO.DarwinStat64>() == 144, "Darwin inode64 stat storage has the wrong size.");
        foreach (var (name, header) in fixtures)
        {
            var bytes = new byte[144];
            header.CopyTo(bytes, 0);
            Check(MemoryMarshal.Read<SnapshotIO.DarwinStat64>(bytes).Mode == 0x81a4, $"{name} read inode bytes as the regular-file mode.");
            foreach (ushort mode in new ushort[] { 0x11a4, 0x21a4, 0x41ed, 0xa1ff, 0xc180 })
            {
                bytes[4] = (byte)(mode & 0xff);
                bytes[5] = (byte)(mode >> 8);
                Check(MemoryMarshal.Read<SnapshotIO.DarwinStat64>(bytes).Mode == mode, $"{name} lost special-file type bits.");
            }
        }
    }

    private static async Task RejectSpecialFileAsync(string path)
    {
        // Run the synchronous open on a worker so the timeout also detects a blocking FIFO open.
        try { await Task.Run(() => SnapshotIO.ReadTextAsync(path)).WaitAsync(TimeSpan.FromSeconds(2)); }
        catch (InvalidDataException) { return; }
        throw new InvalidOperationException("A non-regular input was accepted: " + path);
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
