using System.Text;
using System.Text.Json;

namespace Opscope.Api;

/// <summary>Read-only MCP JSON-RPC. Stdio uses newline-delimited messages; HTTP uses the same handler behind local session authentication.</summary>
public static class McpServer
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web) { MaxDepth = 32 };
    public static Task RunAsync(Func<CancellationToken, Task<Snapshot>> readLatest, CancellationToken cancellationToken = default) => RunAsync(readLatest, Console.In, Console.Out, cancellationToken);

    public static async Task RunAsync(Func<CancellationToken, Task<Snapshot>> readLatest, TextReader input, TextWriter output, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(readLatest);
        Snapshot? latest = null;
        async Task<Snapshot> Cached(CancellationToken token) => latest ??= await readLatest(token);
        while (!cancellationToken.IsCancellationRequested)
        {
            var line = await ReadBoundedLineAsync(input, 64 * 1024, cancellationToken);
            if (line is null) break;
            var response = await HandleAsync(line, Cached, cancellationToken);
            if (response is not null) { await output.WriteLineAsync(response.AsMemory(), cancellationToken); await output.FlushAsync(cancellationToken); }
        }
    }

    public static async Task<string?> HandleAsync(string message, Func<CancellationToken, Task<Snapshot>> readLatest, CancellationToken cancellationToken = default)
    {
        JsonElement? id = null;
        try
        {
            if (Encoding.UTF8.GetByteCount(message) > 64 * 1024) return Error(null, -32600, "Request exceeds 64 KiB.");
            using var document = JsonDocument.Parse(message, new JsonDocumentOptions { MaxDepth = 32 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("jsonrpc", out var version) || version.GetString() != "2.0" || !root.TryGetProperty("method", out var methodProperty) || methodProperty.ValueKind != JsonValueKind.String)
                return Error(null, -32600, "Invalid JSON-RPC request.");
            if (root.TryGetProperty("id", out var suppliedId))
            {
                if (suppliedId.ValueKind is not (JsonValueKind.Number or JsonValueKind.String)) return Error(null, -32600, "Invalid request id.");
                id = suppliedId.Clone();
            }
            var method = methodProperty.GetString();
            if (id is null) return null; // Notifications, including initialized, never return a response.
            object result;
            switch (method)
            {
                case "initialize":
                    result = new { protocolVersion = "2024-11-05", capabilities = new { tools = new { listChanged = false } }, serverInfo = new { name = "opscope-read-only", version = "1.0.0" }, instructions = "Only redacted local snapshots and findings are exposed. No arbitrary paths, commands, or host changes are supported." };
                    break;
                case "ping": result = new { }; break;
                case "tools/list":
                    result = new { tools = new[] {
                        Tool("opscope_snapshot", "Read the latest redacted local evidence snapshot."),
                        Tool("opscope_findings", "Read the latest redacted findings and collection warnings.")
                    } };
                    break;
                case "tools/call":
                    if (!root.TryGetProperty("params", out var parameters) || parameters.ValueKind != JsonValueKind.Object || !parameters.TryGetProperty("name", out var nameProperty) || nameProperty.ValueKind != JsonValueKind.String)
                        return Error(id, -32602, "A listed tool name is required.");
                    var name = nameProperty.GetString();
                    if (name is not ("opscope_snapshot" or "opscope_findings")) return Error(id, -32602, "Unknown read-only tool.");
                    if (parameters.TryGetProperty("arguments", out var args) && (args.ValueKind != JsonValueKind.Object || args.EnumerateObject().Any())) return Error(id, -32602, "These tools accept no arguments, paths, or commands.");
                    var snapshot = Reporter.RedactForOutput(await readLatest(cancellationToken));
                    var payload = name == "opscope_snapshot" ? Reporter.ToJson(snapshot) : JsonSerializer.Serialize(new { findings = snapshot.Findings, collectionWarnings = snapshot.CollectionWarnings }, Options);
                    result = new { content = new[] { new { type = "text", text = payload } }, isError = false };
                    break;
                default: return Error(id, -32601, "Method not found.");
            }
            return JsonSerializer.Serialize(new { jsonrpc = "2.0", id, result }, Options);
        }
        catch (JsonException) { return Error(id, -32700, "Parse error."); }
        catch (InvalidOperationException) { return Error(id, -32600, "Invalid request."); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { return Error(id, -32603, "Local evidence is unavailable."); }
    }
    private static object Tool(string name, string description) => new { name, description, inputSchema = new { type = "object", properties = new { }, additionalProperties = false }, annotations = new { readOnlyHint = true, destructiveHint = false, openWorldHint = false } };
    private static string Error(JsonElement? id, int code, string message) => JsonSerializer.Serialize(new { jsonrpc = "2.0", id, error = new { code, message } }, Options);
    private static async Task<string?> ReadBoundedLineAsync(TextReader input, int limit, CancellationToken cancellationToken)
    {
        var result = new StringBuilder();
        var buffer = new char[1];
        var tooLarge = false;
        while (true)
        {
            var count = await input.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (count == 0) return result.Length == 0 ? null : tooLarge ? "!oversized" : result.ToString();
            if (buffer[0] == '\n') return tooLarge ? "!oversized" : result.ToString().TrimEnd('\r');
            if (result.Length >= limit) tooLarge = true;
            else result.Append(buffer[0]);
        }
    }
}
