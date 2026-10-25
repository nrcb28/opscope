using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Opscope;

public static class ReportExporter
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true, MaxDepth = 64 };
    public static IReadOnlyList<string> Formats { get; } = ["json", "sarif", "junit", "html", "pdf", "csv", "jsonl", "cef", "asff"];
    public static string Export(Snapshot snapshot, string format, bool redact = true)
    {
        var view = redact ? Reporter.RedactForOutput(snapshot) : snapshot;
        if (Normalize(format) == "json") return Reporter.ToJson(view);
        return Render(new("snapshot", view.CollectedAtUtc, view.Findings, view, view.CollectionWarnings), Normalize(format));
    }
    public static string Export(AnalysisReport report, string format, bool redact = true) => Render(redact ? Redact(report) : report, Normalize(format));
    public static string ExportAsff(AnalysisReport report, string accountId, string region, bool redact = true)
    {
        if (accountId is null || accountId.Length != 12 || !Regex.IsMatch(accountId, @"\A[0-9]{12}\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)) || accountId.All(c => c == '0'))
            throw new ArgumentException("ASFF requires a 12-digit AWS account ID; the all-zero placeholder is unsupported.", nameof(accountId));
        if (region is null || region.Length > 32 || !Regex.IsMatch(region, @"\A[a-z]{2}(?:-[a-z0-9]+)+-[1-9][0-9]?\z", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)))
            throw new ArgumentException("ASFF requires an AWS region such as us-east-1 or eu-west-1.", nameof(region));
        return Asff(redact ? Redact(report) : report, accountId, region);
    }
    public static string ExportAsff(Snapshot snapshot, string accountId, string region, bool redact = true) =>
        ExportAsff(new AnalysisReport("snapshot", snapshot.CollectedAtUtc, snapshot.Findings, snapshot, snapshot.CollectionWarnings), accountId, region, redact);
    public static string Export(DiffReport report, string format, bool redact = true)
    {
        var view = redact ? Reporter.RedactForOutput(report) : report;
        if (Normalize(format) == "json") return Reporter.ToJson(view);
        var findings = view.Changes.Select((c, i) => new Finding(FindingSeverity.Warning, $"DRIFT_{i + 1}", $"{c.Category}: {c.Change}", $"{c.Identity}: {c.Details}", "Review the drift against the approved baseline."))
            .Concat(view.Metrics.Where(m => Math.Abs(m.Delta) > 0).Select((m, i) => new Finding(view.Significant ? FindingSeverity.Warning : FindingSeverity.Info, $"DRIFT_METRIC_{i + 1}", m.Name, $"{m.Baseline} -> {m.Current} ({m.Delta:+0.##;-0.##;0} {m.Unit})", "Review the metric change."))).ToArray();
        return Render(new("diff", view.CurrentCollectedAtUtc, findings, view, view.Warnings), Normalize(format));
    }
    public static Task WriteAsync(string path, Snapshot report, string format, bool redact = true, CancellationToken cancellationToken = default) => WriteOutput(path, Export(report, format, redact), format, cancellationToken);
    public static Task WriteAsync(string path, AnalysisReport report, string format, bool redact = true, CancellationToken cancellationToken = default) => WriteOutput(path, Export(report, format, redact), format, cancellationToken);
    public static Task WriteAsync(string path, DiffReport report, string format, bool redact = true, CancellationToken cancellationToken = default) => WriteOutput(path, Export(report, format, redact), format, cancellationToken);
    private static async Task WriteOutput(string path, string content, string format, CancellationToken ct)
    {
        if (Normalize(format) != "pdf") { await Reporter.WriteTextAtomicallyAsync(path, content, ct); return; }
        await PrivateFiles.WriteAsync(path, Encoding.Latin1.GetBytes(content), ct);
    }
    public static AnalysisReport Redact(AnalysisReport report) => ReportSecurity.Redact(report);
    private static string Normalize(string format)
    {
        var normalized = format.ToLowerInvariant() switch { "sarif2.1.0" => "sarif", "junit-xml" => "junit", "ndjson" => "jsonl", _ => format.ToLowerInvariant() };
        if (!Formats.Contains(normalized)) throw new ArgumentException($"Unsupported output format '{Reporter.SafeDisplay(format)}'.", nameof(format));
        return normalized;
    }
    private static string Render(AnalysisReport report, string format) => format switch
    {
        "json" => JsonSerializer.Serialize(report, Json),
        "sarif" => Sarif(report), "junit" => Junit(report), "html" => Html(report), "pdf" => Pdf(report),
        "csv" => Csv(report), "jsonl" => Jsonl(report), "cef" => Cef(report), "asff" => Asff(report),
        _ => throw new ArgumentException("Unsupported output format.", nameof(format))
    };
    private static string Sarif(AnalysisReport report)
    {
        var rules = report.Findings.GroupBy(f => f.Code).Select(g => new { id = g.Key, shortDescription = new { text = g.First().Title }, help = new { text = g.First().Recommendation } }).ToArray();
        var output = new Dictionary<string, object>
        {
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
            ["version"] = "2.1.0",
            ["runs"] = new[] { new { tool = new { driver = new { name = "Opscope", rules } }, results = report.Findings.Select(f => new { ruleId = f.Code, level = f.Severity switch { FindingSeverity.Critical => "error", FindingSeverity.Warning => "warning", _ => "note" }, message = new { text = f.Title + ": " + f.Detail }, properties = new { recommendation = f.Recommendation } }), invocations = new[] { new { executionSuccessful = report.Warnings is null || report.Warnings.Count == 0, endTimeUtc = report.CollectedAtUtc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture), toolExecutionNotifications = (report.Warnings ?? []).Select(w => new { level = "warning", message = new { text = w } }) } } } }
        };
        return JsonSerializer.Serialize(output, Json);
    }
    private static string Junit(AnalysisReport report)
    {
        var cases = report.Findings.Select(f => new XElement("testcase", new XAttribute("classname", "opscope." + XmlText(report.Kind)), new XAttribute("name", XmlText(f.Code + ": " + f.Title)), f.Severity >= FindingSeverity.Warning ? new XElement("failure", new XAttribute("type", f.Severity.ToString()), new XAttribute("message", XmlText(f.Title)), XmlText(f.Detail + "\n" + f.Recommendation)) : new XElement("system-out", XmlText(f.Detail)))).ToList();
        if (cases.Count == 0) cases.Add(new XElement("testcase", new XAttribute("classname", "opscope"), new XAttribute("name", "No findings")));
        var suite = new XElement("testsuite", new XAttribute("name", "Opscope " + XmlText(report.Kind)), new XAttribute("tests", cases.Count), new XAttribute("failures", report.Findings.Count(f => f.Severity >= FindingSeverity.Warning)), new XAttribute("errors", 0), new XAttribute("timestamp", report.CollectedAtUtc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture)), cases, new XElement("system-err", XmlText(string.Join('\n', report.Warnings ?? []))));
        return new XDocument(new XDeclaration("1.0", "utf-8", null), new XElement("testsuites", suite)).ToString();
    }
    private static string XmlText(string? value) => new((value ?? "").Where(c => c is '\n' or '\r' or '\t' || c >= 0x20 && (c <= 0xD7FF || c >= 0xE000 && c <= 0xFFFD)).ToArray());
    private static string Html(AnalysisReport report)
    {
        var html = new StringBuilder("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>Opscope handoff report</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:1000px;margin:3rem auto;padding:0 1rem;color:#17243b}h1{border-bottom:3px solid #178178}article{border:1px solid #cbd5e1;border-radius:6px;padding:1rem;margin:1rem 0;break-inside:avoid}h3{margin:.2rem 0}.critical{border-left:5px solid #be123c}.warning{border-left:5px solid #b45309}.info{border-left:5px solid #2563eb}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.5 monospace}footer{margin-top:2rem;border-top:1px solid #cbd5e1;font-size:12px}@media print{body{margin:0;max-width:none}article{break-inside:avoid}@page{margin:18mm}}</style></head><body><h1>Opscope handoff report</h1>");
        html.Append("<p>Analysis: ").Append(H(report.Kind)).Append("<br>Collected: ").Append(H(report.CollectedAtUtc.ToString("O", CultureInfo.InvariantCulture))).Append("</p><h2>Executive summary</h2><p>")
            .Append(report.Findings.Count).Append(" findings; ").Append(report.Findings.Count(f => f.Severity == FindingSeverity.Critical)).Append(" critical; ").Append(report.Findings.Count(f => f.Severity == FindingSeverity.Warning)).Append(" warning.</p><h2>Prioritized findings</h2>");
        foreach (var f in report.Findings.OrderByDescending(f => f.Severity)) html.Append("<article class=\"").Append(f.Severity.ToString().ToLowerInvariant()).Append("\"><strong>").Append(H(f.Severity + " · " + f.Code)).Append("</strong><h3>").Append(H(f.Title)).Append("</h3><p>").Append(H(f.Detail)).Append("</p><p><strong>Recommended action:</strong> ").Append(H(f.Recommendation)).Append("</p></article>");
        if (report.Findings.Count == 0) html.Append("<p>No findings were recorded.</p>");
        if (report.Warnings is { Count: > 0 }) { html.Append("<h2>Collection limitations</h2><ul>"); foreach (var warning in report.Warnings) html.Append("<li>").Append(H(warning)).Append("</li>"); html.Append("</ul>"); }
        if (report.Data is not null) html.Append("<h2>Evidence</h2><pre>").Append(H(JsonSerializer.Serialize(report.Data, Json))).Append("</pre>");
        return html.Append("<footer>Opscope read-only evidence report. Review collection limitations before drawing conclusions. Print or save this self-contained document as PDF for handoff.</footer></body></html>").ToString();
    }
    private static string H(string? value) => WebUtility.HtmlEncode(value ?? "");
    private static string Csv(AnalysisReport report)
    {
        var text = new StringBuilder("collectedAtUtc,kind,severity,code,title,detail,recommendation\r\n");
        foreach (var f in report.Findings) text.AppendJoin(',', new[] { report.CollectedAtUtc.ToString("O", CultureInfo.InvariantCulture), report.Kind, f.Severity.ToString(), f.Code, f.Title, f.Detail, f.Recommendation }.Select(CsvCell)).Append("\r\n");
        return text.ToString();
    }
    private static string CsvCell(string value)
    {
        if (value.TrimStart().FirstOrDefault() is '=' or '+' or '-' or '@' or '\t' or '\r') value = "'" + value;
        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }
    private static string Jsonl(AnalysisReport report) => string.Join('\n', report.Findings.Select(f => JsonSerializer.Serialize(new { collectedAtUtc = report.CollectedAtUtc, kind = report.Kind, severity = f.Severity.ToString(), f.Code, f.Title, f.Detail, f.Recommendation }))) + (report.Findings.Count > 0 ? "\n" : "");
    private static string Cef(AnalysisReport report) => string.Join('\n', report.Findings.Select(f => $"CEF:0|Opscope|Opscope|1|{CefHeader(f.Code)}|{CefHeader(f.Title)}|{(f.Severity == FindingSeverity.Critical ? 10 : f.Severity == FindingSeverity.Warning ? 5 : 1)}|rt={report.CollectedAtUtc.ToUnixTimeMilliseconds()} msg={CefValue(f.Detail)} cs1Label=recommendation cs1={CefValue(f.Recommendation)}")) + (report.Findings.Count > 0 ? "\n" : "");
    private static string CefHeader(string value) => value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("|", "\\|", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal).Replace("\r", "\\r", StringComparison.Ordinal);
    private static string CefValue(string value) => value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("=", "\\=", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal).Replace("\r", "\\r", StringComparison.Ordinal);
    private static string Asff(AnalysisReport report, string? accountId = null, string? region = null)
    {
        var offline = accountId is null;
        accountId ??= "000000000000";
        region ??= "us-east-1";
        var partition = region.StartsWith("cn-", StringComparison.Ordinal) ? "aws-cn"
            : region.StartsWith("us-gov-", StringComparison.Ordinal) ? "aws-us-gov"
            : region.StartsWith("us-isob-", StringComparison.Ordinal) ? "aws-iso-b"
            : region.StartsWith("us-iso-", StringComparison.Ordinal) ? "aws-iso"
            : region.StartsWith("eu-isoe-", StringComparison.Ordinal) ? "aws-iso-e"
            : region.StartsWith("us-isof-", StringComparison.Ordinal) ? "aws-iso-f" : "aws";
        var context = new Dictionary<string, string> { ["opscope/exportMode"] = offline ? "offline-placeholder" : "configured-account", ["opscope/redaction"] = "Output follows the selected redaction setting." };
        if (offline) context["opscope/notice"] = "Offline export. Replace placeholder account, region, ProductArn and resource IDs before import.";
        return JsonSerializer.Serialize(new
        {
            Findings = report.Findings.Select((f, i) => new
            {
                SchemaVersion = "2018-10-08", Id = $"opscope/{accountId}/{region}/{report.CollectedAtUtc.ToUnixTimeMilliseconds()}/{f.Code}/{i}",
                ProductArn = $"arn:{partition}:securityhub:{region}:{accountId}:product/{accountId}/default", GeneratorId = "opscope/" + report.Kind, AwsAccountId = accountId,
                Types = new[] { "Software and Configuration Checks" }, CreatedAt = report.CollectedAtUtc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture), UpdatedAt = report.CollectedAtUtc.UtcDateTime.ToString("O", CultureInfo.InvariantCulture),
                Severity = new { Label = f.Severity switch { FindingSeverity.Critical => "CRITICAL", FindingSeverity.Warning => "MEDIUM", _ => "INFORMATIONAL" } },
                Title = Limit(string.IsNullOrEmpty(f.Title) ? "Opscope finding" : f.Title, 256), Description = Limit(string.IsNullOrEmpty(f.Detail) ? "Opscope collected a finding." : f.Detail, 1024),
                Remediation = new { Recommendation = new { Text = Limit(f.Recommendation, 512) } },
                Resources = new[] { new { Type = "Other", Id = $"opscope:{accountId}:{region}:local-evidence", Partition = partition, Region = region } }, ProductFields = context
            })
        }, new JsonSerializerOptions { WriteIndented = true });
    }
    private static string Limit(string value, int length) => value.Length <= length ? value : value[..length];
    private static string Pdf(AnalysisReport report)
    {
        var lines = new List<string> { "Opscope handoff report", "", $"Analysis: {report.Kind}", $"Collected: {report.CollectedAtUtc:O}", $"Findings: {report.Findings.Count}", "" };
        foreach (var f in report.Findings.OrderByDescending(f => f.Severity)) { lines.AddRange(Wrap($"[{f.Severity}] {f.Code}: {f.Title}")); lines.AddRange(Wrap(f.Detail)); lines.AddRange(Wrap("Action: " + f.Recommendation)); lines.Add(""); }
        foreach (var warning in report.Warnings ?? []) lines.AddRange(Wrap("Collection limitation: " + warning));
        if (report.Data is not null)
        {
            lines.Add(""); lines.Add("Evidence");
            foreach (var line in JsonSerializer.Serialize(report.Data, Json).Split('\n')) lines.AddRange(Wrap(line));
        }
        var pages = lines.Chunk(48).ToArray(); if (pages.Length == 0) pages = [[]];
        var objects = new List<string> { "<< /Type /Catalog /Pages 2 0 R >>", "", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>" };
        var pageIds = new List<int>();
        foreach (var page in pages)
        {
            var pageId = objects.Count + 1; var contentId = pageId + 1; pageIds.Add(pageId);
            objects.Add($"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents {contentId} 0 R >>");
            var stream = new StringBuilder("BT /F1 10 Tf 48 794 Td 15 TL\n");
            foreach (var line in page) stream.Append('(').Append(PdfEscape(line)).Append(") Tj T*\n");
            stream.Append("ET\n"); objects.Add($"<< /Length {Encoding.Latin1.GetByteCount(stream.ToString())} >>\nstream\n{stream}endstream");
        }
        objects[1] = $"<< /Type /Pages /Count {pageIds.Count} /Kids [{string.Join(' ', pageIds.Select(id => id + " 0 R"))}] >>";
        var pdf = new StringBuilder("%PDF-1.4\n%Opscope\n"); var offsets = new List<int> { 0 };
        for (var i = 0; i < objects.Count; i++) { offsets.Add(Encoding.Latin1.GetByteCount(pdf.ToString())); pdf.Append(i + 1).Append(" 0 obj\n").Append(objects[i]).Append("\nendobj\n"); }
        var start = Encoding.Latin1.GetByteCount(pdf.ToString()); pdf.Append("xref\n0 ").Append(objects.Count + 1).Append("\n0000000000 65535 f \n");
        foreach (var offset in offsets.Skip(1)) pdf.Append(offset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n");
        return pdf.Append("trailer\n<< /Size ").Append(objects.Count + 1).Append(" /Root 1 0 R >>\nstartxref\n").Append(start).Append("\n%%EOF\n").ToString();
    }
    private static IEnumerable<string> Wrap(string value)
    {
        var cleaned = Reporter.SafeDisplay(value);
        while (cleaned.Length > 92) { var end = cleaned.LastIndexOf(' ', 92); if (end < 20) end = 92; yield return cleaned[..end]; cleaned = cleaned[end..].TrimStart(); }
        yield return cleaned;
    }
    private static string PdfEscape(string value)
    {
        var text = new StringBuilder();
        foreach (var character in value)
        {
            if (character is >= (char)32 and <= (char)126)
            {
                if (character is '\\' or '(' or ')') text.Append('\\');
                text.Append(character);
            }
            else if (character is >= (char)160 and <= (char)255) text.Append('\\').Append(Convert.ToString(character, 8).PadLeft(3, '0'));
            else text.Append('?');
        }
        return text.ToString();
    }
}

internal static class PrivateFiles
{
    internal static FileStream Create(string path) => CommandRunner.CreatePrivateFile(path);
    internal static async Task WriteAsync(string path, byte[] bytes, CancellationToken cancellationToken)
    {
        var full = Path.GetFullPath(path); Directory.CreateDirectory(Path.GetDirectoryName(full)!); var temp = full + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try { await using (var file = Create(temp)) await file.WriteAsync(bytes, cancellationToken); File.Move(temp, full, true); }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
}
