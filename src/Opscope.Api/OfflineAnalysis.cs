using System.Text;
using System.Text.Json;
using Opscope.Evidence;

namespace Opscope.Api;

/// <summary>Strict, stateless saved-evidence input. Never accepts paths or invokes native collectors.</summary>
internal sealed record OfflineAnalysis(Snapshot Snapshot, string Operation, string? Scenario = null,
    IocImport? Indicators = null, Snapshot? Baseline = null)
{
    // EN: The envelope accepts data, not paths or commands, and keeps saved analysis stateless.
    // ES: El sobre acepta datos, no rutas ni comandos, y mantiene el análisis guardado sin persistencia.
    internal const int MaximumIndicatorBytes = 128 * 1024;

    internal static OfflineAnalysis Parse(JsonElement root)
    {
        try { return ParseCore(root); }
        catch (InvalidOperationException error) { throw new InvalidDataException("Invalid saved-evidence JSON text.", error); }
    }

    private static OfflineAnalysis ParseCore(JsonElement root)
    {
        RequireFields(root, "snapshot", "operation", "scenario", "indicators", "baseline");
        if (!root.TryGetProperty("snapshot", out var snapshot) || !root.TryGetProperty("operation", out var operation) || operation.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("A snapshot and operation are required.");
        var kind = operation.GetString();
        var allowed = kind switch
        {
            "inspect" => new[] { "snapshot", "operation" },
            "triage" => ["snapshot", "operation", "scenario"],
            "ioc" => ["snapshot", "operation", "indicators"],
            "timeline" => ["snapshot", "operation", "baseline"],
            _ => throw new InvalidDataException("Unsupported saved-evidence operation.")
        };
        RequireFields(root, allowed);
        var parsed = Reporter.ParseSnapshot(snapshot.GetRawText());
        if (kind == "triage")
        {
            if (!root.TryGetProperty("scenario", out var scenario) || scenario.ValueKind != JsonValueKind.String || scenario.GetString() is not ("high-cpu" or "disk-full" or "port-exposed"))
                throw new InvalidDataException("A supported triage scenario is required.");
            return new(parsed, kind, scenario.GetString());
        }
        if (kind == "ioc")
        {
            if (!root.TryGetProperty("indicators", out var indicators)) throw new InvalidDataException("Indicators are required.");
            RequireFields(indicators, "format", "text");
            if (!indicators.TryGetProperty("format", out var format) || format.ValueKind != JsonValueKind.String || format.GetString() is not ("csv" or "stix") ||
                !indicators.TryGetProperty("text", out var text) || text.ValueKind != JsonValueKind.String || Encoding.UTF8.GetByteCount(text.GetString()!) > MaximumIndicatorBytes)
                throw new InvalidDataException("Indicators require csv or stix format and at most 128 KiB of text.");
            IocImport import;
            try { import = IocAnalyzer.Parse(text.GetString()!, format.GetString()!); }
            catch (InvalidOperationException error) { throw new InvalidDataException("Invalid indicator document.", error); }
            return new(parsed, kind, Indicators: import);
        }
        return new(parsed, kind!, Baseline: root.TryGetProperty("baseline", out var baseline) ? Reporter.ParseSnapshot(baseline.GetRawText()) : null);
    }

    internal AnalysisReport Analyze()
    {
        if (Operation == "triage") return TriageAdvisor.Analyze(Snapshot, Scenario!);
        if (Operation == "timeline") return TimelineBuilder.Build(Snapshot, Baseline);
        if (Operation == "ioc")
        {
            // This overload only compares recorded observables. AnalyzeAsync also reads live executables.
            var report = IocAnalyzer.Analyze(Snapshot, Indicators!.Indicators);
            return report with { Warnings = Indicators.Warnings.Concat(report.Warnings ?? []).Distinct().ToArray() };
        }
        throw new InvalidOperationException("Inspection returns a snapshot directly.");
    }

    internal static void RequireFields(JsonElement root, params string[] allowed)
    {
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("A JSON object is required.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            foreach (var field in root.EnumerateObject())
                if (!allowed.Contains(field.Name, StringComparer.Ordinal) || !seen.Add(field.Name))
                    throw new InvalidDataException("Unknown or duplicate request field.");
        }
        catch (InvalidOperationException error) { throw new InvalidDataException("Invalid JSON property name.", error); }
    }
}
