namespace Opscope;

public sealed record AnalysisReport(string Kind, DateTimeOffset CollectedAtUtc, IReadOnlyList<Finding> Findings, object? Data = null, IReadOnlyList<string>? Warnings = null)
{
    public bool OperationSucceeded { get; init; } = true;
}
