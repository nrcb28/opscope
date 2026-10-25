namespace Opscope;

public sealed record AnalysisReport(string Kind, DateTimeOffset CollectedAtUtc, IReadOnlyList<Finding> Findings, object? Data = null, IReadOnlyList<string>? Warnings = null)
{
    // EN: Execution success is separate from finding severity; empty findings must not hide a failed collection.
    // ES: El éxito de ejecución es distinto de la severidad; una lista vacía no debe ocultar una recolección fallida.
    public bool OperationSucceeded { get; init; } = true;
}
