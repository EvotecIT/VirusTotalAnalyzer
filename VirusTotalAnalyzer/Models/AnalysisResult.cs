

namespace VirusTotalAnalyzer.Models;

public sealed class AnalysisResult
{
    public string Category { get; set; } = string.Empty;

    public string EngineName { get; set; } = string.Empty;

    public string? EngineVersion { get; set; }

    public string? Method { get; set; }

    public string? Result { get; set; }
}