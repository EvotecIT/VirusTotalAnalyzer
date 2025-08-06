using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class AnalysisReport
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public AnalysisData Data { get; set; } = new();
}

public sealed class AnalysisData
{
    public AnalysisAttributes Attributes { get; set; } = new();
}

public sealed class AnalysisAttributes
{
    [JsonPropertyName("status")]
    public AnalysisStatus Status { get; set; }
}
