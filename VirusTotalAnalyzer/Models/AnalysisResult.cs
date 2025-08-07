using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class AnalysisResult
{
    [JsonPropertyName("category")]
    public string Category { get; set; } = string.Empty;

    [JsonPropertyName("engine_name")]
    public string EngineName { get; set; } = string.Empty;

    [JsonPropertyName("engine_version")]
    public string? EngineVersion { get; set; }

    [JsonPropertyName("method")]
    public string? Method { get; set; }

    [JsonPropertyName("result")]
    public string? Result { get; set; }
}
