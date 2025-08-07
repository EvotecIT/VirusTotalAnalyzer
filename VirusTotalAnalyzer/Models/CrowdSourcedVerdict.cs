using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class CrowdSourcedVerdict
{
    [JsonPropertyName("engine_name")]
    public string EngineName { get; set; } = string.Empty;

    [JsonPropertyName("verdict")]
    public Verdict Verdict { get; set; }
}
