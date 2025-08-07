using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class CrowdsourcedVerdict
{
    [JsonPropertyName("source")]
    public string Source { get; set; } = string.Empty;

    [JsonPropertyName("verdict")]
    public Verdict Verdict { get; set; }

    [JsonPropertyName("timestamp")]
    public long Timestamp { get; set; }
}
