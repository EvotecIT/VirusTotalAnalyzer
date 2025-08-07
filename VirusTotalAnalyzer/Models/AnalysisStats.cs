using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class AnalysisStats
{
    [JsonPropertyName("harmless")] public int Harmless { get; set; }
    [JsonPropertyName("malicious")] public int Malicious { get; set; }
    [JsonPropertyName("suspicious")] public int Suspicious { get; set; }
    [JsonPropertyName("undetected")] public int Undetected { get; set; }
    [JsonPropertyName("timeout")] public int Timeout { get; set; }
    [JsonPropertyName("failure")] public int Failure { get; set; }
    [JsonPropertyName("type-unsupported")] public int TypeUnsupported { get; set; }
}
