using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class AnalysisStats
{
    public int Harmless { get; set; }
    public int Malicious { get; set; }
    public int Suspicious { get; set; }
    public int Undetected { get; set; }
    public int Timeout { get; set; }
    public int Failure { get; set; }
    [JsonPropertyName("type-unsupported")] public int TypeUnsupported { get; set; }
}
