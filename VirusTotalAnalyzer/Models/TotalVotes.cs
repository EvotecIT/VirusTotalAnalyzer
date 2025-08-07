using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class TotalVotes
{
    [JsonPropertyName("harmless")] public int Harmless { get; set; }
    [JsonPropertyName("malicious")] public int Malicious { get; set; }
}
