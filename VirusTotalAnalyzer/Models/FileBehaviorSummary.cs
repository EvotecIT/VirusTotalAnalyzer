using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class FileBehaviorSummary
{
    [JsonPropertyName("data")]
    public BehaviorSummaryData Data { get; set; } = new();
}

public sealed class BehaviorSummaryData
{
    [JsonPropertyName("tags")]
    public List<string> Tags { get; set; } = new();
}
