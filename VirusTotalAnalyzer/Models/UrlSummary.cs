using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class UrlSummary
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public ResourceType Type { get; set; }

    [JsonPropertyName("attributes")]
    public UrlSummaryAttributes Attributes { get; set; } = new();
}

public sealed class UrlSummaryAttributes
{
    [JsonPropertyName("url")]
    public string Url { get; set; } = string.Empty;

    [JsonPropertyName("last_analysis_stats")]
    public AnalysisStats LastAnalysisStats { get; set; } = new();
}

public sealed class UrlSummariesResponse
{
    [JsonPropertyName("data")]
    public List<UrlSummary> Data { get; set; } = new();
}
