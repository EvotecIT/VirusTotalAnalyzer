using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class UrlReport
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public UrlData Data { get; set; } = new();
}

public sealed class UrlData
{
    public UrlAttributes Attributes { get; set; } = new();
}

public sealed class UrlAttributes
{
    [JsonPropertyName("url")]
    public string Url { get; set; } = string.Empty;

    [JsonPropertyName("reputation")]
    public int Reputation { get; set; }

    [JsonPropertyName("last_analysis_stats")]
    public AnalysisStats LastAnalysisStats { get; set; } = new();

    [JsonPropertyName("total_votes")]
    public TotalVotes TotalVotes { get; set; } = new();

    [JsonPropertyName("categories")]
    public Dictionary<string, Verdict> Categories { get; set; } = new();

    [JsonPropertyName("last_analysis_date")]
    public long LastAnalysisDate { get; set; }
}
