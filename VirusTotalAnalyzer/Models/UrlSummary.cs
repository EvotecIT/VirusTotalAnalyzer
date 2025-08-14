using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class UrlSummary
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    [JsonPropertyName("links")]
    public Links Links { get; set; } = new();
    public UrlSummaryData Data { get; set; } = new();
}

public sealed class UrlSummaryData
{
    public UrlSummaryAttributes Attributes { get; set; } = new();
}

public sealed class UrlSummaryAttributes
{
    [JsonPropertyName("url")]
    public string Url { get; set; } = string.Empty;

    [JsonPropertyName("last_analysis_stats")]
    public AnalysisStats LastAnalysisStats { get; set; } = new();

    [JsonPropertyName("total_votes")]
    public TotalVotes TotalVotes { get; set; } = new();
}

public sealed class UrlSummariesResponse
{
    [JsonPropertyName("data")]
    public List<UrlSummary> Data { get; set; } = new();

    [JsonPropertyName("meta")]
    public PaginationMetadata? Meta { get; set; }
}

