using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class DomainSummary
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    [JsonPropertyName("links")]
    public Links Links { get; set; } = new();
    public DomainSummaryData Data { get; set; } = new();
}

public sealed class DomainSummaryData
{
    public DomainSummaryAttributes Attributes { get; set; } = new();
}

public sealed class DomainSummaryAttributes
{
    [JsonPropertyName("domain")]
    public string Domain { get; set; } = string.Empty;

    [JsonPropertyName("last_analysis_stats")]
    public AnalysisStats LastAnalysisStats { get; set; } = new();

    [JsonPropertyName("total_votes")]
    public TotalVotes TotalVotes { get; set; } = new();
}

public sealed class DomainSummariesResponse
{
    [JsonPropertyName("data")]
    public List<DomainSummary> Data { get; set; } = new();

    [JsonPropertyName("meta")]
    public PaginationMetadata? Meta { get; set; }
}

