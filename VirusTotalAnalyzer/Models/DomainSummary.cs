using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class DomainSummary
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public ResourceType Type { get; set; }

    [JsonPropertyName("attributes")]
    public DomainSummaryAttributes Attributes { get; set; } = new();
}

public sealed class DomainSummaryAttributes
{
    [JsonPropertyName("domain")]
    public string Domain { get; set; } = string.Empty;

    [JsonPropertyName("last_analysis_stats")]
    public AnalysisStats LastAnalysisStats { get; set; } = new();
}

public sealed class DomainSummariesResponse
{
    [JsonPropertyName("data")]
    public List<DomainSummary> Data { get; set; } = new();
}
