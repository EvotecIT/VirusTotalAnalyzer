using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class DomainReport
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    [JsonPropertyName("attributes")]
    public DomainAttributes Attributes { get; set; } = new();
}

public sealed class DomainReportResponse
{
    [JsonPropertyName("data")]
    public DomainReport Data { get; set; } = new();
}

public sealed class DomainAttributes
{
    [JsonPropertyName("domain")]
    public string Domain { get; set; } = string.Empty;

    [JsonPropertyName("reputation")]
    public int Reputation { get; set; }

    [JsonPropertyName("creation_date")]
    public DateTimeOffset CreationDate { get; set; }

    [JsonPropertyName("tags")]
    public List<string> Tags { get; set; } = new();

    [JsonPropertyName("last_analysis_stats")]
    public AnalysisStats LastAnalysisStats { get; set; } = new();

    [JsonPropertyName("last_analysis_results")]
    public Dictionary<string, AnalysisResult> LastAnalysisResults { get; set; } = new();

    [JsonPropertyName("total_votes")]
    public TotalVotes TotalVotes { get; set; } = new();

    [JsonPropertyName("categories")]
    public Dictionary<string, Verdict> Categories { get; set; } = new();

    [JsonPropertyName("last_analysis_date")]
    public DateTimeOffset LastAnalysisDate { get; set; }
}
