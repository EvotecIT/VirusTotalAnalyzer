using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class DomainReport
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public DomainData Data { get; set; } = new();
}

public sealed class DomainData
{
    public DomainAttributes Attributes { get; set; } = new();
}

public sealed class DomainAttributes
{
    [JsonPropertyName("domain")]
    public string Domain { get; set; } = string.Empty;

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
