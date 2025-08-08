using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class IpAddressReport
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public IpAddressData Data { get; set; } = new();
}

public sealed class IpAddressData
{
    public IpAddressAttributes Attributes { get; set; } = new();
}

public sealed class IpAddressAttributes
{
    [JsonPropertyName("ip_address")]
    public string IpAddress { get; set; } = string.Empty;

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
