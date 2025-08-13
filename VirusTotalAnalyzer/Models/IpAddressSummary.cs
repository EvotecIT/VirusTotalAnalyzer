using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class IpAddressSummary
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public IpAddressSummaryData Data { get; set; } = new();
}

public sealed class IpAddressSummaryResponse
{
    [JsonPropertyName("data")]
    public IpAddressSummary Data { get; set; } = new();
}

public sealed class IpAddressSummaryData
{
    public IpAddressSummaryAttributes Attributes { get; set; } = new();
}

public sealed class IpAddressSummaryAttributes
{
    [JsonPropertyName("ip_address")]
    public string IpAddress { get; set; } = string.Empty;

    [JsonPropertyName("last_analysis_stats")]
    public AnalysisStats LastAnalysisStats { get; set; } = new();

    [JsonPropertyName("total_votes")]
    public TotalVotes TotalVotes { get; set; } = new();
}

public sealed class IpAddressSummariesResponse
{
    [JsonPropertyName("data")]
    public List<IpAddressSummary> Data { get; set; } = new();

    [JsonPropertyName("meta")]
    public PaginationMetadata? Meta { get; set; }
}

