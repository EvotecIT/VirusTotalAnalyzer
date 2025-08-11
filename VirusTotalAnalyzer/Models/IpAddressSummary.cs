using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class IpAddressSummary
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public ResourceType Type { get; set; }

    [JsonPropertyName("attributes")]
    public IpAddressSummaryAttributes Attributes { get; set; } = new();
}

public sealed class IpAddressSummaryAttributes
{
    [JsonPropertyName("ip_address")]
    public string IpAddress { get; set; } = string.Empty;

    [JsonPropertyName("last_analysis_stats")]
    public AnalysisStats LastAnalysisStats { get; set; } = new();
}

public sealed class IpAddressSummariesResponse
{
    [JsonPropertyName("data")]
    public List<IpAddressSummary> Data { get; set; } = new();
}
