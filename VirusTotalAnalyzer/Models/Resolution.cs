using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class Resolution
{
    public string Id { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public ResolutionData Data { get; set; } = new();
}

public sealed class ResolutionData
{
    public ResolutionAttributes Attributes { get; set; } = new();
}

public sealed class ResolutionAttributes
{
    [JsonPropertyName("date")]
    public DateTimeOffset Date { get; set; }

    [JsonPropertyName("host_name")]
    public string? HostName { get; set; }

    [JsonPropertyName("ip_address")]
    public string? IpAddress { get; set; }
}

public sealed class ResolutionsResponse
{
    [JsonPropertyName("data")]
    public List<Resolution> Data { get; set; } = new();

    [JsonPropertyName("meta")]
    public PaginationMetadata? Meta { get; set; }
}
