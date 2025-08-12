using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class DomainSubdomainsResponse
{
    [JsonPropertyName("data")]
    public List<DomainSummary> Data { get; set; } = new();

    [JsonPropertyName("meta")]
    public PaginationMetadata? Meta { get; set; }
}

public sealed class DomainSiblingsResponse
{
    [JsonPropertyName("data")]
    public List<DomainSummary> Data { get; set; } = new();

    [JsonPropertyName("meta")]
    public PaginationMetadata? Meta { get; set; }
}

public sealed class DomainUrlsResponse
{
    [JsonPropertyName("data")]
    public List<UrlSummary> Data { get; set; } = new();

    [JsonPropertyName("meta")]
    public PaginationMetadata? Meta { get; set; }
}

