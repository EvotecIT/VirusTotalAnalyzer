using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class SearchResponse
{
    [JsonPropertyName("data")]
    public List<SearchResult> Data { get; set; } = new();

    [JsonPropertyName("meta")]
    public PaginationMetadata? Meta { get; set; }
}

public sealed class SearchResult
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public ResourceType Type { get; set; }

    [JsonPropertyName("links")]
    public Links Links { get; set; } = new();
}
