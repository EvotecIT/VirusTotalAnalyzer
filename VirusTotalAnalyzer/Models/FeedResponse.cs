using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class FeedResponse
{
    [JsonPropertyName("data")]
    public List<FeedItem> Data { get; set; } = new();

    [JsonPropertyName("meta")]
    public PaginationMetadata? Meta { get; set; }
}

public sealed class FeedItem
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public ResourceType Type { get; set; }

    [JsonPropertyName("links")]
    public Links Links { get; set; } = new();
}
