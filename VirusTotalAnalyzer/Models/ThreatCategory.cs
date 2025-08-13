using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class ThreatCategory
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("attributes")]
    public ThreatCategoryAttributes Attributes { get; set; } = new();
}

public sealed class ThreatCategoryAttributes
{
    [JsonPropertyName("count")]
    public long Count { get; set; }
}

public sealed class ThreatCategoriesResponse
{
    [JsonPropertyName("data")]
    public List<ThreatCategory> Data { get; set; } = new();
}
