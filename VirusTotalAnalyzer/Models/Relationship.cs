using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class Relationship
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public ResourceType Type { get; set; }

    [JsonPropertyName("links")]
    public Links Links { get; set; } = new();
}

public sealed class RelationshipResponse
{
    [JsonPropertyName("data")]
    public List<Relationship> Data { get; set; } = new();
}
