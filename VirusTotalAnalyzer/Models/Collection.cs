using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class Collection
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public CollectionData Data { get; set; } = new();
}

public sealed class CollectionData
{
    public CollectionAttributes Attributes { get; set; } = new();
}

public sealed class CollectionAttributes
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;
}
