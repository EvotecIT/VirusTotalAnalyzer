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

public sealed class CreateCollectionRequest
{
    [JsonPropertyName("data")]
    public CreateCollectionData Data { get; set; } = new();
}

public sealed class CreateCollectionData
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "collection";

    [JsonPropertyName("attributes")]
    public CreateCollectionAttributes Attributes { get; set; } = new();
}

public sealed class CreateCollectionAttributes
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;
}

public sealed class UpdateCollectionRequest
{
    [JsonPropertyName("data")]
    public UpdateCollectionData Data { get; set; } = new();
}

public sealed class UpdateCollectionData
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "collection";

    [JsonPropertyName("attributes")]
    public UpdateCollectionAttributes Attributes { get; set; } = new();
}

public sealed class UpdateCollectionAttributes
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }
}
