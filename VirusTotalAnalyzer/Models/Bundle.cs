using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class Bundle
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public BundleData Data { get; set; } = new();
}

public sealed class BundleData
{
    public BundleAttributes Attributes { get; set; } = new();
}

public sealed class BundleAttributes
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("files")]
    public List<Relationship> Files { get; set; } = new();
}
