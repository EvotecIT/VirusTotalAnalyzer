using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class Bundle
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    [JsonPropertyName("links")]
    public Links Links { get; set; } = new();
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

public sealed class CreateBundleRequest
{
    [JsonPropertyName("data")]
    public CreateBundleData Data { get; set; } = new();
}

public sealed class CreateBundleData
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "bundle";

    [JsonPropertyName("attributes")]
    public CreateBundleAttributes Attributes { get; set; } = new();
}

public sealed class CreateBundleAttributes
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("files")]
    public List<Relationship> Files { get; set; } = new();
}

public sealed class UpdateBundleRequest
{
    [JsonPropertyName("data")]
    public UpdateBundleData Data { get; set; } = new();
}

public sealed class UpdateBundleData
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "bundle";

    [JsonPropertyName("attributes")]
    public UpdateBundleAttributes Attributes { get; set; } = new();
}

public sealed class UpdateBundleAttributes
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("files")]
    public List<Relationship> Files { get; set; } = new();
}
