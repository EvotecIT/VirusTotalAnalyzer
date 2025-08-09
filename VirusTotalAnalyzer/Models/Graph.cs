using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class Graph
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public GraphData Data { get; set; } = new();
}

public sealed class GraphData
{
    public GraphAttributes Attributes { get; set; } = new();
}

public sealed class GraphAttributes
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;
}

public sealed class CreateGraphRequest
{
    [JsonPropertyName("data")]
    public CreateGraphData Data { get; set; } = new();
}

public sealed class CreateGraphData
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "graph";

    [JsonPropertyName("attributes")]
    public CreateGraphAttributes Attributes { get; set; } = new();
}

public sealed class CreateGraphAttributes
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;
}

public sealed class UpdateGraphRequest
{
    [JsonPropertyName("data")]
    public UpdateGraphData Data { get; set; } = new();
}

public sealed class UpdateGraphData
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "graph";

    [JsonPropertyName("attributes")]
    public UpdateGraphAttributes Attributes { get; set; } = new();
}

public sealed class UpdateGraphAttributes
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }
}
