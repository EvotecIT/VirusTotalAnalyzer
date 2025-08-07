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
