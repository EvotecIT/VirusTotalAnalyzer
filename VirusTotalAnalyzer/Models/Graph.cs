

namespace VirusTotalAnalyzer.Models;

public sealed class Graph
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
    public GraphData Data { get; set; } = new();
}

public sealed class GraphData
{
    public GraphAttributes Attributes { get; set; } = new();
}

public sealed class GraphAttributes
{
    public string Name { get; set; } = string.Empty;
}

public sealed class CreateGraphRequest
{
    public CreateGraphData Data { get; set; } = new();
}

public sealed class CreateGraphData
{
    public string Type { get; set; } = "graph";

    public CreateGraphAttributes Attributes { get; set; } = new();
}

public sealed class CreateGraphAttributes
{
    public string Name { get; set; } = string.Empty;
}

public sealed class UpdateGraphRequest
{
    public UpdateGraphData Data { get; set; } = new();
}

public sealed class UpdateGraphData
{
    public string Type { get; set; } = "graph";

    public UpdateGraphAttributes Attributes { get; set; } = new();
}

public sealed class UpdateGraphAttributes
{
    public string? Name { get; set; }
}