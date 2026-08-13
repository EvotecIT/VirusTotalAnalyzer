using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class Graph
{
    public string Id { get; set; } = string.Empty;

    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();

    public GraphAttributes Attributes { get; set; } = new();
}

public sealed class GraphAttributes : ExtensibleAttributes
{
    public int? CommentsCount { get; set; }

    public DateTimeOffset? CreationDate { get; set; }

    public GraphData GraphData { get; set; } = new();

    public DateTimeOffset? LastModifiedDate { get; set; }

    public List<GraphConnection> Links { get; set; } = new();

    public List<GraphNode> Nodes { get; set; } = new();

    public GraphPosition? Position { get; set; }

    public bool? Private { get; set; }

    public int? ViewsCount { get; set; }
}

public sealed class GraphData : ExtensibleAttributes
{
    public string? Description { get; set; }

    public string? Version { get; set; }
}

public sealed class GraphConnection : ExtensibleAttributes
{
    public string? ConnectionType { get; set; }

    public string? Source { get; set; }

    public string? Target { get; set; }
}

public sealed class GraphNode : ExtensibleAttributes
{
    public Dictionary<string, JsonElement> EntityAttributes { get; set; } = new();

    public string? EntityId { get; set; }

    public double? Fx { get; set; }

    public double? Fy { get; set; }

    public int? Index { get; set; }

    public string? Text { get; set; }

    public string? Type { get; set; }

    public double? X { get; set; }

    public double? Y { get; set; }
}

public sealed class GraphPosition : ExtensibleAttributes
{
    public double? Scale { get; set; }

    public double? X { get; set; }

    public double? Y { get; set; }
}

public sealed class CreateGraphRequest
{
    public CreateGraphData Data { get; set; } = new();
}

public sealed class CreateGraphData
{
    public ResourceType Type { get; set; } = ResourceType.Graph;

    public GraphWriteAttributes Attributes { get; set; } = new();
}

public sealed class UpdateGraphRequest
{
    public UpdateGraphData Data { get; set; } = new();
}

public sealed class UpdateGraphData
{
    public ResourceType Type { get; set; } = ResourceType.Graph;

    public GraphWriteAttributes Attributes { get; set; } = new();
}

public sealed class GraphWriteAttributes : ExtensibleAttributes
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public GraphData? GraphData { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<GraphConnection>? Links { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<GraphNode>? Nodes { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public GraphPosition? Position { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Private { get; set; }
}
