using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class Relationship
{
    public string Id { get; set; } = string.Empty;

    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
}

public sealed class RelationshipResponse
{
    public List<Relationship> Data { get; set; } = new();
}