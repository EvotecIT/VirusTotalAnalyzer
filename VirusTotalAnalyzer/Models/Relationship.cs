using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class Relationship
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? Id { get; set; }

    public ResourceType Type { get; set; }

    /// <summary>
    /// Gets or sets a literal URL descriptor. Collection URL relationships accept either this
    /// value or the precomputed URL identifier in <see cref="Id"/>.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? Url { get; set; }

    public Links? Links { get; set; }
}

/// <summary>A compact VirusTotal object descriptor used in relationship mutation requests.</summary>
public sealed class RelationshipDescriptor
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? Id { get; set; }

    public ResourceType Type { get; set; }

    /// <summary>A literal URL accepted by collection URL relationships instead of a URL id.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? Url { get; set; }
}

public sealed class RelationshipResponse
{
    public List<Relationship> Data { get; set; } = new();
}
