using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class FileBehavior
{
    [JsonPropertyName("data")]
    public List<BehaviorEntry> Data { get; set; } = new();
}

public sealed class BehaviorEntry
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("attributes")]
    public BehaviorAttributes Attributes { get; set; } = new();
}

public sealed class BehaviorAttributes
{
    [JsonPropertyName("processes")]
    public List<BehaviorProcess> Processes { get; set; } = new();
}

public sealed class BehaviorProcess
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }
}
