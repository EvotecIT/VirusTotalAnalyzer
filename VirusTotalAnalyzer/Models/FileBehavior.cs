using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class FileBehavior
{
    public List<BehaviorEntry> Data { get; set; } = new();
}

public sealed class BehaviorEntry
{
    public string Id { get; set; } = string.Empty;

    public string Type { get; set; } = string.Empty;

    public BehaviorAttributes Attributes { get; set; } = new();
}

public sealed class BehaviorAttributes
{
    public List<BehaviorProcess> Processes { get; set; } = new();
}

public sealed class BehaviorProcess
{
    public string? Name { get; set; }
}