using System;
using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class FileBehavior
{
    public List<BehaviorEntry> Data { get; set; } = new();

    public Meta? Meta { get; set; }

    public Links? Links { get; set; }
}

public sealed class BehaviorEntry
{
    public string Id { get; set; } = string.Empty;

    public string Type { get; set; } = string.Empty;

    public BehaviorAttributes Attributes { get; set; } = new();
}

public sealed class BehaviorAttributes : ExtensibleAttributes
{
    public List<BehaviorProcess> Processes { get; set; } = new();

    public List<BehaviorProcess> ProcessesTree { get; set; } = new();

    public string? SandboxName { get; set; }

    public DateTimeOffset? AnalysisDate { get; set; }

    public DateTimeOffset? LastModificationDate { get; set; }

    public bool? HasHtmlReport { get; set; }

    public bool? HasEvtx { get; set; }

    public bool? HasPcap { get; set; }

    public bool? HasMemdump { get; set; }
}

public sealed class BehaviorProcess
{
    public string? ProcessId { get; set; }

    public string? Name { get; set; }

    public List<BehaviorProcess> Children { get; set; } = new();
}
