using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class FileBehaviorSummary
{
    public BehaviorSummaryData Data { get; set; } = new();
}

public sealed class BehaviorSummaryData
{
    public List<string> Tags { get; set; } = new();
}