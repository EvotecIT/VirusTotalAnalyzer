

using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class FileClassificationAttributes
{
    public List<ThreatPopularity> PopularThreatName { get; set; } = new();

    public List<ThreatPopularity> PopularThreatCategory { get; set; } = new();

    public string? SuggestedThreatLabel { get; set; }
}

public sealed class ThreatPopularity
{
    public int Count { get; set; }

    public string? Value { get; set; }
}
