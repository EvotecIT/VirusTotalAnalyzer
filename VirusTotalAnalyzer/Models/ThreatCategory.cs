using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class ThreatCategory
{
    public string Id { get; set; } = string.Empty;

    public string Type { get; set; } = string.Empty;

    public ThreatCategoryAttributes Attributes { get; set; } = new();
}

public sealed class ThreatCategoryAttributes
{
    public long Count { get; set; }
}

public sealed class ThreatCategoriesResponse
{
    public List<ThreatCategory> Data { get; set; } = new();
}