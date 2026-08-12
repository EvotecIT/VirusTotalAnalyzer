using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class ThreatCategoriesResponse
{
    public List<string> Data { get; set; } = new();
}
