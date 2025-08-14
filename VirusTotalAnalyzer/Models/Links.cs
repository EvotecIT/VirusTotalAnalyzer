using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class Links
{
    public string Self { get; set; } = string.Empty;

    public Dictionary<string, string> Related { get; set; } = new();
}