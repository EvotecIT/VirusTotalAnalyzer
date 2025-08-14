using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class Links
{
    [JsonPropertyName("self")]
    public string Self { get; set; } = string.Empty;

    [JsonPropertyName("related")]
    public Dictionary<string, string> Related { get; set; } = new();
}
