using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class Meta
{
    [JsonPropertyName("cursor")]
    public string? Cursor { get; set; }
}

