using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class PaginationMetadata
{
    [JsonPropertyName("cursor")]
    public string? Cursor { get; set; }
}
