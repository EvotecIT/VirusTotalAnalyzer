using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class FileStringsResponse
{
    [JsonPropertyName("data")]
    public List<string> Data { get; set; } = new();
}
