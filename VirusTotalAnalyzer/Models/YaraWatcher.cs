using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class YaraWatcher
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;
}

