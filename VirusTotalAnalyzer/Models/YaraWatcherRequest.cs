using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class YaraWatcherRequest
{
    [JsonPropertyName("data")]
    public List<YaraWatcher> Data { get; set; } = new();
}

