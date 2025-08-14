using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class YaraWatcherResponse
{
    [JsonPropertyName("data")]
    public List<YaraWatcher> Data { get; set; } = new();
}

