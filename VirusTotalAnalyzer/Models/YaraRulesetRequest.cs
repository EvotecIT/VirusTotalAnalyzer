using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class YaraRulesetRequest
{
    [JsonPropertyName("data")]
    public YaraRulesetRequestData Data { get; set; } = new();
}

public sealed class YaraRulesetRequestData
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "intelligence_hunting_ruleset";

    [JsonPropertyName("attributes")]
    public YaraRulesetRequestAttributes Attributes { get; set; } = new();
}

public sealed class YaraRulesetRequestAttributes
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("rules")]
    public string Rules { get; set; } = string.Empty;

    [JsonPropertyName("watchers")]
    public List<YaraWatcher>? Watchers { get; set; }
}

