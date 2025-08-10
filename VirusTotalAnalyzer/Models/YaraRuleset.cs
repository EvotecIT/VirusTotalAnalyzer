using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class YaraRuleset
{
    public string Id { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public YaraRulesetData Data { get; set; } = new();
}

public sealed class YaraRulesetData
{
    public YaraRulesetAttributes Attributes { get; set; } = new();
}

public sealed class YaraRulesetAttributes
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("rules")]
    public string Rules { get; set; } = string.Empty;

    [JsonPropertyName("watchers")]
    public List<YaraWatcher>? Watchers { get; set; }
}

public sealed class YaraRulesetResponse
{
    [JsonPropertyName("data")]
    public YaraRuleset? Data { get; set; }
}

public sealed class YaraRulesetsResponse
{
    [JsonPropertyName("data")]
    public List<YaraRuleset> Data { get; set; } = new();

    [JsonPropertyName("meta")]
    public Meta? Meta { get; set; }
}

