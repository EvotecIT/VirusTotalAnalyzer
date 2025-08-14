using System.Collections.Generic;

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
    public string Name { get; set; } = string.Empty;

    public string Rules { get; set; } = string.Empty;

    public List<YaraWatcher>? Watchers { get; set; }
}

public sealed class YaraRulesetResponse
{
    public YaraRuleset? Data { get; set; }
}

public sealed class YaraRulesetsResponse
{
    public List<YaraRuleset> Data { get; set; } = new();

    public Meta? Meta { get; set; }
}

