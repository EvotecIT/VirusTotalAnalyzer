using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class YaraRulesetRequest
{
    public YaraRulesetRequestData Data { get; set; } = new();
}

public sealed class YaraRulesetRequestData
{
    public string Type { get; set; } = "intelligence_hunting_ruleset";

    public YaraRulesetRequestAttributes Attributes { get; set; } = new();
}

public sealed class YaraRulesetRequestAttributes
{
    public string Name { get; set; } = string.Empty;

    public string Rules { get; set; } = string.Empty;

    public List<YaraWatcher>? Watchers { get; set; }
}

