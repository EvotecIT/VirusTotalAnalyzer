using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class CrowdsourcedYaraResult
{
    [JsonPropertyName("rule_name")]
    public string? RuleName { get; set; }

    [JsonPropertyName("ruleset_id")]
    public string? RulesetId { get; set; }

    [JsonPropertyName("ruleset_name")]
    public string? RulesetName { get; set; }

    [JsonPropertyName("source")]
    public string? Source { get; set; }

    [JsonPropertyName("author")]
    public string? Author { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }
}

public sealed class CrowdsourcedYaraResultsResponse
{
    [JsonPropertyName("data")]
    public List<CrowdsourcedYaraResult> Data { get; set; } = new();
}
