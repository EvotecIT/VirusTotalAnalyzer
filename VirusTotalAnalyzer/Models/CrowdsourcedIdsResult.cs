using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class CrowdsourcedIdsResult
{
    [JsonPropertyName("rule_name")]
    public string? RuleName { get; set; }

    [JsonPropertyName("rule_id")]
    public string? RuleId { get; set; }

    [JsonPropertyName("ruleset_id")]
    public string? RulesetId { get; set; }

    [JsonPropertyName("ruleset_name")]
    public string? RulesetName { get; set; }

    [JsonPropertyName("source")]
    public string? Source { get; set; }

    [JsonPropertyName("alert_severity")]
    public int AlertSeverity { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }
}

public sealed class CrowdsourcedIdsResultsResponse
{
    [JsonPropertyName("data")]
    public List<CrowdsourcedIdsResult> Data { get; set; } = new();
}
