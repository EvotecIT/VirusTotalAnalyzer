using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class CrowdsourcedIdsResult
{
    public string? RuleName { get; set; }

    public string? RuleId { get; set; }

    public string? RulesetId { get; set; }

    public string? RulesetName { get; set; }

    public string? Source { get; set; }

    public int AlertSeverity { get; set; }

    public string? Description { get; set; }
}

public sealed class CrowdsourcedIdsResultsResponse
{
    public List<CrowdsourcedIdsResult> Data { get; set; } = new();
}