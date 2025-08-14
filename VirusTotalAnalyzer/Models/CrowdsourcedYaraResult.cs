using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class CrowdsourcedYaraResult
{
    public string? RuleName { get; set; }

    public string? RulesetId { get; set; }

    public string? RulesetName { get; set; }

    public string? Source { get; set; }

    public string? Author { get; set; }

    public string? Description { get; set; }
}

public sealed class CrowdsourcedYaraResultsResponse
{
    public List<CrowdsourcedYaraResult> Data { get; set; } = new();
}