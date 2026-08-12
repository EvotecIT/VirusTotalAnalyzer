namespace VirusTotalAnalyzer.Models;

public sealed class CrowdsourcedYaraResult : ExtensibleAttributes
{
    public string? RuleName { get; set; }

    public string? RulesetId { get; set; }

    public string? RulesetName { get; set; }

    public string? Source { get; set; }

    public string? Author { get; set; }

    public string? Description { get; set; }

    public bool? MatchInSubfile { get; set; }
}
