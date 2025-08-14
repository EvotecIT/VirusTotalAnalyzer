using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class DomainSummary
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
    public DomainSummaryData Data { get; set; } = new();
}

public sealed class DomainSummaryData
{
    public DomainSummaryAttributes Attributes { get; set; } = new();
}

public sealed class DomainSummaryAttributes
{
    public string Domain { get; set; } = string.Empty;

    public AnalysisStats LastAnalysisStats { get; set; } = new();

    public TotalVotes TotalVotes { get; set; } = new();
}

public sealed class DomainSummariesResponse
{
    public List<DomainSummary> Data { get; set; } = new();

    public PaginationMetadata? Meta { get; set; }
}

