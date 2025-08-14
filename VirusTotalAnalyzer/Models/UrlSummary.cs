using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class UrlSummary
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
    public UrlSummaryData Data { get; set; } = new();
}

public sealed class UrlSummaryData
{
    public UrlSummaryAttributes Attributes { get; set; } = new();
}

public sealed class UrlSummaryAttributes
{
    public string Url { get; set; } = string.Empty;

    public AnalysisStats LastAnalysisStats { get; set; } = new();

    public TotalVotes TotalVotes { get; set; } = new();
}

public sealed class UrlSummariesResponse
{
    public List<UrlSummary> Data { get; set; } = new();

    public PaginationMetadata? Meta { get; set; }
}

