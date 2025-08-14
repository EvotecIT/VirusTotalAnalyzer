using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class IpAddressSummary
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
    public IpAddressSummaryData Data { get; set; } = new();
}

public sealed class IpAddressSummaryResponse
{
    public IpAddressSummary Data { get; set; } = new();
}

public sealed class IpAddressSummaryData
{
    public IpAddressSummaryAttributes Attributes { get; set; } = new();
}

public sealed class IpAddressSummaryAttributes
{
    public string IpAddress { get; set; } = string.Empty;

    public AnalysisStats LastAnalysisStats { get; set; } = new();

    public TotalVotes TotalVotes { get; set; } = new();
}

public sealed class IpAddressSummariesResponse
{
    public List<IpAddressSummary> Data { get; set; } = new();

    public PaginationMetadata? Meta { get; set; }
}

