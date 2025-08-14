using System;
using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class DomainReport
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();

    public DomainAttributes Attributes { get; set; } = new();
}

public sealed class DomainReportResponse
{
    public DomainReport Data { get; set; } = new();
}

public sealed class DomainReportsResponse
{
    public List<DomainReport> Data { get; set; } = new();

    public PaginationMetadata? Meta { get; set; }
}

public sealed class DomainAttributes
{
    public string Domain { get; set; } = string.Empty;

    public int Reputation { get; set; }

    public DateTimeOffset CreationDate { get; set; }

    public List<string> Tags { get; set; } = new();

    public AnalysisStats LastAnalysisStats { get; set; } = new();

    public Dictionary<string, AnalysisResult> LastAnalysisResults { get; set; } = new();

    public TotalVotes TotalVotes { get; set; } = new();

    public Dictionary<string, Verdict> Categories { get; set; } = new();

    public DateTimeOffset LastAnalysisDate { get; set; }
}