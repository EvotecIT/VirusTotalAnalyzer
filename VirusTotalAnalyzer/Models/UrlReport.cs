using System;
using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class UrlReport
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();

    public UrlAttributes Attributes { get; set; } = new();
}

public sealed class UrlReportResponse
{
    public UrlReport Data { get; set; } = new();
}

public sealed class UrlReportsResponse
{
    public List<UrlReport> Data { get; set; } = new();

    public PaginationMetadata? Meta { get; set; }
}

public sealed class UrlAttributes
{
    public string Url { get; set; } = string.Empty;

    public int Reputation { get; set; }

    public DateTimeOffset CreationDate { get; set; }

    public List<string> Tags { get; set; } = new();

    public DateTimeOffset FirstSubmissionDate { get; set; }

    public DateTimeOffset LastSubmissionDate { get; set; }

    public DateTimeOffset LastModificationDate { get; set; }

    public int TimesSubmitted { get; set; }

    public AnalysisStats LastAnalysisStats { get; set; } = new();

    public Dictionary<string, AnalysisResult> LastAnalysisResults { get; set; } = new();

    public TotalVotes TotalVotes { get; set; } = new();

    public Dictionary<string, Verdict> Categories { get; set; } = new();

    public DateTimeOffset LastAnalysisDate { get; set; }

    public List<CrowdsourcedVerdict> CrowdsourcedVerdicts { get; set; } = new();
}