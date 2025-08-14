using System;
using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class FileReport
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();

    public FileAttributes Attributes { get; set; } = new();
}

public sealed class FileReportResponse
{
    public FileReport Data { get; set; } = new();
}

public sealed class FileAttributes
{
    public string Md5 { get; set; } = string.Empty;

    public string? Sha256 { get; set; }

    public int Reputation { get; set; }

    public DateTimeOffset CreationDate { get; set; }

    public List<string> Tags { get; set; } = new();

    public long Size { get; set; }

    public DateTimeOffset FirstSubmissionDate { get; set; }

    public DateTimeOffset LastSubmissionDate { get; set; }

    public DateTimeOffset LastModificationDate { get; set; }

    public int TimesSubmitted { get; set; }

    public string? MeaningfulName { get; set; }

    public List<string> Names { get; set; } = new();

    public AnalysisStats LastAnalysisStats { get; set; } = new();

    public Dictionary<string, AnalysisResult> LastAnalysisResults { get; set; } = new();

    public TotalVotes TotalVotes { get; set; } = new();

    public Dictionary<string, Verdict> Categories { get; set; } = new();

    public DateTimeOffset LastAnalysisDate { get; set; }

    public List<CrowdsourcedVerdict> CrowdsourcedVerdicts { get; set; } = new();
}

public sealed class FileReportsResponse
{
    public List<FileReport> Data { get; set; } = new();

    public PaginationMetadata? Meta { get; set; }
}

