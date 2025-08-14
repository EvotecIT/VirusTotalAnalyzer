using System;
using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class AnalysisReport
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
    public AnalysisData Data { get; set; } = new();
}

public sealed class AnalysisData
{
    public AnalysisAttributes Attributes { get; set; } = new();
}

public sealed class AnalysisAttributes
{
    public AnalysisStatus Status { get; set; }

    public AnalysisStats Stats { get; set; } = new();

    public Dictionary<string, AnalysisResult> Results { get; set; } = new();

    public DateTimeOffset Date { get; set; }

    public string? Error { get; set; }
}

public sealed class AnalysisReportsResponse
{
    public List<AnalysisReport> Data { get; set; } = new();

    public PaginationMetadata? Meta { get; set; }
}