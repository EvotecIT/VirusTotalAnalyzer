using System;
using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class PrivateAnalysis
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
    public PrivateAnalysisData Data { get; set; } = new();
}

public sealed class PrivateAnalysisData
{
    public PrivateAnalysisAttributes Attributes { get; set; } = new();
}

public sealed class PrivateAnalysisAttributes
{
    public AnalysisStatus Status { get; set; }

    public AnalysisStats Stats { get; set; } = new();

    public Dictionary<string, AnalysisResult> Results { get; set; } = new();

    public DateTimeOffset Date { get; set; }

    public string? Error { get; set; }
}