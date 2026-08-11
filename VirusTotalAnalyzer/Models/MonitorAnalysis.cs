using System;
using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

/// <summary>Represents a historical analysis of a VirusTotal Monitor item.</summary>
public sealed class MonitorAnalysis
{
    public string Id { get; set; } = string.Empty;

    public string Type { get; set; } = string.Empty;

    public MonitorAnalysisAttributes Attributes { get; set; } = new();
}

public sealed class MonitorAnalysisAttributes
{
    public Dictionary<string, AnalysisResult> AnalysisResults { get; set; } = new();

    public DateTimeOffset Date { get; set; }

    public int DetectionsCount { get; set; }

    public string Sha256 { get; set; } = string.Empty;

    public List<string> Tags { get; set; } = new();
}

/// <summary>Represents a Monitor partner comment associated with an item hash.</summary>
public sealed class MonitorItemComment
{
    public string Id { get; set; } = string.Empty;

    public string Type { get; set; } = string.Empty;

    public MonitorItemCommentAttributes Attributes { get; set; } = new();
}

public sealed class MonitorItemCommentAttributes
{
    public string Comment { get; set; } = string.Empty;

    public DateTimeOffset Date { get; set; }

    public string Detection { get; set; } = string.Empty;

    public string Engine { get; set; } = string.Empty;

    public string Sha256 { get; set; } = string.Empty;
}
