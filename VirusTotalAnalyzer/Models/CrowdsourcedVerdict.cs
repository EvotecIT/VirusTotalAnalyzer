using System;

namespace VirusTotalAnalyzer.Models;

public sealed class CrowdsourcedVerdict
{
    public string Source { get; set; } = string.Empty;

    public Verdict Verdict { get; set; }

    public DateTimeOffset Timestamp { get; set; }
}