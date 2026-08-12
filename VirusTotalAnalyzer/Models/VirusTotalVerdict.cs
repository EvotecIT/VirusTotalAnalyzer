using System;

namespace VirusTotalAnalyzer.Models;

/// <summary>Provides a concise pipeline-friendly view of a VirusTotal report.</summary>
public sealed class VirusTotalVerdict
{
    public string Id { get; set; } = string.Empty;
    public ResourceType ResourceType { get; set; }
    public VirusTotalVerdictKind Verdict { get; set; }
    public int Malicious { get; set; }
    public int Suspicious { get; set; }
    public int Harmless { get; set; }
    public int Undetected { get; set; }
    public int Timeout { get; set; }
    public int ConfirmedTimeout { get; set; }
    public int Failure { get; set; }
    public int TypeUnsupported { get; set; }
    public int Total { get; set; }
    public int? Reputation { get; set; }
    public DateTimeOffset? LastAnalysisDate { get; set; }
    public Uri? Permalink { get; set; }

    /// <summary>Gets or sets the complete source report.</summary>
    public object Report { get; set; } = null!;
}

/// <summary>Represents the highest-severity engine result in a VirusTotal report.</summary>
public enum VirusTotalVerdictKind
{
    Unknown = 0,
    Undetected = 1,
    Harmless = 2,
    Suspicious = 3,
    Malicious = 4
}
