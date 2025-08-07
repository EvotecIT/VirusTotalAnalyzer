namespace VirusTotalAnalyzer;

/// <summary>
/// Status values returned by the VirusTotal analysis endpoints.
/// </summary>
using System.Runtime.Serialization;

public enum AnalysisStatus
{
    [EnumMember(Value = "queued")]
    Queued,

    [EnumMember(Value = "in-progress")]
    InProgress,

    [EnumMember(Value = "completed")]
    Completed,

    [EnumMember(Value = "error")]
    Error,

    [EnumMember(Value = "cancelled")]
    Cancelled,

    [EnumMember(Value = "timeout")]
    Timeout
}
