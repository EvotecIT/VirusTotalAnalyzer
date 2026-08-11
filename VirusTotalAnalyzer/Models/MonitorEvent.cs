using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

/// <summary>Represents a historical VirusTotal Monitor event.</summary>
public sealed class MonitorEvent
{
    public MonitorEventAction Action { get; set; }

    public string CreatorId { get; set; } = string.Empty;

    public List<MonitorEventDetail> Details { get; set; } = new();

    [JsonNumberHandling(JsonNumberHandling.AllowReadingFromString)]
    public int Level { get; set; }

    public string MonitorKey { get; set; } = string.Empty;

    public string OwnerId { get; set; } = string.Empty;

    public string? PlaintextDescription { get; set; }

    public MonitorEventSource Source { get; set; }

    public string? Subject { get; set; }

    public DateTimeOffset Timestamp { get; set; }
}

public sealed class MonitorEventDetail
{
    public string V { get; set; } = string.Empty;
}

public enum MonitorEventAction
{
    Unknown,

    [EnumMember(Value = "CLEAN")]
    Clean,

    [EnumMember(Value = "COMMENT")]
    Comment,

    [EnumMember(Value = "DELETE")]
    Delete,

    [EnumMember(Value = "DETECTED")]
    Detected,

    [EnumMember(Value = "UPLOAD")]
    Upload,

    [EnumMember(Value = "RESOLVED")]
    Resolved
}

public enum MonitorEventSource
{
    Unknown,

    [EnumMember(Value = "ANALYSIS")]
    Analysis,

    [EnumMember(Value = "FILE")]
    File,

    [EnumMember(Value = "QUOTA")]
    Quota
}
