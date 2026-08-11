using System;
using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

/// <summary>Represents one historical VirusTotal Monitor statistics period.</summary>
public sealed class MonitorStatistics
{
    public string Id { get; set; } = string.Empty;

    public string Type { get; set; } = string.Empty;

    public MonitorStatisticsAttributes Attributes { get; set; } = new();
}

public sealed class MonitorStatisticsAttributes
{
    public DateTimeOffset Date { get; set; }

    public int ItemsDetectedCount { get; set; }

    public int IncreasingDetectionsCount { get; set; }

    public string OwnerId { get; set; } = string.Empty;

    public string Period { get; set; } = string.Empty;

    public long StorageBytesCount { get; set; }

    public long StorageFilesCount { get; set; }

    public List<MonitorTopAgeItem> TopAgeItems { get; set; } = new();

    public List<MonitorTopDetectedItem> TopDetectedItems { get; set; } = new();

    public List<MonitorTopEngine> TopEngines { get; set; } = new();

    public List<MonitorTopSignature> TopSignatures { get; set; } = new();
}

public sealed class MonitorTopAgeItem
{
    public long Age { get; set; }

    public int DetectionsCount { get; set; }

    public string MonitorKey { get; set; } = string.Empty;

    public int TotalEnginesCount { get; set; }
}

public sealed class MonitorTopDetectedItem
{
    public int DetectionsCount { get; set; }

    public string MonitorKey { get; set; } = string.Empty;

    public int TotalEnginesCount { get; set; }
}

public sealed class MonitorTopEngine
{
    public int Count { get; set; }

    public string Engine { get; set; } = string.Empty;
}

public sealed class MonitorTopSignature
{
    public int Count { get; set; }

    public string Signature { get; set; } = string.Empty;
}

public sealed class MonitorStatisticsResponse
{
    public List<MonitorStatistics> Data { get; set; } = new();

    public MonitorStatisticsMeta Meta { get; set; } = new();

    public Links? Links { get; set; }
}

public sealed class MonitorStatisticsMeta
{
    public string? Cursor { get; set; }

    public MonitorRealtimeStatistics Realtime { get; set; } = new();
}

public sealed class MonitorRealtimeStatistics
{
    public int DecreasingDetectionsCount { get; set; }

    public int IncreasingDetectionsCount { get; set; }

    public int ItemsDetectedCount { get; set; }

    public int NewDetectionsCount { get; set; }

    public int SolvedDetectionsCount { get; set; }

    public int SwappedDetectionsCount { get; set; }
}
