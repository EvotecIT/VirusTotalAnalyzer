

namespace VirusTotalAnalyzer.Models;

public sealed class MonitorEvent
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
    public MonitorEventData Data { get; set; } = new();
}

public sealed class MonitorEventData
{
    public MonitorEventAttributes Attributes { get; set; } = new();
}

public sealed class MonitorEventAttributes
{
    public string ItemId { get; set; } = string.Empty;

    public string Path { get; set; } = string.Empty;

    public string EventType { get; set; } = string.Empty;
}

