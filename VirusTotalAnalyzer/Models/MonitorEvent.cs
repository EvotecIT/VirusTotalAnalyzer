using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class MonitorEvent
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public MonitorEventData Data { get; set; } = new();
}

public sealed class MonitorEventData
{
    public MonitorEventAttributes Attributes { get; set; } = new();
}

public sealed class MonitorEventAttributes
{
    [JsonPropertyName("item_id")]
    public string ItemId { get; set; } = string.Empty;

    [JsonPropertyName("path")]
    public string Path { get; set; } = string.Empty;

    [JsonPropertyName("event_type")]
    public string EventType { get; set; } = string.Empty;
}

