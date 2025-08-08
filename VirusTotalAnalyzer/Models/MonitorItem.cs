using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class MonitorItem
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public MonitorItemData Data { get; set; } = new();
}

public sealed class MonitorItemData
{
    public MonitorItemAttributes Attributes { get; set; } = new();
}

public sealed class MonitorItemAttributes
{
    [JsonPropertyName("path")]
    public string Path { get; set; } = string.Empty;
}
