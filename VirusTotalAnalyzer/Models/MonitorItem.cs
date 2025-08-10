using System.Collections.Generic;
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

public sealed class MonitorItemsResponse
{
    [JsonPropertyName("data")]
    public List<MonitorItem> Data { get; set; } = new();

    [JsonPropertyName("meta")]
    public Meta? Meta { get; set; }
}

public sealed class CreateMonitorItemRequest
{
    [JsonPropertyName("data")]
    public CreateMonitorItemData Data { get; set; } = new();
}

public sealed class CreateMonitorItemData
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "monitor_item";

    [JsonPropertyName("attributes")]
    public CreateMonitorItemAttributes Attributes { get; set; } = new();
}

public sealed class CreateMonitorItemAttributes
{
    [JsonPropertyName("path")]
    public string Path { get; set; } = string.Empty;
}

public sealed class UpdateMonitorItemRequest
{
    [JsonPropertyName("data")]
    public UpdateMonitorItemData Data { get; set; } = new();
}

public sealed class UpdateMonitorItemData
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "monitor_item";

    [JsonPropertyName("attributes")]
    public UpdateMonitorItemAttributes Attributes { get; set; } = new();
}

public sealed class UpdateMonitorItemAttributes
{
    [JsonPropertyName("path")]
    public string? Path { get; set; }
}
