

namespace VirusTotalAnalyzer.Models;

public sealed class MonitorItem
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
    public MonitorItemData Data { get; set; } = new();
}

public sealed class MonitorItemData
{
    public MonitorItemAttributes Attributes { get; set; } = new();
}

public sealed class MonitorItemAttributes
{
    public string Path { get; set; } = string.Empty;
}

public sealed class CreateMonitorItemRequest
{
    public CreateMonitorItemData Data { get; set; } = new();
}

public sealed class CreateMonitorItemData
{
    public string Type { get; set; } = "monitor_item";

    public CreateMonitorItemAttributes Attributes { get; set; } = new();
}

public sealed class CreateMonitorItemAttributes
{
    public string Path { get; set; } = string.Empty;
}

public sealed class UpdateMonitorItemRequest
{
    public UpdateMonitorItemData Data { get; set; } = new();
}

public sealed class UpdateMonitorItemData
{
    public string Type { get; set; } = "monitor_item";

    public UpdateMonitorItemAttributes Attributes { get; set; } = new();
}

public sealed class UpdateMonitorItemAttributes
{
    public string? Path { get; set; }
}