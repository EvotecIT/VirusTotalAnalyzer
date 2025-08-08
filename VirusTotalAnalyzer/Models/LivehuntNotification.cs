using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class LivehuntNotification
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public LivehuntNotificationData Data { get; set; } = new();
}

public sealed class LivehuntNotificationData
{
    public LivehuntNotificationAttributes Attributes { get; set; } = new();
}

public sealed class LivehuntNotificationAttributes
{
    [JsonPropertyName("rule_name")]
    public string RuleName { get; set; } = string.Empty;
}
