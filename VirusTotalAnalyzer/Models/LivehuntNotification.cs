using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class LivehuntNotification
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    [JsonPropertyName("links")]
    public Links Links { get; set; } = new();

    [JsonPropertyName("attributes")]
    public LivehuntNotificationAttributes Attributes { get; set; } = new();
}

public sealed class LivehuntNotificationResponse
{
    [JsonPropertyName("data")]
    public LivehuntNotification Data { get; set; } = new();
}

public sealed class LivehuntNotificationAttributes
{
    [JsonPropertyName("rule_name")]
    public string RuleName { get; set; } = string.Empty;
}

public sealed class LivehuntNotificationsResponse
{
    [JsonPropertyName("data")]
    public List<LivehuntNotification> Data { get; set; } = new();

    [JsonPropertyName("meta")]
    public Meta? Meta { get; set; }
}
