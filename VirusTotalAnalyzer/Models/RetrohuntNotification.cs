using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalAnalyzer.Models;

public sealed class RetrohuntNotification
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }
    public RetrohuntNotificationData Data { get; set; } = new();
}

public sealed class RetrohuntNotificationData
{
    public RetrohuntNotificationAttributes Attributes { get; set; } = new();
}

public sealed class RetrohuntNotificationAttributes
{
    [JsonPropertyName("job_id")]
    public string JobId { get; set; } = string.Empty;
}

public sealed class RetrohuntNotificationsResponse
{
    [JsonPropertyName("data")]
    public List<RetrohuntNotification> Data { get; set; } = new();

    [JsonPropertyName("meta")]
    public Meta? Meta { get; set; }
}
