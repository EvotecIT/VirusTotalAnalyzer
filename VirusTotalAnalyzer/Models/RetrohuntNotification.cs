using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class RetrohuntNotification
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();
    public RetrohuntNotificationData Data { get; set; } = new();
}

public sealed class RetrohuntNotificationData
{
    public RetrohuntNotificationAttributes Attributes { get; set; } = new();
}

public sealed class RetrohuntNotificationAttributes
{
    public string JobId { get; set; } = string.Empty;
}

public sealed class RetrohuntNotificationsResponse
{
    public List<RetrohuntNotification> Data { get; set; } = new();

    public Meta? Meta { get; set; }
}