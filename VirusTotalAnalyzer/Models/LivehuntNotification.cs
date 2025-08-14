using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class LivehuntNotification
{
    public string Id { get; set; } = string.Empty;
    public ResourceType Type { get; set; }

    public Links Links { get; set; } = new();

    public LivehuntNotificationAttributes Attributes { get; set; } = new();
}

public sealed class LivehuntNotificationResponse
{
    public LivehuntNotification Data { get; set; } = new();
}

public sealed class LivehuntNotificationAttributes
{
    public string RuleName { get; set; } = string.Empty;
}

public sealed class LivehuntNotificationsResponse
{
    public List<LivehuntNotification> Data { get; set; } = new();

    public Meta? Meta { get; set; }
}