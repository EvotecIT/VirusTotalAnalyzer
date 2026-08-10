using System;
using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

/// <summary>Represents a file or folder stored in VirusTotal Monitor.</summary>
public sealed class MonitorItem
{
    public string Id { get; set; } = string.Empty;

    public string Type { get; set; } = string.Empty;

    public Links Links { get; set; } = new();

    public MonitorItemAttributes Attributes { get; set; } = new();
}

/// <summary>Describes VirusTotal Monitor item metadata.</summary>
public sealed class MonitorItemAttributes
{
    public long? Size { get; set; }

    public string? Sha1 { get; set; }

    public string? Sha256 { get; set; }

    public string? Md5 { get; set; }

    public DateTimeOffset? FirstDetectionDate { get; set; }

    public DateTimeOffset? NextAnalysisDate { get; set; }

    public DateTimeOffset? LastAnalysisDate { get; set; }

    public int? LastDetectionsCount { get; set; }

    public List<string> Tags { get; set; } = new();

    public DateTimeOffset? CreationDate { get; set; }

    public string ItemType { get; set; } = string.Empty;

    public string CreatorId { get; set; } = string.Empty;

    public Dictionary<string, AnalysisResult> LastAnalysisResults { get; set; } = new();

    public string? Details { get; set; }

    public string Path { get; set; } = string.Empty;
}

/// <summary>Configures publisher-provided metadata for a Monitor item.</summary>
public sealed class ConfigureMonitorItemRequest
{
    public ConfigureMonitorItemData Data { get; set; } = new();
}

public sealed class ConfigureMonitorItemData
{
    public string Id { get; set; } = string.Empty;

    public string Type { get; set; } = "monitoritem";

    public ConfigureMonitorItemAttributes Attributes { get; set; } = new();
}

public sealed class ConfigureMonitorItemAttributes
{
    public string Details { get; set; } = string.Empty;
}

/// <summary>Builds a supported VirusTotal Monitor item filter.</summary>
public sealed class MonitorItemFilter
{
    private MonitorItemFilter(string expression) => Expression = expression;

    public string Expression { get; }

    public static MonitorItemFilter ByPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !path.StartsWith("/", StringComparison.Ordinal))
        {
            throw new ArgumentException("A Monitor filter path must start with '/'.", nameof(path));
        }

        return new MonitorItemFilter($"path:{path}");
    }

    public static MonitorItemFilter ByItem(string itemId)
    {
        if (string.IsNullOrWhiteSpace(itemId))
        {
            throw new ArgumentException("A Monitor item id must not be empty.", nameof(itemId));
        }

        return new MonitorItemFilter($"item:{itemId}");
    }

    public static MonitorItemFilter ByTags(params string[] tags)
    {
        if (tags is null || tags.Length == 0)
        {
            throw new ArgumentException("At least one Monitor tag is required.", nameof(tags));
        }
        foreach (var tag in tags)
        {
            if (string.IsNullOrWhiteSpace(tag) || tag.IndexOfAny(new[] { ' ', '\t', '\r', '\n' }) >= 0)
            {
                throw new ArgumentException("Monitor tags must be non-empty and cannot contain whitespace.", nameof(tags));
            }
        }

        return new MonitorItemFilter($"tag:{string.Join(" ", tags)}");
    }

    public static MonitorItemFilter Raw(string expression)
    {
        if (string.IsNullOrWhiteSpace(expression))
        {
            throw new ArgumentException("A Monitor filter expression must not be empty.", nameof(expression));
        }

        return new MonitorItemFilter(expression);
    }

    public override string ToString() => Expression;
}
