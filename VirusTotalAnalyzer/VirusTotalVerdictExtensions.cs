using System;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

/// <summary>Creates concise verdicts while preserving the complete VirusTotal report.</summary>
public static class VirusTotalVerdictExtensions
{
    public static VirusTotalVerdict ToVerdict(this FileReport report)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));
        return Create(report.Id, ResourceType.File, report.Attributes.LastAnalysisStats,
            report.Attributes.Reputation, report.Attributes.LastAnalysisDate, report);
    }

    public static VirusTotalVerdict ToVerdict(this UrlReport report)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));
        return Create(report.Id, ResourceType.Url, report.Attributes.LastAnalysisStats,
            report.Attributes.Reputation, report.Attributes.LastAnalysisDate, report);
    }

    public static VirusTotalVerdict ToVerdict(this DomainReport report)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));
        return Create(report.Id, ResourceType.Domain, report.Attributes.LastAnalysisStats,
            report.Attributes.Reputation, report.Attributes.LastAnalysisDate, report);
    }

    public static VirusTotalVerdict ToVerdict(this IpAddressReport report)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));
        return Create(report.Id, ResourceType.IpAddress, report.Attributes.LastAnalysisStats,
            report.Attributes.Reputation, report.Attributes.LastAnalysisDate, report);
    }

    public static VirusTotalVerdict ToVerdict(this AnalysisReport report)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));
        return Create(report.Id, ResourceType.Analysis, report.Attributes.Stats,
            null, report.Attributes.Date, report);
    }

    private static VirusTotalVerdict Create(
        string id,
        ResourceType resourceType,
        AnalysisStats? stats,
        int? reputation,
        DateTimeOffset? lastAnalysisDate,
        object report)
    {
        stats ??= new AnalysisStats();
        return new VirusTotalVerdict
        {
            Id = id,
            ResourceType = resourceType,
            Verdict = Classify(stats),
            Malicious = stats.Malicious,
            Suspicious = stats.Suspicious,
            Harmless = stats.Harmless,
            Undetected = stats.Undetected,
            Timeout = stats.Timeout,
            ConfirmedTimeout = stats.ConfirmedTimeout,
            Failure = stats.Failure,
            TypeUnsupported = stats.TypeUnsupported,
            Total = stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected +
                    stats.Timeout + stats.ConfirmedTimeout + stats.Failure + stats.TypeUnsupported,
            Reputation = reputation,
            LastAnalysisDate = lastAnalysisDate,
            Permalink = CreatePermalink(resourceType, id),
            Report = report
        };
    }

    private static VirusTotalVerdictKind Classify(AnalysisStats stats)
    {
        if (stats.Malicious > 0)
            return VirusTotalVerdictKind.Malicious;
        if (stats.Suspicious > 0)
            return VirusTotalVerdictKind.Suspicious;
        if (stats.Harmless > 0)
            return VirusTotalVerdictKind.Harmless;
        if (stats.Undetected > 0)
            return VirusTotalVerdictKind.Undetected;
        return VirusTotalVerdictKind.Unknown;
    }

    private static Uri? CreatePermalink(ResourceType resourceType, string id)
    {
        var segment = resourceType switch
        {
            ResourceType.File => "file",
            ResourceType.Url => "url",
            ResourceType.Domain => "domain",
            ResourceType.IpAddress => "ip-address",
            _ => null
        };
        return segment is null || string.IsNullOrWhiteSpace(id)
            ? null
            : new Uri($"https://www.virustotal.com/gui/{segment}/{Uri.EscapeDataString(id)}");
    }
}
