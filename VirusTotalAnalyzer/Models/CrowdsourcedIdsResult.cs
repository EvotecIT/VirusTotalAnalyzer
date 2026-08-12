using System.Collections.Generic;

namespace VirusTotalAnalyzer.Models;

public sealed class CrowdsourcedIdsResult : ExtensibleAttributes
{
    public List<CrowdsourcedIdsAlertContext> AlertContext { get; set; } = new();

    public string? AlertSeverity { get; set; }

    public string? RuleCategory { get; set; }

    public string? RuleId { get; set; }

    public string? RuleMsg { get; set; }

    public string? RuleSource { get; set; }
}

public sealed class CrowdsourcedIdsAlertContext : ExtensibleAttributes
{
    public string? DestIp { get; set; }

    public int? DestPort { get; set; }

    public string? Hostname { get; set; }

    public string? Protocol { get; set; }

    public string? SrcIp { get; set; }

    public int? SrcPort { get; set; }

    public string? Url { get; set; }
}
