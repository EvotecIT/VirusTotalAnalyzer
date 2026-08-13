namespace VirusTotalAnalyzer.Models;

/// <summary>Provides a pipeline-friendly view of one VirusTotal account quota.</summary>
public sealed class VirusTotalQuotaStatus
{
    public string Name { get; set; } = string.Empty;
    public long Allowed { get; set; }
    public long Used { get; set; }
    public long Remaining => Allowed > Used ? Allowed - Used : 0;
    public double PercentUsed => Allowed > 0 ? Used * 100d / Allowed : 0d;
}
