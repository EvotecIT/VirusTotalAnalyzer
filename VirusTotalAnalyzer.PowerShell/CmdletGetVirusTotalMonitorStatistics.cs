using System.Management.Automation;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.PowerShell;

/// <summary>Gets VirusTotal Monitor publisher statistics.</summary>
/// <example>
///   <summary>Get current and historical publisher statistics.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>Get-VirusTotalMonitorStatistics -ApiKey $ApiKey</para>
///   </code>
/// </example>
[Cmdlet(VerbsCommon.Get, "VirusTotalMonitorStatistics")]
[OutputType(typeof(MonitorStatisticsResponse))]
public sealed class CmdletGetVirusTotalMonitorStatistics : VirusTotalCmdlet
{
    /// <summary>Maximum number of ranked entries requested.</summary>
    [Parameter]
    [ValidateRange(1, int.MaxValue)]
    public int? Limit { get; set; }

    /// <summary>Pagination cursor.</summary>
    [Parameter]
    public string? Cursor { get; set; }

    /// <inheritdoc/>
    protected override async Task ProcessRecordAsync()
    {
        try
        {
            WriteObject(await ActiveClient.GetMonitorStatisticsAsync(Limit, Cursor, CancelToken).ConfigureAwait(false));
        }
        catch (ApiException exception)
        {
            WriteApiError(exception);
        }
    }
}
