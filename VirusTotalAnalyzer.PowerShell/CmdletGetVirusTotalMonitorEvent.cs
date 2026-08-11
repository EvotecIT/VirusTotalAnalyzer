using System.Management.Automation;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.PowerShell;

/// <summary>Gets historical VirusTotal Monitor events.</summary>
/// <example>
///   <summary>Read one event page and retain its continuation metadata.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>$page = Get-VirusTotalMonitorEvent -ApiKey $ApiKey; $next = Get-VirusTotalMonitorEvent -ApiKey $ApiKey -Cursor $page.Meta.Cursor -JobId $page.Meta.JobId</para>
///   </code>
///   <para>The default mode returns the full page so both cursor and job identifier remain available.</para>
/// </example>
/// <example>
///   <summary>Stream every available Monitor event.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>Get-VirusTotalMonitorEvent -ApiKey $ApiKey -All</para>
///   </code>
/// </example>
[Cmdlet(VerbsCommon.Get, "VirusTotalMonitorEvent")]
[OutputType(typeof(MonitorEvent), typeof(PagedResponse<MonitorEvent>))]
public sealed class CmdletGetVirusTotalMonitorEvent : VirusTotalCmdlet
{
    /// <summary>Optional VirusTotal Monitor filter expression.</summary>
    [Parameter]
    public string? Filter { get; set; }

    /// <summary>Cursor at which to begin reading events.</summary>
    [Parameter]
    public string? Cursor { get; set; }

    /// <summary>Event job identifier returned by a previous page.</summary>
    [Parameter]
    public string? JobId { get; set; }

    /// <summary>Reads every page until VirusTotal returns no cursor.</summary>
    [Parameter]
    public SwitchParameter All { get; set; }

    /// <inheritdoc/>
    protected override async Task ProcessRecordAsync()
    {
        try
        {
            if (All)
            {
                await foreach (var monitorEvent in ActiveClient.EnumerateMonitorEventsAsync(Filter, Cursor, JobId, CancelToken))
                {
                    WriteObject(monitorEvent);
                }
                return;
            }

            var page = await ActiveClient.ListMonitorEventsAsync(Filter, Cursor, JobId, CancelToken).ConfigureAwait(false);
            if (page is not null)
            {
                WriteObject(page);
            }
        }
        catch (ApiException exception)
        {
            WriteApiError(exception, Filter);
        }
    }
}
