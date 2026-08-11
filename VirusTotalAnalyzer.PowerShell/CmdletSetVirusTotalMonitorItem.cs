using System.Management.Automation;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.PowerShell;

/// <summary>Sets publisher details on a VirusTotal Monitor item.</summary>
/// <example>
///   <summary>Update publisher details for an uploaded item.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>Set-VirusTotalMonitorItem -ApiKey $ApiKey -Id 'monitor-item-id' -Details 'Signed release build'</para>
///   </code>
/// </example>
[Cmdlet(VerbsCommon.Set, "VirusTotalMonitorItem", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.Medium)]
[OutputType(typeof(MonitorItem))]
public sealed class CmdletSetVirusTotalMonitorItem : VirusTotalCmdlet
{
    /// <summary>Identifier of the Monitor item to configure.</summary>
    [Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    public string Id { get; set; } = string.Empty;

    /// <summary>Publisher details stored with the item.</summary>
    [Parameter(Mandatory = true)]
    [AllowEmptyString]
    public string Details { get; set; } = string.Empty;

    /// <inheritdoc/>
    protected override async Task ProcessRecordAsync()
    {
        if (!ShouldProcess(Id, "Configure VirusTotal Monitor item"))
        {
            return;
        }

        try
        {
            WriteObject(await ActiveClient.ConfigureMonitorItemAsync(Id, Details, CancelToken).ConfigureAwait(false));
        }
        catch (ApiException exception)
        {
            WriteApiError(exception, Id);
        }
    }
}
