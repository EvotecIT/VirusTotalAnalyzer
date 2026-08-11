using System.Management.Automation;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.PowerShell;

/// <summary>Removes a VirusTotal Monitor item.</summary>
/// <example>
///   <summary>Remove one Monitor item after confirmation.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>Remove-VirusTotalMonitorItem -ApiKey $ApiKey -Id 'monitor-item-id'</para>
///   </code>
/// </example>
[Cmdlet(VerbsCommon.Remove, "VirusTotalMonitorItem", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High)]
public sealed class CmdletRemoveVirusTotalMonitorItem : VirusTotalCmdlet
{
    /// <summary>Identifier of the Monitor item to delete.</summary>
    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    public string Id { get; set; } = string.Empty;

    /// <inheritdoc/>
    protected override async Task ProcessRecordAsync()
    {
        if (!ShouldProcess(Id, "Delete VirusTotal Monitor item"))
        {
            return;
        }

        try
        {
            await ActiveClient.DeleteMonitorItemAsync(Id, CancelToken).ConfigureAwait(false);
        }
        catch (ApiException exception)
        {
            WriteApiError(exception, Id);
        }
    }
}
