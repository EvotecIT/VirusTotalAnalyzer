using System.Management.Automation;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.PowerShell;

/// <summary>Creates a folder in VirusTotal Monitor.</summary>
/// <example>
///   <summary>Create an absolute Monitor folder.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>New-VirusTotalMonitorFolder -ApiKey $ApiKey -Path '/Product/1.0/'</para>
///   </code>
/// </example>
[Cmdlet(VerbsCommon.New, "VirusTotalMonitorFolder", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.Medium)]
[OutputType(typeof(MonitorItem))]
public sealed class CmdletNewVirusTotalMonitorFolder : VirusTotalCmdlet
{
    /// <summary>Absolute Monitor folder path, including the trailing slash.</summary>
    [Parameter(Mandatory = true, Position = 0)]
    [ValidateNotNullOrEmpty]
    public string Path { get; set; } = string.Empty;

    /// <inheritdoc/>
    protected override async Task ProcessRecordAsync()
    {
        if (!ShouldProcess(Path, "Create VirusTotal Monitor folder"))
        {
            return;
        }

        try
        {
            WriteObject(await ActiveClient.CreateMonitorFolderAsync(Path, CancelToken).ConfigureAwait(false));
        }
        catch (ApiException exception)
        {
            WriteApiError(exception, Path);
        }
    }
}
