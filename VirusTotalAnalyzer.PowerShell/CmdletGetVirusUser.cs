using System.Management.Automation;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.PowerShell;

/// <summary>Retrieves information about a VirusTotal user.</summary>
/// <para>Fetches the documented user object. Quotas and privileges are populated when visible to the caller.</para>
/// <example>
///   <code>
///     <para><prefix>PS&gt; </prefix>Get-VirusUser -ApiKey $ApiKey -Id 'user1'</para>
///   </code>
///   <para>Returns details for the given user identifier.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "VirusUser")]
public sealed class CmdletGetVirusUser : VirusTotalCmdlet
{
    /// <summary>Identifier of the user to retrieve.</summary>
    [Parameter(Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string Id { get; set; } = string.Empty;

    /// <inheritdoc/>
    protected override async Task ProcessRecordAsync()
    {
        try
        {
            var user = await ActiveClient.GetUserAsync(Id, CancelToken).ConfigureAwait(false);
            if (user is not null)
            {
                WriteObject(user);
            }
        }
        catch (ApiException ex)
        {
            WriteApiError(ex, Id);
        }
    }
}
