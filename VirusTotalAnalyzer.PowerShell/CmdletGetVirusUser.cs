using System.Management.Automation;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.PowerShell;

/// <summary>Retrieves information about a VirusTotal user.</summary>
/// <para>Fetches public profile data for the specified username.</para>
[Cmdlet(VerbsCommon.Get, "VirusUser")]
public sealed class CmdletGetVirusUser : AsyncPSCmdlet
{
    /// <summary>VirusTotal API key.</summary>
    [Parameter(Mandatory = true)]
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>Identifier of the user to retrieve.</summary>
    [Parameter(Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string Id { get; set; } = string.Empty;

    /// <summary>Existing VirusTotal client to reuse.</summary>
    [Parameter]
    public VirusTotalClient? Client { get; set; }

    /// <inheritdoc/>
    protected override async Task ProcessRecordAsync()
    {
        var client = Client ?? VirusTotalClient.Create(ApiKey);
        try
        {
            var user = await client.GetUserAsync(Id, CancelToken).ConfigureAwait(false);
            if (user is not null)
            {
                WriteObject(user);
            }
        }
        finally
        {
            if (Client is null)
            {
                client.Dispose();
            }
        }
    }
}
