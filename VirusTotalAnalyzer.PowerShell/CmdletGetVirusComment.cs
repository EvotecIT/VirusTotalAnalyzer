using System.Management.Automation;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.PowerShell;

/// <summary>Retrieves comments for a specified resource.</summary>
/// <para>Fetches community comments associated with files, URLs, IP addresses or domains.</para>
/// <example>
///   <code>
///     <para><prefix>PS&gt; </prefix>Get-VirusComment -ApiKey $ApiKey -ResourceType File -Id 'abc'</para>
///   </code>
///   <para>Displays community feedback for the file with the given hash.</para>
/// </example>
[Cmdlet(VerbsCommon.Get, "VirusComment")]
public sealed class CmdletGetVirusComment : AsyncPSCmdlet
{
    /// <summary>VirusTotal API key.</summary>
    [Parameter(Mandatory = true)]
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>Resource type to retrieve comments for.</summary>
    [Parameter(Mandatory = true)]
    public ResourceType ResourceType { get; set; }

    /// <summary>Identifier of the resource.</summary>
    [Parameter(Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string Id { get; set; } = string.Empty;

    /// <summary>Maximum number of comments to return.</summary>
    [Parameter]
    public int? Limit { get; set; }

    /// <summary>Pagination cursor.</summary>
    [Parameter]
    public string? Cursor { get; set; }

    /// <summary>Existing VirusTotal client to reuse.</summary>
    [Parameter]
    public VirusTotalClient? Client { get; set; }

    /// <inheritdoc/>
    protected override async Task ProcessRecordAsync()
    {
        var client = Client ?? VirusTotalClient.Create(ApiKey);
        try
        {
            var comments = await client.GetCommentsAsync(ResourceType, Id, Limit, Cursor, CancelToken).ConfigureAwait(false);
            if (comments is not null)
            {
                WriteObject(comments.Data, true);
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
