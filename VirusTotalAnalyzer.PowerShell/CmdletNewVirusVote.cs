using System.Management.Automation;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.PowerShell;

/// <summary>Casts a vote for a resource.</summary>
/// <para>Submits a harmless or malicious verdict for the specified resource.</para>
/// <example>
///   <code>
///     <para><prefix>PS&gt; </prefix>New-VirusVote -ApiKey $ApiKey -ResourceType File -Id 'abc' -Verdict Malicious</para>
///   </code>
///   <para>Marks the file identified by the given hash as malicious.</para>
/// </example>
[Cmdlet(VerbsCommon.New, "VirusVote")]
public sealed class CmdletNewVirusVote : VirusTotalCmdlet
{
    /// <summary>Resource type to vote on.</summary>
    [Parameter(Mandatory = true)]
    public ResourceType ResourceType { get; set; }

    /// <summary>Identifier of the resource.</summary>
    [Parameter(Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string Id { get; set; } = string.Empty;

    /// <summary>Verdict to cast.</summary>
    [Parameter(Mandatory = true)]
    public VoteVerdict Verdict { get; set; }

    /// <inheritdoc/>
    protected override async Task ProcessRecordAsync()
    {
        try
        {
            var vote = await ActiveClient.CreateVoteAsync(ResourceType, Id, Verdict, CancelToken).ConfigureAwait(false);
            WriteObject(vote);
        }
        catch (ApiException ex)
        {
            WriteApiError(ex, Id);
        }
    }
}
