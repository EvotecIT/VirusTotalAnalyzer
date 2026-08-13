using System;
using System.Management.Automation;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.PowerShell;

/// <summary>Retrieves VirusTotal account information or visible quota usage.</summary>
/// <para>Uses an explicit user identifier or VIRUSTOTAL_USER_ID. The API key is never substituted into the URL path.</para>
/// <example>
///   <summary>Get the configured account.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>$env:VIRUSTOTAL_USER_ID = 'user1'; Get-VirusAccount</para>
///   </code>
/// </example>
/// <example>
///   <summary>Return pipeline-friendly quota rows.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>Get-VirusUser -Id 'user1' -Quota</para>
///   </code>
/// </example>
[Cmdlet(VerbsCommon.Get, "VirusUser")]
[Alias("Get-VirusAccount")]
[OutputType(typeof(User), typeof(VirusTotalQuotaStatus))]
public sealed class CmdletGetVirusUser : VirusTotalCmdlet
{
    /// <summary>User identifier. Defaults to VIRUSTOTAL_USER_ID; it never defaults to the API key.</summary>
    [Parameter(ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? Id { get; set; }

    /// <summary>Returns one concise row for each visible quota instead of the complete user object.</summary>
    [Parameter]
    public SwitchParameter Quota { get; set; }

    /// <inheritdoc/>
    protected override async Task ProcessRecordAsync()
    {
        var resolvedId = string.IsNullOrWhiteSpace(Id)
            ? Environment.GetEnvironmentVariable("VIRUSTOTAL_USER_ID")
            : Id;
        if (string.IsNullOrWhiteSpace(resolvedId))
        {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("Specify Id or set VIRUSTOTAL_USER_ID. The API key is intentionally not used as a URL identifier."),
                "VirusTotalUserIdRequired",
                ErrorCategory.InvalidArgument,
                null));
            return;
        }

        try
        {
            var user = await ActiveClient.GetUserAsync(resolvedId!, CancelToken).ConfigureAwait(false);
            if (user is null)
                return;

            if (Quota)
                WriteObject(user.GetQuotaStatus(), enumerateCollection: true);
            else
                WriteObject(user);
        }
        catch (ApiException exception)
        {
            WriteApiError(exception, resolvedId);
        }
    }
}
