using System;
using System.Management.Automation;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.PowerShell;

/// <summary>Uploads a publisher file to VirusTotal Monitor.</summary>
/// <example>
///   <summary>Upload a new publisher file and verify its SHA-256.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>Send-VirusTotalMonitorFile -ApiKey $ApiKey -File 'C:\releases\app.exe' -Path '/Product/1.0/app.exe'</para>
///   </code>
/// </example>
/// <example>
///   <summary>Replace the contents of an existing Monitor item.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>Send-VirusTotalMonitorFile -ApiKey $ApiKey -File 'C:\releases\app.exe' -ExistingItemId 'monitor-item-id'</para>
///   </code>
/// </example>
[Cmdlet(VerbsCommunications.Send, "VirusTotalMonitorFile", DefaultParameterSetName = "Path")]
[OutputType(typeof(MonitorUploadResult))]
public sealed class CmdletSendVirusTotalMonitorFile : VirusTotalCmdlet
{
    /// <summary>Local file to upload.</summary>
    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty]
    public string File { get; set; } = string.Empty;

    /// <summary>Absolute destination path in Monitor.</summary>
    [Parameter(Mandatory = true, ParameterSetName = "Path")]
    [ValidateNotNullOrEmpty]
    public string? Path { get; set; }

    /// <summary>Existing Monitor item identifier whose contents will be replaced.</summary>
    [Parameter(Mandatory = true, ParameterSetName = "ExistingItem")]
    [ValidateNotNullOrEmpty]
    public string? ExistingItemId { get; set; }

    /// <summary>Optional publisher details assigned after upload.</summary>
    [Parameter]
    public string? Details { get; set; }

    /// <summary>Returns after upload without polling for the remote SHA-256.</summary>
    [Parameter]
    public SwitchParameter SkipHashVerification { get; set; }

    /// <summary>Maximum seconds to wait for a remote SHA-256.</summary>
    [Parameter]
    [ValidateRange(0, int.MaxValue)]
    public int VerificationTimeoutSeconds { get; set; } = 120;

    /// <summary>Seconds between Monitor item verification requests.</summary>
    [Parameter]
    [ValidateRange(1, int.MaxValue)]
    public int PollingIntervalSeconds { get; set; } = 2;

    /// <inheritdoc/>
    protected override async Task ProcessRecordAsync()
    {
        if (!EnsureFileExists(File, GetErrorActionPreference()))
        {
            return;
        }

        var options = new MonitorUploadOptions
        {
            Path = Path,
            ExistingItemId = ExistingItemId,
            Details = Details,
            VerifySha256 = !SkipHashVerification,
            VerificationTimeout = TimeSpan.FromSeconds(VerificationTimeoutSeconds),
            PollingInterval = TimeSpan.FromSeconds(PollingIntervalSeconds)
        };

        try
        {
            var result = await ActiveClient.UploadMonitorFileAsync(File, options, CancelToken).ConfigureAwait(false);
            WriteObject(result);
        }
        catch (ApiException exception)
        {
            WriteApiError(exception, File);
        }
    }
}
