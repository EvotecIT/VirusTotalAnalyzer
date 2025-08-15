using System;
using System.IO;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Threading.Tasks;
using VirusTotalAnalyzer;

namespace VirusTotalAnalyzer.PowerShell;

/// <summary>Submits resources to VirusTotal for scanning.</summary>
/// <para>Uploads files, hashes, or URLs to the VirusTotal API and returns the resulting analysis object.</para>
/// <para>You can rescan existing files by providing a known hash.</para>
/// <list type="alertSet">
///   <item>
///     <description>Submitted data is shared with the VirusTotal community.</description>
///   </item>
/// </list>
/// <example>
///   <summary>Upload a file to VirusTotal.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>New-VirusScan -ApiKey $ApiKey -File 'C:\\samples\\app.exe'</para>
///   </code>
///   <para>Starts a new analysis for the specified file.</para>
/// </example>
/// <example>
///   <summary>Submit a URL for scanning.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>New-VirusScan -ApiKey $ApiKey -Url 'https://example.com'</para>
///   </code>
///   <para>Queues the URL for analysis and returns its identifier.</para>
/// </example>
/// <seealso href="https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/invoke-webrequest" />
/// <seealso href="https://github.com/EvotecIT/VirusTotalAnalyzer" />
[Cmdlet(VerbsCommon.New, "VirusScan")]
public sealed class CmdletNewVirusScan : AsyncPSCmdlet
{
    /// <summary>VirusTotal API key.</summary>
    [Parameter(Mandatory = true)]
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>Hash of an already submitted file to reanalyse.</summary>
    [Parameter(ParameterSetName = "Hash", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? Hash { get; set; }

    /// <summary>Path to a file whose hash should be recalculated and reanalysed.</summary>
    [Parameter(ParameterSetName = "FileHash", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? FileHash { get; set; }

    /// <summary>Path to a local file to upload for scanning.</summary>
    [Parameter(ParameterSetName = "FileInformation", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? File { get; set; }

    /// <summary>URL to submit for scanning.</summary>
    [Alias("Uri")]
    [Parameter(ParameterSetName = "Url", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public Uri? Url { get; set; }

    /// <summary>Password to use when submitting a protected archive.</summary>
    [Parameter]
    public string? Password { get; set; }

    /// <summary>Existing <see cref="VirusTotalClient"/> instance to reuse.</summary>
    [Parameter]
    public VirusTotalClient? Client { get; set; }

    /// <inheritdoc/>
    protected override async Task ProcessRecordAsync()
    {
        var client = Client ?? VirusTotalClient.Create(ApiKey);
        try
        {
            switch (ParameterSetName)
            {
                case "FileInformation":
                    if (!EnsureFileExists(File!, GetErrorActionPreference()))
                        return;
                    var fileAnalysis = await client.ScanFileAsync(File!, Password, CancelToken).ConfigureAwait(false);
                    WriteObject(fileAnalysis);
                    break;

                case "Hash":
                    var hashAnalysis = await client.ReanalyzeFileAsync(Hash!, CancelToken).ConfigureAwait(false);
                    WriteObject(hashAnalysis);
                    break;

                case "FileHash":
                    if (!EnsureFileExists(FileHash!, GetErrorActionPreference()))
                        return;
                    string hash;
                    using (var sha256 = SHA256.Create())
                    using (var stream = System.IO.File.OpenRead(FileHash!))
                    {
                        var bytes = sha256.ComputeHash(stream);
#if NET472
                        hash = BitConverter.ToString(bytes).Replace("-", string.Empty).ToLowerInvariant();
#else
                        hash = Convert.ToHexString(bytes).ToLowerInvariant();
#endif
                    }
                    var fhAnalysis = await client.ReanalyzeFileAsync(hash, CancelToken).ConfigureAwait(false);
                    WriteObject(fhAnalysis);
                    break;

                case "Url":
                    var urlAnalysis = await client.ScanUrlAsync(Url!.ToString(), CancelToken).ConfigureAwait(false);
                    WriteObject(urlAnalysis);
                    break;
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
