using System;
using System.IO;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using VirusTotalAnalyzer.Models;

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
/// <example>
///   <summary>Submit a file and wait for the completed analysis.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>$env:VIRUSTOTAL_API_KEY = 'your-api-key'; New-VirusScan -File 'C:\samples\app.exe' -Wait</para>
///   </code>
///   <para>Uses the environment API key and polls at a free-API-friendly interval.</para>
/// </example>
/// <seealso href="https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/invoke-webrequest" />
/// <seealso href="https://github.com/EvotecIT/VirusTotalAnalyzer" />
[Cmdlet(VerbsCommon.New, "VirusScan")]
[OutputType(typeof(AnalysisReport))]
public sealed class CmdletNewVirusScan : VirusTotalCmdlet
{
    /// <summary>Hash of an already submitted file to reanalyse.</summary>
    [Parameter(Mandatory = true, ParameterSetName = "Hash", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? Hash { get; set; }

    /// <summary>Path to a file whose hash should be recalculated and reanalysed.</summary>
    [Parameter(Mandatory = true, ParameterSetName = "FileHash", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? FileHash { get; set; }

    /// <summary>Path to a local file to upload for scanning.</summary>
    [Parameter(Mandatory = true, ParameterSetName = "FileInformation", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? File { get; set; }

    /// <summary>URL to submit for scanning.</summary>
    [Alias("Uri")]
    [Parameter(Mandatory = true, ParameterSetName = "Url", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public Uri? Url { get; set; }

    /// <summary>Password to use when submitting a protected archive.</summary>
    [Parameter]
    public string? Password { get; set; }

    /// <summary>Wait for VirusTotal to finish the submitted analysis.</summary>
    [Parameter]
    public SwitchParameter Wait { get; set; }

    /// <summary>Maximum number of seconds to wait for analysis completion.</summary>
    [Parameter]
    [ValidateRange(1, int.MaxValue)]
    [PSDefaultValue(Value = 300)]
    public int TimeoutSeconds { get; set; } = 300;

    /// <summary>Seconds between status requests. The default is suitable for the public API rate limit.</summary>
    [Parameter]
    [ValidateRange(1, int.MaxValue)]
    [PSDefaultValue(Value = 20)]
    public int PollingIntervalSeconds { get; set; } = 20;

    /// <inheritdoc/>
    protected override async Task ProcessRecordAsync()
    {
        try
        {
            switch (ParameterSetName)
            {
                case "FileInformation":
                    if (!EnsureFileExists(File!, GetErrorActionPreference()))
                        return;
                    var fileAnalysis = await ActiveClient.ScanFileAsync(File!, Password, CancelToken).ConfigureAwait(false);
                    WriteObject(await CompleteAnalysisAsync(fileAnalysis).ConfigureAwait(false));
                    break;

                case "Hash":
                    var hashAnalysis = await ActiveClient.ReanalyzeFileAsync(Hash!, CancelToken).ConfigureAwait(false);
                    WriteObject(await CompleteAnalysisAsync(hashAnalysis).ConfigureAwait(false));
                    break;

                case "FileHash":
                    if (!EnsureFileExists(FileHash!, GetErrorActionPreference()))
                        return;
                    string hash;
                    var progress = new ProgressRecord(1, "Hashing file", FileHash!);
                    WriteProgress(progress);
                    try
                    {
                        using var sha256 = SHA256.Create();
                        using var stream = System.IO.File.OpenRead(FileHash!);
                        var length = stream.Length;
                        var buffer = new byte[81920];
                        int read;
                        long total = 0;
                        while ((read = await stream.ReadAsync(buffer, 0, buffer.Length, CancelToken).ConfigureAwait(false)) > 0)
                        {
                            sha256.TransformBlock(buffer, 0, read, null, 0);
                            total += read;
                            progress.PercentComplete = length > 0 ? (int)(total * 100 / length) : 0;
                            WriteProgress(progress);
                        }
                        sha256.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                        var bytes = sha256.Hash!;
#if NET472
                        hash = BitConverter.ToString(bytes).Replace("-", string.Empty).ToLowerInvariant();
#else
                        hash = Convert.ToHexString(bytes).ToLowerInvariant();
#endif
                    }
                    finally
                    {
                        progress.RecordType = ProgressRecordType.Completed;
                        WriteProgress(progress);
                    }
                    var fhAnalysis = await ActiveClient.ReanalyzeFileAsync(hash, CancelToken).ConfigureAwait(false);
                    WriteObject(await CompleteAnalysisAsync(fhAnalysis).ConfigureAwait(false));
                    break;

                case "Url":
                    var urlAnalysis = await ActiveClient.ScanUrlAsync(Url!.ToString(), CancelToken).ConfigureAwait(false);
                    WriteObject(await CompleteAnalysisAsync(urlAnalysis).ConfigureAwait(false));
                    break;
            }
        }
        catch (ApiException ex)
        {
            var target = ParameterSetName switch
            {
                "FileInformation" => File,
                "Hash" => Hash,
                "FileHash" => FileHash,
                "Url" => Url?.ToString(),
                _ => null
            };
            WriteApiError(ex, target);
        }
        catch (TimeoutException ex)
        {
            WriteError(new ErrorRecord(ex, "VirusTotalAnalysisTimeout", ErrorCategory.OperationTimeout, null));
        }
    }

    private async Task<AnalysisReport?> CompleteAnalysisAsync(AnalysisReport? analysis)
    {
        if (!Wait || analysis is null || string.IsNullOrWhiteSpace(analysis.Id))
        {
            return analysis;
        }

        return await ActiveClient.WaitForAnalysisCompletionAsync(
            analysis.Id,
            TimeSpan.FromSeconds(TimeoutSeconds),
            TimeSpan.FromSeconds(PollingIntervalSeconds),
            CancelToken).ConfigureAwait(false);
    }
}
