using System;
using System.IO;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Threading.Tasks;
using VirusTotalAnalyzer;

namespace VirusTotalAnalyzer.PowerShell;

[Cmdlet(VerbsCommon.New, "VirusScan")]
public sealed class CmdletNewVirusScan : AsyncPSCmdlet
{
    [Parameter(Mandatory = true)]
    public string ApiKey { get; set; } = string.Empty;

    [Parameter(ParameterSetName = "Hash", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? Hash { get; set; }

    [Parameter(ParameterSetName = "FileHash", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? FileHash { get; set; }

    [Parameter(ParameterSetName = "FileInformation", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? File { get; set; }

    [Alias("Uri")]
    [Parameter(ParameterSetName = "Url", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public Uri? Url { get; set; }

    [Parameter]
    public string? Password { get; set; }

    [Parameter]
    public VirusTotalClient? Client { get; set; }

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
                        hash = Convert.ToHexString(bytes);
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
