using System;
using System.IO;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Threading.Tasks;
using VirusTotalAnalyzer;

namespace VirusTotalAnalyzer.PowerShell;

[Cmdlet(VerbsCommon.Get, "VirusReport", DefaultParameterSetName = "FileInformation")]
[Alias("Get-VirusScan")]
public sealed class CmdletGetVirusReport : AsyncPSCmdlet
{
    [Parameter(Mandatory = true)]
    public string ApiKey { get; set; } = string.Empty;

    [Parameter(ParameterSetName = "Analysis", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? AnalysisId { get; set; }

    [Parameter(ParameterSetName = "Hash", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? Hash { get; set; }

    [Alias("FileHash")]
    [Parameter(ParameterSetName = "FileInformation", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? File { get; set; }

    [Alias("Uri")]
    [Parameter(ParameterSetName = "Url", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public Uri? Url { get; set; }

    [Parameter(ParameterSetName = "IPAddress", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? IPAddress { get; set; }

    [Parameter(ParameterSetName = "DomainName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? DomainName { get; set; }

    [Parameter(ParameterSetName = "Search", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? Search { get; set; }

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
                    string hash;
                    using (var sha256 = SHA256.Create())
                    using (var stream = System.IO.File.OpenRead(File!))
                    {
                        var bytes = sha256.ComputeHash(stream);
#if NET472
                        hash = BitConverter.ToString(bytes).Replace("-", string.Empty).ToLowerInvariant();
#else
                        hash = Convert.ToHexString(bytes);
#endif
                    }
                    var fileReport = await client.GetFileReportAsync(hash, cancellationToken: CancelToken).ConfigureAwait(false);
                    WriteObject(fileReport);
                    break;

                case "Hash":
                    var hashReport = await client.GetFileReportAsync(Hash!, cancellationToken: CancelToken).ConfigureAwait(false);
                    WriteObject(hashReport);
                    break;

                case "Url":
                    var urlReport = await client.GetUrlReportAsync(Url!, cancellationToken: CancelToken).ConfigureAwait(false);
                    WriteObject(urlReport);
                    break;

                case "IPAddress":
                    var ipReport = await client.GetIpAddressReportAsync(IPAddress!, cancellationToken: CancelToken).ConfigureAwait(false);
                    WriteObject(ipReport);
                    break;

                case "DomainName":
                    var domainReport = await client.GetDomainReportAsync(DomainName!, cancellationToken: CancelToken).ConfigureAwait(false);
                    WriteObject(domainReport);
                    break;

                case "Analysis":
                    var analysis = await client.GetAnalysisAsync(AnalysisId!, CancelToken).ConfigureAwait(false);
                    WriteObject(analysis);
                    break;

                case "Search":
                    var search = await client.SearchAsync(Search!, cancellationToken: CancelToken).ConfigureAwait(false);
                    WriteObject(search);
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
