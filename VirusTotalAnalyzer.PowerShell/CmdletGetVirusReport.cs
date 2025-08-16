using System;
using System.IO;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Threading.Tasks;
using VirusTotalAnalyzer;

namespace VirusTotalAnalyzer.PowerShell;

/// <summary>Retrieves analysis reports from VirusTotal.</summary>
/// <para>Queries the VirusTotal API for information about files, hashes, URLs, IP addresses, domains, or existing analyses.</para>
/// <para>Provide an API key or an existing <see cref="IVirusTotalClient"/> to authenticate requests.</para>
/// <list type="alertSet">
///   <item>
///     <description>Each request consumes your VirusTotal API quota.</description>
///   </item>
/// </list>
/// <example>
///   <summary>Get a report for a local file.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>Get-VirusReport -ApiKey $ApiKey -File 'C:\\samples\\app.exe'</para>
///   </code>
///   <para>Calculates the file hash and returns the latest analysis.</para>
/// </example>
/// <example>
///   <summary>Check a URL against VirusTotal.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>Get-VirusReport -ApiKey $ApiKey -Url 'https://example.com'</para>
///   </code>
///   <para>Displays detection results for the provided URL.</para>
/// </example>
/// <seealso href="https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/invoke-restmethod" />
/// <seealso href="https://github.com/EvotecIT/VirusTotalAnalyzer" />
[Cmdlet(VerbsCommon.Get, "VirusReport", DefaultParameterSetName = "FileInformation")]
[Alias("Get-VirusScan")]
public sealed class CmdletGetVirusReport : AsyncPSCmdlet
{
    /// <summary>VirusTotal API key.</summary>
    [Parameter(Mandatory = true)]
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>Analysis identifier returned from a previous scan.</summary>
    [Parameter(ParameterSetName = "Analysis", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? AnalysisId { get; set; }

    /// <summary>SHA256 or other supported hash to look up.</summary>
    [Parameter(ParameterSetName = "Hash", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? Hash { get; set; }

    /// <summary>Path to a local file to compute its hash.</summary>
    [Alias("FileHash")]
    [Parameter(ParameterSetName = "FileInformation", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? File { get; set; }

    /// <summary>URL to check against VirusTotal.</summary>
    [Alias("Uri")]
    [Parameter(ParameterSetName = "Url", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public Uri? Url { get; set; }

    /// <summary>IP address to inspect.</summary>
    [Parameter(ParameterSetName = "IPAddress", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? IPAddress { get; set; }

    /// <summary>Domain name to inspect.</summary>
    [Parameter(ParameterSetName = "DomainName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? DomainName { get; set; }

    /// <summary>Free-form search expression.</summary>
    [Parameter(ParameterSetName = "Search", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? Search { get; set; }

    /// <summary>Existing <see cref="IVirusTotalClient"/> instance to reuse.</summary>
    [Parameter]
    public IVirusTotalClient? Client { get; set; }

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
                    string hash;
                    using (var sha256 = SHA256.Create())
                    using (var stream = System.IO.File.OpenRead(File!))
                    {
                        var bytes = sha256.ComputeHash(stream);
#if NET472
                        hash = BitConverter.ToString(bytes).Replace("-", string.Empty).ToLowerInvariant();
#else
                        hash = Convert.ToHexString(bytes).ToLowerInvariant();
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
