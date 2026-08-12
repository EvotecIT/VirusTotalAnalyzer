using System;
using System.Collections.Generic;
using System.IO;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.PowerShell;

/// <summary>Retrieves analysis reports from VirusTotal.</summary>
/// <para>Buffers report selectors for one invocation, removes duplicate requests, caches results, retries rate limits, and spaces requests for public API quotas.</para>
/// <para>Provide an API key or an existing <see cref="IVirusTotalClient"/> to authenticate requests, or set VIRUSTOTAL_API_KEY.</para>
/// <example>
///   <summary>Get concise verdicts for several hashes with free-key defaults.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>Get-VirusReport -Hash $hashes -Client $Client -Summary</para>
///   </code>
///   <para>Deduplicates the array, spaces network requests by 20 seconds, and returns pipeline-friendly verdict objects that retain the full report.</para>
/// </example>
/// <example>
///   <summary>Use a faster interval for a key with a higher quota.</summary>
///   <code>
///     <para><prefix>PS&gt; </prefix>Get-VirusReport -DomainName 'example.com','example.net' -MinimumIntervalSeconds 1 -ApiKey $ApiKey</para>
///   </code>
/// </example>
/// <seealso href="https://docs.virustotal.com/reference/public-vs-premium-api" />
/// <seealso href="https://github.com/EvotecIT/VirusTotalAnalyzer" />
[Cmdlet(VerbsCommon.Get, "VirusReport", DefaultParameterSetName = "FileInformation")]
[Alias("Get-VirusScan")]
[OutputType(typeof(FileReport), typeof(UrlReport), typeof(IpAddressReport), typeof(DomainReport), typeof(AnalysisReport), typeof(VirusTotalVerdict), typeof(SearchResponse))]
public sealed class CmdletGetVirusReport : VirusTotalCmdlet
{
    private readonly List<string> _analysisIds = new();
    private readonly List<string> _hashes = new();
    private readonly List<string> _files = new();
    private readonly List<string> _urls = new();
    private readonly List<string> _ipAddresses = new();
    private readonly List<string> _domainNames = new();

    /// <summary>Analysis identifiers returned from previous scans.</summary>
    [Parameter(Mandatory = true, ParameterSetName = "Analysis", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string[] AnalysisId { get; set; } = Array.Empty<string>();

    /// <summary>SHA256 or other supported hashes to look up.</summary>
    [Parameter(Mandatory = true, ParameterSetName = "Hash", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string[] Hash { get; set; } = Array.Empty<string>();

    /// <summary>Paths to local files whose SHA256 hashes should be looked up.</summary>
    [Alias("FileHash")]
    [Parameter(Mandatory = true, ParameterSetName = "FileInformation", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string[] File { get; set; } = Array.Empty<string>();

    /// <summary>URLs to check against VirusTotal.</summary>
    [Alias("Uri")]
    [Parameter(Mandatory = true, ParameterSetName = "Url", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public Uri[] Url { get; set; } = Array.Empty<Uri>();

    /// <summary>IP addresses to inspect.</summary>
    [Parameter(Mandatory = true, ParameterSetName = "IPAddress", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string[] IPAddress { get; set; } = Array.Empty<string>();

    /// <summary>Domain names to inspect.</summary>
    [Parameter(Mandatory = true, ParameterSetName = "DomainName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string[] DomainName { get; set; } = Array.Empty<string>();

    /// <summary>Public search query for an exact IOC or a comment tag.</summary>
    [Parameter(Mandatory = true, ParameterSetName = "Search", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string? Search { get; set; }

    /// <summary>Minimum seconds between report request starts. The public-key default is 20; use 0 only when your quota permits it.</summary>
    [Parameter(ParameterSetName = "Analysis")]
    [Parameter(ParameterSetName = "Hash")]
    [Parameter(ParameterSetName = "FileInformation")]
    [Parameter(ParameterSetName = "Url")]
    [Parameter(ParameterSetName = "IPAddress")]
    [Parameter(ParameterSetName = "DomainName")]
    [ValidateRange(0, 86400)]
    public int MinimumIntervalSeconds { get; set; } = 20;

    /// <summary>Seconds to reuse successful reports within the client. Use 0 to disable cross-batch caching.</summary>
    [Parameter(ParameterSetName = "Analysis")]
    [Parameter(ParameterSetName = "Hash")]
    [Parameter(ParameterSetName = "FileInformation")]
    [Parameter(ParameterSetName = "Url")]
    [Parameter(ParameterSetName = "IPAddress")]
    [Parameter(ParameterSetName = "DomainName")]
    [ValidateRange(0, 31536000)]
    public int CacheSeconds { get; set; } = 300;

    /// <summary>Maximum retries after VirusTotal responds with a rate limit.</summary>
    [Parameter(ParameterSetName = "Analysis")]
    [Parameter(ParameterSetName = "Hash")]
    [Parameter(ParameterSetName = "FileInformation")]
    [Parameter(ParameterSetName = "Url")]
    [Parameter(ParameterSetName = "IPAddress")]
    [Parameter(ParameterSetName = "DomainName")]
    [ValidateRange(0, 100)]
    public int MaxRetries { get; set; } = 3;

    /// <summary>Returns a concise verdict object while retaining the complete report in its Report property.</summary>
    [Parameter(ParameterSetName = "Analysis")]
    [Parameter(ParameterSetName = "Hash")]
    [Parameter(ParameterSetName = "FileInformation")]
    [Parameter(ParameterSetName = "Url")]
    [Parameter(ParameterSetName = "IPAddress")]
    [Parameter(ParameterSetName = "DomainName")]
    public SwitchParameter Summary { get; set; }

    /// <inheritdoc/>
    protected override async Task ProcessRecordAsync()
    {
        if (ParameterSetName == "Search")
        {
            try
            {
                WriteObject(await ActiveClient.SearchAsync(Search!, cancellationToken: CancelToken).ConfigureAwait(false));
            }
            catch (ApiException exception)
            {
                WriteApiError(exception, Search);
            }
            return;
        }

        switch (ParameterSetName)
        {
            case "Analysis":
                _analysisIds.AddRange(AnalysisId);
                break;
            case "Hash":
                _hashes.AddRange(Hash);
                break;
            case "FileInformation":
                foreach (var path in File)
                {
                    if (EnsureFileExists(path, GetErrorActionPreference()))
                        _files.Add(path);
                }
                break;
            case "Url":
                foreach (var uri in Url)
                    _urls.Add(uri.AbsoluteUri);
                break;
            case "IPAddress":
                _ipAddresses.AddRange(IPAddress);
                break;
            case "DomainName":
                _domainNames.AddRange(DomainName);
                break;
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    /// <inheritdoc/>
    protected override async Task EndProcessingAsync()
    {
        try
        {
            if (ParameterSetName == "Search")
                return;

            var options = new VirusTotalBatchOptions
            {
                MinimumInterval = TimeSpan.FromSeconds(MinimumIntervalSeconds),
                CacheDuration = TimeSpan.FromSeconds(CacheSeconds),
                MaxRetries = MaxRetries
            };

            switch (ParameterSetName)
            {
                case "Analysis":
                    WriteReports(await ActiveClient.GetAnalysesBatchAsync(_analysisIds, options, CancelToken).ConfigureAwait(false));
                    break;
                case "Hash":
                    WriteReports(await ActiveClient.GetFileReportsBatchAsync(_hashes, options, cancellationToken: CancelToken).ConfigureAwait(false));
                    break;
                case "FileInformation":
                    var fileHashes = new List<string>(_files.Count);
                    foreach (var file in _files)
                        fileHashes.Add(await GetSha256Async(file).ConfigureAwait(false));
                    if (fileHashes.Count > 0)
                        WriteReports(await ActiveClient.GetFileReportsBatchAsync(fileHashes, options, cancellationToken: CancelToken).ConfigureAwait(false));
                    break;
                case "Url":
                    var urlIds = new List<string>(_urls.Count);
                    foreach (var url in _urls)
                        urlIds.Add(VirusTotalClientExtensions.GetUrlId(url));
                    WriteReports(await ActiveClient.GetUrlReportsBatchAsync(urlIds, options, cancellationToken: CancelToken).ConfigureAwait(false));
                    break;
                case "IPAddress":
                    WriteReports(await ActiveClient.GetIpAddressReportsBatchAsync(_ipAddresses, options, cancellationToken: CancelToken).ConfigureAwait(false));
                    break;
                case "DomainName":
                    WriteReports(await ActiveClient.GetDomainReportsBatchAsync(_domainNames, options, cancellationToken: CancelToken).ConfigureAwait(false));
                    break;
            }
        }
        catch (ApiException exception)
        {
            WriteApiError(exception, GetErrorTarget());
        }
        finally
        {
            await base.EndProcessingAsync().ConfigureAwait(false);
        }
    }

    private async Task<string> GetSha256Async(string path)
    {
        var progress = new ProgressRecord(1, "Hashing file", path);
        WriteProgress(progress);
        try
        {
            using var sha256 = SHA256.Create();
            using var stream = System.IO.File.OpenRead(path);
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
            return BitConverter.ToString(bytes).Replace("-", string.Empty).ToLowerInvariant();
#else
            return Convert.ToHexString(bytes).ToLowerInvariant();
#endif
        }
        finally
        {
            progress.RecordType = ProgressRecordType.Completed;
            WriteProgress(progress);
        }
    }

    private void WriteReports<T>(IReadOnlyList<T> reports) where T : class
    {
        foreach (var report in reports)
        {
            if (!Summary)
            {
                WriteObject(report);
                continue;
            }

            var verdict = report switch
            {
                FileReport value => value.ToVerdict(),
                UrlReport value => value.ToVerdict(),
                DomainReport value => value.ToVerdict(),
                IpAddressReport value => value.ToVerdict(),
                AnalysisReport value => value.ToVerdict(),
                _ => throw new InvalidOperationException($"Unsupported report type {report.GetType().FullName}.")
            };
            WriteObject(verdict);
        }
    }

    private object? GetErrorTarget()
        => ParameterSetName switch
        {
            "FileInformation" => _files.Count > 0 ? _files[0] : null,
            "Hash" => _hashes.Count > 0 ? _hashes[0] : null,
            "Url" => _urls.Count > 0 ? _urls[0] : null,
            "IPAddress" => _ipAddresses.Count > 0 ? _ipAddresses[0] : null,
            "DomainName" => _domainNames.Count > 0 ? _domainNames[0] : null,
            "Analysis" => _analysisIds.Count > 0 ? _analysisIds[0] : null,
            _ => null
        };
}
