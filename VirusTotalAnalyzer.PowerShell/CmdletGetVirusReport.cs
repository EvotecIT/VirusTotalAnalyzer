using System;
using System.Collections.Generic;
using System.IO;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Threading;
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
                    await WriteReportBatchAsync(
                        _analysisIds,
                        (ids, token) => ActiveClient.GetAnalysesBatchAsync(ids, options, token),
                        StringComparer.Ordinal).ConfigureAwait(false);
                    break;
                case "Hash":
                    await WriteReportBatchAsync(
                        _hashes,
                        (ids, token) => ActiveClient.GetFileReportsBatchAsync(ids, options, cancellationToken: token),
                        StringComparer.OrdinalIgnoreCase).ConfigureAwait(false);
                    break;
                case "FileInformation":
                    var completedFileHashes = new Dictionary<string, FileReport?>(StringComparer.OrdinalIgnoreCase);
                    var failedFileHashes = new Dictionary<string, ApiException>(StringComparer.OrdinalIgnoreCase);
                    foreach (var file in _files)
                    {
                        string hash;
                        try
                        {
                            hash = await GetSha256Async(file).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException) when (CancelToken.IsCancellationRequested)
                        {
                            throw;
                        }
                        catch (Exception exception)
                        {
                            WriteError(new ErrorRecord(
                                exception,
                                "FileHashFailed",
                                ErrorCategory.ReadError,
                                file));
                            continue;
                        }

                        await WriteReportAsync(
                            hash,
                            (ids, token) => ActiveClient.GetFileReportsBatchAsync(ids, options, cancellationToken: token),
                            completedFileHashes,
                            failedFileHashes).ConfigureAwait(false);
                    }
                    break;
                case "Url":
                    var urlIds = new List<string>(_urls.Count);
                    foreach (var url in _urls)
                        urlIds.Add(VirusTotalClientExtensions.GetUrlId(url));
                    await WriteReportBatchAsync(
                        urlIds,
                        (ids, token) => ActiveClient.GetUrlReportsBatchAsync(ids, options, cancellationToken: token),
                        StringComparer.Ordinal).ConfigureAwait(false);
                    break;
                case "IPAddress":
                    await WriteReportBatchAsync(
                        _ipAddresses,
                        (ids, token) => ActiveClient.GetIpAddressReportsBatchAsync(ids, options, cancellationToken: token),
                        StringComparer.OrdinalIgnoreCase).ConfigureAwait(false);
                    break;
                case "DomainName":
                    await WriteReportBatchAsync(
                        _domainNames,
                        (ids, token) => ActiveClient.GetDomainReportsBatchAsync(ids, options, cancellationToken: token),
                        StringComparer.OrdinalIgnoreCase).ConfigureAwait(false);
                    break;
            }
        }
        finally
        {
            await base.EndProcessingAsync().ConfigureAwait(false);
        }
    }

    private async Task WriteReportBatchAsync<T>(
        IReadOnlyList<string> ids,
        Func<IEnumerable<string>, CancellationToken, Task<IReadOnlyList<T>>> fetch,
        IEqualityComparer<string> comparer)
        where T : class
    {
        var completed = new Dictionary<string, T?>(comparer);
        var failures = new Dictionary<string, ApiException>(comparer);
        foreach (var id in ids)
        {
            await WriteReportAsync(id, fetch, completed, failures).ConfigureAwait(false);
        }
    }

    private async Task WriteReportAsync<T>(
        string id,
        Func<IEnumerable<string>, CancellationToken, Task<IReadOnlyList<T>>> fetch,
        IDictionary<string, T?> completed,
        IDictionary<string, ApiException> failures)
        where T : class
    {
        CancelToken.ThrowIfCancellationRequested();
        if (completed.TryGetValue(id, out var duplicate))
        {
            if (duplicate is not null)
                WriteReport(duplicate);
            return;
        }
        if (failures.TryGetValue(id, out var repeatedFailure))
        {
            WriteApiError(repeatedFailure, id);
            return;
        }

        try
        {
            var reports = await fetch(new[] { id }, CancelToken).ConfigureAwait(false);
            var report = reports.Count > 0 ? reports[0] : null;
            completed.Add(id, report);
            if (report is not null)
                WriteReport(report);
        }
        catch (ApiException exception)
        {
            failures.Add(id, exception);
            WriteApiError(exception, id);
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

    private void WriteReport<T>(T report) where T : class
    {
        if (!Summary)
        {
            WriteObject(report);
            return;
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
