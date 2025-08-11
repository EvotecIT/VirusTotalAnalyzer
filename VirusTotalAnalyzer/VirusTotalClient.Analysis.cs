using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

public sealed partial class VirusTotalClient
{
    public async Task<FileReport?> GetFileReportAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"files/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<FileReport>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<FileBehavior?> GetFileBehaviorAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"files/{id}/behavior", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<FileBehavior>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<FileBehaviorSummary?> GetFileBehaviorSummaryAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"files/{id}/behavior_summary", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<FileBehaviorSummary>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<FileNetworkTraffic?> GetFileNetworkTrafficAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"files/{id}/network-traffic", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<FileNetworkTraffic>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<CrowdsourcedYaraResult>?> GetCrowdsourcedYaraResultsAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"files/{id}/crowdsourced_yara_results", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<CrowdsourcedYaraResultsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IReadOnlyList<CrowdsourcedIdsResult>?> GetCrowdsourcedIdsResultsAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"files/{id}/crowdsourced_ids_results", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<CrowdsourcedIdsResultsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<Stream> DownloadFileAsync(string id, CancellationToken cancellationToken = default)
    {
        var response = await _httpClient.GetAsync($"files/{id}/download", HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        return await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        return await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
    }

    public async Task<UrlReport?> GetUrlReportAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"urls/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<UrlReport>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public Task<UrlReport?> GetUrlReportAsync(Uri url, CancellationToken cancellationToken = default)
    {
        if (url == null) throw new ArgumentNullException(nameof(url));
        return GetUrlReportAsync(VirusTotalClientExtensions.GetUrlId(url.ToString()), cancellationToken);
    }

    public async Task<IpAddressReport?> GetIpAddressReportAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"ip_addresses/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<IpAddressReport>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<DomainReport?> GetDomainReportAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"domains/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<DomainReport>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<AnalysisReport?> GetAnalysisAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"analyses/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<AnalysisReport>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<PrivateAnalysis?> GetPrivateAnalysisAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"private/analyses/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<PrivateAnalysis>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<AnalysisReport?> WaitForAnalysisCompletionAsync(
        string id,
        TimeSpan timeout,
        TimeSpan? pollingInterval = null,
        CancellationToken cancellationToken = default)
    {
        var interval = pollingInterval ?? TimeSpan.FromSeconds(1);
        var start = DateTimeOffset.UtcNow;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var report = await GetAnalysisAsync(id, cancellationToken).ConfigureAwait(false);
            var status = report?.Data.Attributes.Status;
            if (status == AnalysisStatus.Completed)
            {
                return report;
            }

            var error = report?.Data.Attributes.Error;
            if (status == AnalysisStatus.Error || status == AnalysisStatus.Cancelled)
            {
                var apiError = string.IsNullOrEmpty(error) ? null : new ApiError { Message = error };
                throw new ApiException(apiError, error);
            }

            if (status == AnalysisStatus.Timeout)
            {
                throw new TimeoutException(error ?? "The analysis request timed out.");
            }

            if (DateTimeOffset.UtcNow - start >= timeout)
            {
                throw new TimeoutException("The analysis did not complete within the specified timeout.");
            }

            var remaining = timeout - (DateTimeOffset.UtcNow - start);
            var delay = remaining < interval ? remaining : interval;
            if (delay > TimeSpan.Zero)
            {
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }
    }

}
