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
    public async Task<IReadOnlyList<FileReport>?> GetFileReportsAsync(
        IEnumerable<string> ids,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        if (ids == null) throw new ArgumentNullException(nameof(ids));
        var url = new StringBuilder("files?ids=")
            .Append(string.Join(",", ids.Select(Uri.EscapeDataString)));

        if (fields != null && fields.Any())
        {
            url.Append("&fields=").Append(string.Join(",", fields.Select(Uri.EscapeDataString)));
        }

        if (relationships != null && relationships.Any())
        {
            url.Append("&relationships=").Append(string.Join(",", relationships.Select(Uri.EscapeDataString)));
        }

        using var response = await _httpClient.GetAsync(url.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<FileReportsResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<FileReport?> GetFileReportAsync(
        string id,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        var url = new StringBuilder($"files/{Uri.EscapeDataString(id)}");
        var hasQuery = false;

        if (fields != null && fields.Any())
        {
            url.Append("?fields=").Append(string.Join(",", fields.Select(Uri.EscapeDataString)));
            hasQuery = true;
        }

        if (relationships != null && relationships.Any())
        {
            url.Append(hasQuery ? '&' : '?')
                .Append("relationships=")
                .Append(string.Join(",", relationships.Select(Uri.EscapeDataString)));
        }

        using var response = await _httpClient.GetAsync(url.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<FileReportResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result?.Data;
    }

    /// <summary>
    /// Retrieves detailed runtime behavior for a file.
    /// </summary>
    /// <param name="id">The file identifier or hash.</param>
    /// <param name="sandbox">Optional sandbox vendor to use when several are available.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    public async Task<FileBehavior?> GetFileBehaviorAsync(string id, string? sandbox = null, CancellationToken cancellationToken = default)
    {
        var url = $"files/{Uri.EscapeDataString(id)}/behaviour";
        if (!string.IsNullOrEmpty(sandbox))
        {
            url += $"?sandbox={Uri.EscapeDataString(sandbox)}";
        }

        using var response = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<FileBehavior>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Retrieves a summary of the runtime behavior for a file.
    /// </summary>
    /// <param name="id">The file identifier or hash.</param>
    /// <param name="sandbox">Optional sandbox vendor to use when several are available.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    public async Task<FileBehaviorSummary?> GetFileBehaviorSummaryAsync(string id, string? sandbox = null, CancellationToken cancellationToken = default)
    {
        var url = $"files/{Uri.EscapeDataString(id)}/behaviour_summary";
        if (!string.IsNullOrEmpty(sandbox))
        {
            url += $"?sandbox={Uri.EscapeDataString(sandbox)}";
        }

        using var response = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<FileBehaviorSummary>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Retrieves network traffic generated by a file during execution.
    /// </summary>
    /// <param name="id">The file identifier or hash.</param>
    /// <param name="sandbox">Optional sandbox vendor to use when several are available.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    public async Task<FileNetworkTraffic?> GetFileNetworkTrafficAsync(string id, string? sandbox = null, CancellationToken cancellationToken = default)
    {
        var url = $"files/{Uri.EscapeDataString(id)}/network-traffic";
        if (!string.IsNullOrEmpty(sandbox))
        {
            url += $"?sandbox={Uri.EscapeDataString(sandbox)}";
        }

        using var response = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<FileNetworkTraffic>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<FilePeInfo?> GetFilePeInfoAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"files/{Uri.EscapeDataString(id)}/pe_info", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<FilePeInfo>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<FileClassification?> GetFileClassificationAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"files/{Uri.EscapeDataString(id)}/classification", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<FileClassification>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<string>?> GetFileStringsAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"files/{Uri.EscapeDataString(id)}/strings", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<FileStringsResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IReadOnlyList<CrowdsourcedYaraResult>?> GetCrowdsourcedYaraResultsAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"files/{Uri.EscapeDataString(id)}/crowdsourced_yara_results", cancellationToken).ConfigureAwait(false);
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
        using var response = await _httpClient.GetAsync($"files/{Uri.EscapeDataString(id)}/crowdsourced_ids_results", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<CrowdsourcedIdsResultsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<PagedResponse<UrlSummary>?> GetFileContactedUrlsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        var path = new System.Text.StringBuilder($"files/{Uri.EscapeDataString(id)}/contacted_urls");
        var hasQuery = false;
        if (limit.HasValue)
        {
            path.Append("?limit=").Append(limit.Value);
            hasQuery = true;
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(cursor));
        }
        using var response = await _httpClient.GetAsync(path.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<PagedResponse<UrlSummary>>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<PagedResponse<DomainSummary>?> GetFileContactedDomainsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        var path = new System.Text.StringBuilder($"files/{Uri.EscapeDataString(id)}/contacted_domains");
        var hasQuery = false;
        if (limit.HasValue)
        {
            path.Append("?limit=").Append(limit.Value);
            hasQuery = true;
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(cursor));
        }
        using var response = await _httpClient.GetAsync(path.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<PagedResponse<DomainSummary>>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<PagedResponse<IpAddressSummary>?> GetFileContactedIpsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        var path = new System.Text.StringBuilder($"files/{Uri.EscapeDataString(id)}/contacted_ips");
        var hasQuery = false;
        if (limit.HasValue)
        {
            path.Append("?limit=").Append(limit.Value);
            hasQuery = true;
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(cursor));
        }
        using var response = await _httpClient.GetAsync(path.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<PagedResponse<IpAddressSummary>>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<PagedResponse<FileReport>?> GetFileReferrerFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        var path = new System.Text.StringBuilder($"files/{Uri.EscapeDataString(id)}/referrer_files");
        var hasQuery = false;
        if (limit.HasValue)
        {
            path.Append("?limit=").Append(limit.Value);
            hasQuery = true;
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(cursor));
        }
        using var response = await _httpClient.GetAsync(path.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<PagedResponse<FileReport>>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<PagedResponse<FileReport>?> GetFileDownloadedFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        var path = new System.Text.StringBuilder($"files/{Uri.EscapeDataString(id)}/downloaded_files");
        var hasQuery = false;
        if (limit.HasValue)
        {
            path.Append("?limit=").Append(limit.Value);
            hasQuery = true;
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(cursor));
        }
        using var response = await _httpClient.GetAsync(path.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<PagedResponse<FileReport>>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<PagedResponse<FileReport>?> GetFileBundledFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        var path = new System.Text.StringBuilder($"files/{Uri.EscapeDataString(id)}/bundled_files");
        var hasQuery = false;
        if (limit.HasValue)
        {
            path.Append("?limit=").Append(limit.Value);
            hasQuery = true;
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(cursor));
        }
        using var response = await _httpClient.GetAsync(path.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<PagedResponse<FileReport>>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<PagedResponse<FileReport>?> GetFileDroppedFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        var path = new System.Text.StringBuilder($"files/{Uri.EscapeDataString(id)}/dropped_files");
        var hasQuery = false;
        if (limit.HasValue)
        {
            path.Append("?limit=").Append(limit.Value);
            hasQuery = true;
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(cursor));
        }
        using var response = await _httpClient.GetAsync(path.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<PagedResponse<FileReport>>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<PagedResponse<FileReport>?> GetFileSimilarFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        var path = new System.Text.StringBuilder($"files/{Uri.EscapeDataString(id)}/similar_files");
        var hasQuery = false;
        if (limit.HasValue)
        {
            path.Append("?limit=").Append(limit.Value);
            hasQuery = true;
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(cursor));
        }
        using var response = await _httpClient.GetAsync(path.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<PagedResponse<FileReport>>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Uri?> GetFileDownloadUrlAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"files/{Uri.EscapeDataString(id)}/download_url", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<DownloadUrlResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        if (result is null || string.IsNullOrEmpty(result.Data))
        {
            return null;
        }
        return new Uri(result.Data);
    }

    public async Task<Stream> DownloadFileAsync(string id, CancellationToken cancellationToken = default)
    {
        var response = await _httpClient
            .GetAsync($"files/{Uri.EscapeDataString(id)}/download", HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return new StreamWithResponse(response, stream);
    }

    public async Task<IReadOnlyList<UrlReport>?> GetUrlReportsAsync(
        IEnumerable<string> ids,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        if (ids == null) throw new ArgumentNullException(nameof(ids));
        var url = new StringBuilder("urls?ids=")
            .Append(string.Join(",", ids.Select(Uri.EscapeDataString)));

        if (fields != null && fields.Any())
        {
            url.Append("&fields=").Append(string.Join(",", fields.Select(Uri.EscapeDataString)));
        }

        if (relationships != null && relationships.Any())
        {
            url.Append("&relationships=").Append(string.Join(",", relationships.Select(Uri.EscapeDataString)));
        }

        using var response = await _httpClient.GetAsync(url.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<UrlReportsResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<UrlReport?> GetUrlReportAsync(
        string id,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        var url = new StringBuilder($"urls/{Uri.EscapeDataString(id)}");
        var hasQuery = false;

        if (fields != null && fields.Any())
        {
            url.Append("?fields=").Append(string.Join(",", fields.Select(Uri.EscapeDataString)));
            hasQuery = true;
        }

        if (relationships != null && relationships.Any())
        {
            url.Append(hasQuery ? '&' : '?')
                .Append("relationships=")
                .Append(string.Join(",", relationships.Select(Uri.EscapeDataString)));
        }

        using var response = await _httpClient.GetAsync(url.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<UrlReportResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result?.Data;
    }

    public Task<UrlReport?> GetUrlReportAsync(
        Uri url,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        if (url == null) throw new ArgumentNullException(nameof(url));
        return GetUrlReportAsync(
            VirusTotalClientExtensions.GetUrlId(url.ToString()),
            fields,
            relationships,
            cancellationToken);
    }

    public async Task<(List<AnalysisReport> Analyses, string? Cursor)> GetUrlAnalysesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        if (limit == 0)
        {
            return (new List<AnalysisReport>(), cursor);
        }

        var results = new List<AnalysisReport>();
        var remaining = limit;
        var nextCursor = cursor;

        do
        {
            var url = new StringBuilder($"urls/{Uri.EscapeDataString(id)}/analyses");
            var hasQuery = false;
            if (remaining.HasValue)
            {
                url.Append("?limit=").Append(remaining.Value);
                hasQuery = true;
            }
            if (!string.IsNullOrEmpty(nextCursor))
            {
                url.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(nextCursor));
            }

            using var response = await _httpClient.GetAsync(url.ToString(), cancellationToken).ConfigureAwait(false);
            await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
            using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
            var page = await JsonSerializer.DeserializeAsync<AnalysisReportsResponse>(stream, _jsonOptions, cancellationToken)
                .ConfigureAwait(false);
            if (page != null)
            {
                results.AddRange(page.Data);
                nextCursor = page.Meta?.Cursor;
                if (remaining.HasValue)
                {
                    remaining -= page.Data.Count;
                }
            }
            else
            {
                nextCursor = null;
            }
        }
        while (nextCursor != null && (!remaining.HasValue || remaining > 0));

        return (results, nextCursor);
    }

    public async Task<IReadOnlyList<FileReport>?> GetUrlDownloadedFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        var path = new System.Text.StringBuilder($"urls/{Uri.EscapeDataString(id)}/downloaded_files");
        var hasQuery = false;
        if (limit.HasValue)
        {
            path.Append("?limit=").Append(limit.Value);
            hasQuery = true;
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(cursor));
        }
        using var response = await _httpClient.GetAsync(path.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<FileReportsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IReadOnlyList<FileReport>?> GetUrlReferrerFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        var path = new System.Text.StringBuilder($"urls/{Uri.EscapeDataString(id)}/referrer_files");
        var hasQuery = false;
        if (limit.HasValue)
        {
            path.Append("?limit=").Append(limit.Value);
            hasQuery = true;
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(cursor));
        }
        using var response = await _httpClient.GetAsync(path.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<FileReportsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IReadOnlyList<UrlSummary>?> GetUrlRedirectingUrlsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        var path = new System.Text.StringBuilder($"urls/{Uri.EscapeDataString(id)}/redirecting_urls");
        var hasQuery = false;
        if (limit.HasValue)
        {
            path.Append("?limit=").Append(limit.Value);
            hasQuery = true;
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(cursor));
        }
        using var response = await _httpClient.GetAsync(path.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<UrlSummariesResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IReadOnlyList<IpAddressSummary>?> GetUrlContactedIpsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        var path = new System.Text.StringBuilder($"urls/{Uri.EscapeDataString(id)}/contacted_ips");
        var hasQuery = false;
        if (limit.HasValue)
        {
            path.Append("?limit=").Append(limit.Value);
            hasQuery = true;
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(cursor));
        }
        using var response = await _httpClient.GetAsync(path.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<IpAddressSummariesResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IpAddressSummary?> GetUrlLastServingIpAddressAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"urls/{Uri.EscapeDataString(id)}/last_serving_ip_address", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<IpAddressSummaryResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IReadOnlyList<IpAddressReport>?> GetIpAddressReportsAsync(
        IEnumerable<string> ids,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        if (ids == null) throw new ArgumentNullException(nameof(ids));
        var url = new StringBuilder("ip_addresses?ids=")
            .Append(string.Join(",", ids.Select(Uri.EscapeDataString)));

        if (fields != null && fields.Any())
        {
            url.Append("&fields=").Append(string.Join(",", fields.Select(Uri.EscapeDataString)));
        }

        if (relationships != null && relationships.Any())
        {
            url.Append("&relationships=").Append(string.Join(",", relationships.Select(Uri.EscapeDataString)));
        }

        using var response = await _httpClient.GetAsync(url.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<IpAddressReportsResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IpAddressReport?> GetIpAddressReportAsync(
        string id,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        var url = new StringBuilder($"ip_addresses/{Uri.EscapeDataString(id)}");
        var hasQuery = false;

        if (fields != null && fields.Any())
        {
            url.Append("?fields=").Append(string.Join(",", fields.Select(Uri.EscapeDataString)));
            hasQuery = true;
        }

        if (relationships != null && relationships.Any())
        {
            url.Append(hasQuery ? '&' : '?')
                .Append("relationships=")
                .Append(string.Join(",", relationships.Select(Uri.EscapeDataString)));
        }

        using var response = await _httpClient.GetAsync(url.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<IpAddressReportResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IpWhois?> GetIpAddressWhoisAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"ip_addresses/{Uri.EscapeDataString(id)}/whois", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<IpWhois>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<DomainReport>?> GetDomainReportsAsync(
        IEnumerable<string> ids,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        if (ids == null) throw new ArgumentNullException(nameof(ids));
        var url = new StringBuilder("domains?ids=")
            .Append(string.Join(",", ids.Select(Uri.EscapeDataString)));

        if (fields != null && fields.Any())
        {
            url.Append("&fields=").Append(string.Join(",", fields.Select(Uri.EscapeDataString)));
        }

        if (relationships != null && relationships.Any())
        {
            url.Append("&relationships=").Append(string.Join(",", relationships.Select(Uri.EscapeDataString)));
        }

        using var response = await _httpClient.GetAsync(url.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<DomainReportsResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<DomainReport?> GetDomainReportAsync(
        string id,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        var url = new StringBuilder($"domains/{Uri.EscapeDataString(id)}");
        var hasQuery = false;

        if (fields != null && fields.Any())
        {
            url.Append("?fields=").Append(string.Join(",", fields.Select(Uri.EscapeDataString)));
            hasQuery = true;
        }

        if (relationships != null && relationships.Any())
        {
            url.Append(hasQuery ? '&' : '?')
                .Append("relationships=")
                .Append(string.Join(",", relationships.Select(Uri.EscapeDataString)));
        }

        using var response = await _httpClient.GetAsync(url.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<DomainReportResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<DomainWhois?> GetDomainWhoisAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"domains/{Uri.EscapeDataString(id)}/whois", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<DomainWhois>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<AnalysisReport>?> GetAnalysesAsync(
        IEnumerable<string> ids,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        if (ids == null) throw new ArgumentNullException(nameof(ids));
        var url = new StringBuilder("analyses?ids=")
            .Append(string.Join(",", ids.Select(Uri.EscapeDataString)));

        if (fields != null && fields.Any())
        {
            url.Append("&fields=").Append(string.Join(",", fields.Select(Uri.EscapeDataString)));
        }

        if (relationships != null && relationships.Any())
        {
            url.Append("&relationships=").Append(string.Join(",", relationships.Select(Uri.EscapeDataString)));
        }

        using var response = await _httpClient.GetAsync(url.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<AnalysisReportsResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<AnalysisReport?> GetAnalysisAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"analyses/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
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
        using var response = await _httpClient.GetAsync($"private/analyses/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
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
            var status = report?.Data?.Attributes?.Status;
            if (status == AnalysisStatus.Completed)
            {
                return report;
            }

            var error = report?.Data?.Attributes?.Error;
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
