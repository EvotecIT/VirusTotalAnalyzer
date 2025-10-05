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
    /// <summary>
    /// Retrieves reports for multiple files.
    /// </summary>
    /// <param name="ids">Identifiers of the files to retrieve. Must contain between 1 and 4 items.</param>
    /// <param name="fields">Optional fields to include in the response.</param>
    /// <param name="relationships">Optional relationships to include in the response.</param>
    /// <param name="cancellationToken">Token that can be used to cancel the operation.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="ids"/> is empty or contains more than four items.</exception>
    public async Task<IReadOnlyList<FileReport>?> GetFileReportsAsync(
        IEnumerable<string> ids,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        var idArray = ValidateIds(ids, nameof(ids));
        var url = new StringBuilder("files?ids=")
            .Append(string.Join(",", idArray.Select(Uri.EscapeDataString)));

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
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
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
        ValidateId(id, nameof(id));
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
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<FileReportResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<FileBehavior?> GetFileBehaviorAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"files/{Uri.EscapeDataString(id)}/behaviour", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<FileBehavior>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<FileBehaviorSummary?> GetFileBehaviorSummaryAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"files/{Uri.EscapeDataString(id)}/behaviour_summary", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<FileBehaviorSummary>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<FileNetworkTraffic?> GetFileNetworkTrafficAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"files/{Uri.EscapeDataString(id)}/network-traffic", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<FileNetworkTraffic>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<FilePeInfo?> GetFilePeInfoAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"files/{Uri.EscapeDataString(id)}/pe_info", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<FilePeInfo>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<FileClassification?> GetFileClassificationAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"files/{Uri.EscapeDataString(id)}/classification", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<FileClassification>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<string>?> GetFileStringsAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"files/{Uri.EscapeDataString(id)}/strings", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<FileStringsResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IReadOnlyList<CrowdsourcedYaraResult>?> GetCrowdsourcedYaraResultsAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"files/{Uri.EscapeDataString(id)}/crowdsourced_yara_results", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<CrowdsourcedYaraResultsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IReadOnlyList<CrowdsourcedIdsResult>?> GetCrowdsourcedIdsResultsAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"files/{Uri.EscapeDataString(id)}/crowdsourced_ids_results", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<CrowdsourcedIdsResultsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public Task<PagedResponse<UrlSummary>?> GetFileContactedUrlsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        bool fetchAll = false,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        return GetPagedAsync<UrlSummary>(async (c, token) =>
        {
            var path = new System.Text.StringBuilder($"files/{Uri.EscapeDataString(id)}/contacted_urls");
            var hasQuery = false;
            if (limit.HasValue)
            {
                path.Append("?limit=").Append(limit.Value);
                hasQuery = true;
            }
            if (!string.IsNullOrEmpty(c))
            {
                path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(c));
            }
            using var response = await _httpClient.GetAsync(path.ToString(), token).ConfigureAwait(false);
            await EnsureSuccessAsync(response, token).ConfigureAwait(false);
            using var stream = await response.Content.ReadContentStreamAsync(token).ConfigureAwait(false);
            return await JsonSerializer.DeserializeAsync<PagedResponse<UrlSummary>>(stream, _jsonOptions, token).ConfigureAwait(false);
        }, cursor, fetchAll, cancellationToken);
    }

    public Task<PagedResponse<DomainSummary>?> GetFileContactedDomainsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        bool fetchAll = false,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        return GetPagedAsync<DomainSummary>(async (c, token) =>
        {
            var path = new System.Text.StringBuilder($"files/{Uri.EscapeDataString(id)}/contacted_domains");
            var hasQuery = false;
            if (limit.HasValue)
            {
                path.Append("?limit=").Append(limit.Value);
                hasQuery = true;
            }
            if (!string.IsNullOrEmpty(c))
            {
                path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(c));
            }
            using var response = await _httpClient.GetAsync(path.ToString(), token).ConfigureAwait(false);
            await EnsureSuccessAsync(response, token).ConfigureAwait(false);
            using var stream = await response.Content.ReadContentStreamAsync(token).ConfigureAwait(false);
            return await JsonSerializer.DeserializeAsync<PagedResponse<DomainSummary>>(stream, _jsonOptions, token).ConfigureAwait(false);
        }, cursor, fetchAll, cancellationToken);
    }

    public Task<PagedResponse<IpAddressSummary>?> GetFileContactedIpsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        bool fetchAll = false,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        return GetPagedAsync<IpAddressSummary>(async (c, token) =>
        {
            var path = new System.Text.StringBuilder($"files/{Uri.EscapeDataString(id)}/contacted_ips");
            var hasQuery = false;
            if (limit.HasValue)
            {
                path.Append("?limit=").Append(limit.Value);
                hasQuery = true;
            }
            if (!string.IsNullOrEmpty(c))
            {
                path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(c));
            }
            using var response = await _httpClient.GetAsync(path.ToString(), token).ConfigureAwait(false);
            await EnsureSuccessAsync(response, token).ConfigureAwait(false);
            using var stream = await response.Content.ReadContentStreamAsync(token).ConfigureAwait(false);
            return await JsonSerializer.DeserializeAsync<PagedResponse<IpAddressSummary>>(stream, _jsonOptions, token).ConfigureAwait(false);
        }, cursor, fetchAll, cancellationToken);
    }

    public Task<PagedResponse<FileReport>?> GetFileReferrerFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        bool fetchAll = false,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        return GetPagedAsync<FileReport>(async (c, token) =>
        {
            var path = new System.Text.StringBuilder($"files/{Uri.EscapeDataString(id)}/referrer_files");
            var hasQuery = false;
            if (limit.HasValue)
            {
                path.Append("?limit=").Append(limit.Value);
                hasQuery = true;
            }
            if (!string.IsNullOrEmpty(c))
            {
                path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(c));
            }
            using var response = await _httpClient.GetAsync(path.ToString(), token).ConfigureAwait(false);
            await EnsureSuccessAsync(response, token).ConfigureAwait(false);
            using var stream = await response.Content.ReadContentStreamAsync(token).ConfigureAwait(false);
            return await JsonSerializer.DeserializeAsync<PagedResponse<FileReport>>(stream, _jsonOptions, token).ConfigureAwait(false);
        }, cursor, fetchAll, cancellationToken);
    }

    public Task<PagedResponse<FileReport>?> GetFileDownloadedFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        bool fetchAll = false,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        return GetPagedAsync<FileReport>(async (c, token) =>
        {
            var path = new System.Text.StringBuilder($"files/{Uri.EscapeDataString(id)}/downloaded_files");
            var hasQuery = false;
            if (limit.HasValue)
            {
                path.Append("?limit=").Append(limit.Value);
                hasQuery = true;
            }
            if (!string.IsNullOrEmpty(c))
            {
                path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(c));
            }
            using var response = await _httpClient.GetAsync(path.ToString(), token).ConfigureAwait(false);
            await EnsureSuccessAsync(response, token).ConfigureAwait(false);
            using var stream = await response.Content.ReadContentStreamAsync(token).ConfigureAwait(false);
            return await JsonSerializer.DeserializeAsync<PagedResponse<FileReport>>(stream, _jsonOptions, token).ConfigureAwait(false);
        }, cursor, fetchAll, cancellationToken);
    }

    public Task<PagedResponse<FileReport>?> GetFileBundledFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        bool fetchAll = false,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        return GetPagedAsync<FileReport>(async (c, token) =>
        {
            var path = new System.Text.StringBuilder($"files/{Uri.EscapeDataString(id)}/bundled_files");
            var hasQuery = false;
            if (limit.HasValue)
            {
                path.Append("?limit=").Append(limit.Value);
                hasQuery = true;
            }
            if (!string.IsNullOrEmpty(c))
            {
                path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(c));
            }
            using var response = await _httpClient.GetAsync(path.ToString(), token).ConfigureAwait(false);
            await EnsureSuccessAsync(response, token).ConfigureAwait(false);
            using var stream = await response.Content.ReadContentStreamAsync(token).ConfigureAwait(false);
            return await JsonSerializer.DeserializeAsync<PagedResponse<FileReport>>(stream, _jsonOptions, token).ConfigureAwait(false);
        }, cursor, fetchAll, cancellationToken);
    }

    public Task<PagedResponse<FileReport>?> GetFileDroppedFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        bool fetchAll = false,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        return GetPagedAsync<FileReport>(async (c, token) =>
        {
            var path = new System.Text.StringBuilder($"files/{Uri.EscapeDataString(id)}/dropped_files");
            var hasQuery = false;
            if (limit.HasValue)
            {
                path.Append("?limit=").Append(limit.Value);
                hasQuery = true;
            }
            if (!string.IsNullOrEmpty(c))
            {
                path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(c));
            }
            using var response = await _httpClient.GetAsync(path.ToString(), token).ConfigureAwait(false);
            await EnsureSuccessAsync(response, token).ConfigureAwait(false);
            using var stream = await response.Content.ReadContentStreamAsync(token).ConfigureAwait(false);
            return await JsonSerializer.DeserializeAsync<PagedResponse<FileReport>>(stream, _jsonOptions, token).ConfigureAwait(false);
        }, cursor, fetchAll, cancellationToken);
    }

    public Task<PagedResponse<FileReport>?> GetFileSimilarFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        bool fetchAll = false,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        return GetPagedAsync<FileReport>(async (c, token) =>
        {
            var path = new System.Text.StringBuilder($"files/{Uri.EscapeDataString(id)}/similar_files");
            var hasQuery = false;
            if (limit.HasValue)
            {
                path.Append("?limit=").Append(limit.Value);
                hasQuery = true;
            }
            if (!string.IsNullOrEmpty(c))
            {
                path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(c));
            }
            using var response = await _httpClient.GetAsync(path.ToString(), token).ConfigureAwait(false);
            await EnsureSuccessAsync(response, token).ConfigureAwait(false);
            using var stream = await response.Content.ReadContentStreamAsync(token).ConfigureAwait(false);
            return await JsonSerializer.DeserializeAsync<PagedResponse<FileReport>>(stream, _jsonOptions, token).ConfigureAwait(false);
        }, cursor, fetchAll, cancellationToken);
    }

    public async Task<Uri?> GetFileDownloadUrlAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"files/{Uri.EscapeDataString(id)}/download_url", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
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
        ValidateId(id, nameof(id));
        var response = await _httpClient
            .GetAsync($"files/{Uri.EscapeDataString(id)}/download", HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        var disposeResponse = true;
        try
        {
            await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
            var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
            disposeResponse = false;
            return new StreamWithResponse(response, stream);
        }
        finally
        {
            if (disposeResponse)
            {
                response.Dispose();
            }
        }
    }

    /// <summary>
    /// Retrieves reports for multiple URLs.
    /// </summary>
    /// <param name="ids">Identifiers of the URLs to retrieve. Must contain between 1 and 4 items.</param>
    /// <param name="fields">Optional fields to include in the response.</param>
    /// <param name="relationships">Optional relationships to include in the response.</param>
    /// <param name="cancellationToken">Token that can be used to cancel the operation.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="ids"/> is empty or contains more than four items.</exception>
    public async Task<IReadOnlyList<UrlReport>?> GetUrlReportsAsync(
        IEnumerable<string> ids,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        var idArray = ValidateIds(ids, nameof(ids));
        var url = new StringBuilder("urls?ids=")
            .Append(string.Join(",", idArray.Select(Uri.EscapeDataString)));

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
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
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
        ValidateId(id, nameof(id));
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
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
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
        ValidateId(id, nameof(id));
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
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
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
        ValidateId(id, nameof(id));
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
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<FileReportsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IReadOnlyList<FileReport>?> GetUrlReferrerFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
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
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<FileReportsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IReadOnlyList<UrlSummary>?> GetUrlRedirectingUrlsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
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
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<UrlSummariesResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IReadOnlyList<IpAddressSummary>?> GetUrlContactedIpsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
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
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<IpAddressSummariesResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IpAddressSummary?> GetUrlLastServingIpAddressAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"urls/{Uri.EscapeDataString(id)}/last_serving_ip_address", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<IpAddressSummaryResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result?.Data;
    }

    /// <summary>
    /// Retrieves reports for multiple IP addresses.
    /// </summary>
    /// <param name="ids">Identifiers of the IP addresses to retrieve. Must contain between 1 and 4 items.</param>
    /// <param name="fields">Optional fields to include in the response.</param>
    /// <param name="relationships">Optional relationships to include in the response.</param>
    /// <param name="cancellationToken">Token that can be used to cancel the operation.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="ids"/> is empty or contains more than four items.</exception>
    public async Task<IReadOnlyList<IpAddressReport>?> GetIpAddressReportsAsync(
        IEnumerable<string> ids,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        var idArray = ValidateIds(ids, nameof(ids));
        var url = new StringBuilder("ip_addresses?ids=")
            .Append(string.Join(",", idArray.Select(Uri.EscapeDataString)));

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
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
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
        ValidateId(id, nameof(id));
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
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<IpAddressReportResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IpWhois?> GetIpAddressWhoisAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"ip_addresses/{Uri.EscapeDataString(id)}/whois", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<IpWhois>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Retrieves reports for multiple domains.
    /// </summary>
    /// <param name="ids">Domain identifiers to retrieve. Must contain between 1 and 4 items.</param>
    /// <param name="fields">Optional fields to include in the response.</param>
    /// <param name="relationships">Optional relationships to include in the response.</param>
    /// <param name="cancellationToken">Token that can be used to cancel the operation.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="ids"/> is empty or contains more than four items.</exception>
    public async Task<IReadOnlyList<DomainReport>?> GetDomainReportsAsync(
        IEnumerable<string> ids,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        var idArray = ValidateIds(ids, nameof(ids));
        var url = new StringBuilder("domains?ids=")
            .Append(string.Join(",", idArray.Select(Uri.EscapeDataString)));

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
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
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
        ValidateId(id, nameof(id));
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
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<DomainReportResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<DomainWhois?> GetDomainWhoisAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"domains/{Uri.EscapeDataString(id)}/whois", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<DomainWhois>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Retrieves reports for multiple analyses.
    /// </summary>
    /// <param name="ids">Identifiers of the analyses to retrieve. Must contain between 1 and 4 items.</param>
    /// <param name="fields">Optional fields to include in the response.</param>
    /// <param name="relationships">Optional relationships to include in the response.</param>
    /// <param name="cancellationToken">Token that can be used to cancel the operation.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="ids"/> is empty or contains more than four items.</exception>
    public async Task<IReadOnlyList<AnalysisReport>?> GetAnalysesAsync(
        IEnumerable<string> ids,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        var idArray = ValidateIds(ids, nameof(ids));
        var url = new StringBuilder("analyses?ids=")
            .Append(string.Join(",", idArray.Select(Uri.EscapeDataString)));

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
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<AnalysisReportsResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<AnalysisReport?> GetAnalysisAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"analyses/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<AnalysisReport>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<PrivateAnalysis?> GetPrivateAnalysisAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"private/analyses/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<PrivateAnalysis>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<AnalysisReport?> WaitForAnalysisCompletionAsync(
        string id,
        TimeSpan timeout,
        TimeSpan? pollingInterval = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
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

    private static string[] ValidateIds(IEnumerable<string> ids, string paramName)
    {
        if (ids == null)
        {
            throw new ArgumentNullException(paramName);
        }

        var array = ids as string[] ?? ids.ToArray();
        if (array.Length == 0)
        {
            throw new ArgumentException("The collection must not be empty.", paramName);
        }

        if (array.Length > 4)
        {
            throw new ArgumentException("A maximum of 4 ids is allowed.", paramName);
        }

        return array;
    }
}
