using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

public sealed partial class VirusTotalClient
{
    private static readonly TimeSpan MaxAnalysisStatusRequestDuration = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Retrieves reports for multiple files.
    /// </summary>
    /// <param name="ids">Identifiers of the files to retrieve. Each object is requested individually.</param>
    /// <param name="fields">Optional fields to include in each response.</param>
    /// <param name="relationships">Optional relationships to include in each response.</param>
    /// <param name="cancellationToken">Token that can be used to cancel the operation.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="ids"/> is empty or contains an invalid identifier.</exception>
    public async Task<IReadOnlyList<FileReport>> GetFileReportsAsync(
        IEnumerable<string> ids,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        return await GetManyAsync(
                ids,
                (id, token) => GetFileReportAsync(id, fields, relationships, token),
                nameof(ids),
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<FileReport?> GetFileReportAsync(
        string id,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var url = BuildObjectUrl("files", id, fields, relationships);
        using var response = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<FileReportResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result?.Data;
    }

    /// <summary>Gets sandbox behavior reports for a file hash.</summary>
    public Task<PagedResponse<BehaviorEntry>?> GetFileBehaviorsAsync(
        string fileId,
        int? limit = null,
        string? cursor = null,
        bool fetchAll = false,
        CancellationToken cancellationToken = default)
    {
        ValidateId(fileId, nameof(fileId));
        return GetPagedAsync<BehaviorEntry>(
            (nextCursor, token) => GetPageAsync<BehaviorEntry>(
                $"files/{Uri.EscapeDataString(fileId)}/behaviours",
                limit,
                nextCursor,
                token),
            cursor,
            fetchAll,
            cancellationToken);
    }

    /// <summary>Gets one sandbox behavior report by its behavior identifier.</summary>
    public Task<BehaviorEntry?> GetFileBehaviorAsync(
        string behaviorId,
        CancellationToken cancellationToken = default)
    {
        ValidateId(behaviorId, nameof(behaviorId));
        return GetDataAsync<BehaviorEntry>(
            $"file_behaviours/{Uri.EscapeDataString(behaviorId)}",
            cancellationToken);
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

        return Uri.TryCreate(result.Data, UriKind.Absolute, out var uri)
            ? ValidateSignedDownloadUri(uri)
            : null;
    }

    public async Task<Stream> DownloadFileAsync(string id, CancellationToken cancellationToken = default)
    {
        var downloadUri = await GetFileDownloadUrlAsync(id, cancellationToken).ConfigureAwait(false);
        return await DownloadFromSignedUrlAsync(
            downloadUri ?? throw new InvalidDataException("VirusTotal returned no signed download URL."),
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Retrieves reports for multiple URLs.
    /// </summary>
    /// <param name="ids">Identifiers of the URLs to retrieve. Each object is requested individually.</param>
    /// <param name="fields">Optional fields to include in the response.</param>
    /// <param name="relationships">Optional relationships to include in the response.</param>
    /// <param name="cancellationToken">Token that can be used to cancel the operation.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="ids"/> is empty or contains an invalid identifier.</exception>
    public async Task<IReadOnlyList<UrlReport>> GetUrlReportsAsync(
        IEnumerable<string> ids,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        return await GetManyAsync(
                ids,
                (id, token) => GetUrlReportAsync(id, fields, relationships, token),
                nameof(ids),
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<UrlReport?> GetUrlReportAsync(
        string id,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var url = BuildObjectUrl("urls", id, fields, relationships);
        using var response = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
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
    /// Retrieves reports for multiple analyses.
    /// </summary>
    /// <param name="ids">Identifiers of the analyses to retrieve. Each object is requested individually.</param>
    /// <param name="cancellationToken">Token that can be used to cancel the operation.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="ids"/> is empty or contains an invalid identifier.</exception>
    public async Task<IReadOnlyList<AnalysisReport>> GetAnalysesAsync(
        IEnumerable<string> ids,
        CancellationToken cancellationToken = default)
    {
        return await GetManyAsync(
                ids,
                (id, token) => GetAnalysisAsync(id, token),
                nameof(ids),
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<AnalysisReport?> GetAnalysisAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"analyses/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<AnalysisReport>(stream, cancellationToken).ConfigureAwait(false);
    }

    public async Task<PrivateAnalysis?> GetPrivateAnalysisAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"private/analyses/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<PrivateAnalysis>(stream, cancellationToken).ConfigureAwait(false);
    }

    public async Task<AnalysisReport?> WaitForAnalysisCompletionAsync(
        string id,
        TimeSpan timeout,
        TimeSpan? pollingInterval = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        if (timeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout), "Timeout must be greater than zero.");
        }

        var interval = pollingInterval ?? TimeSpan.FromSeconds(20);
        if (interval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(pollingInterval), "Polling interval must be greater than zero.");
        }
        var stopwatch = Stopwatch.StartNew();

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var remainingBeforeRequest = timeout - stopwatch.Elapsed;
            if (remainingBeforeRequest <= TimeSpan.Zero)
            {
                throw new TimeoutException("The analysis did not complete within the specified timeout.");
            }

            AnalysisReport? report;
            using var requestCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var requestDuration = remainingBeforeRequest < MaxAnalysisStatusRequestDuration
                ? remainingBeforeRequest
                : MaxAnalysisStatusRequestDuration;
            requestCancellation.CancelAfter(requestDuration);
            try
            {
                report = await GetAnalysisAsync(id, requestCancellation.Token).ConfigureAwait(false);
            }
            catch (RateLimitExceededException ex)
            {
                var remainingAfterLimit = timeout - stopwatch.Elapsed;
                if (remainingAfterLimit <= TimeSpan.Zero)
                {
                    throw new TimeoutException("The analysis did not complete within the specified timeout.", ex);
                }

                var retryDelay = ex.RetryAfter is { } serverDelay && serverDelay > TimeSpan.Zero
                    ? serverDelay
                    : interval;
                await Task.Delay(
                    retryDelay < remainingAfterLimit ? retryDelay : remainingAfterLimit,
                    cancellationToken).ConfigureAwait(false);
                continue;
            }
            catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException("The analysis did not complete within the specified timeout.", ex);
            }

            if (stopwatch.Elapsed >= timeout)
            {
                throw new TimeoutException("The analysis did not complete within the specified timeout.");
            }

            var status = report?.Attributes.Status;
            if (status == AnalysisStatus.Completed)
            {
                return report;
            }

            var error = report?.Attributes.Error;
            if (status == AnalysisStatus.Error || status == AnalysisStatus.Cancelled)
            {
                var apiError = string.IsNullOrEmpty(error) ? null : new ApiError { Message = error };
                throw new ApiException(apiError, error);
            }

            if (status == AnalysisStatus.Timeout)
            {
                throw new TimeoutException(error ?? "The analysis request timed out.");
            }

            var remaining = timeout - stopwatch.Elapsed;
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

        for (var i = 0; i < array.Length; i++)
        {
            if (string.IsNullOrWhiteSpace(array[i]))
            {
                throw new ArgumentException("The collection cannot contain null, empty, or whitespace ids.", paramName);
            }
        }

        return array;
    }

    private static async Task<IReadOnlyList<T>> GetManyAsync<T>(
        IEnumerable<string> ids,
        Func<string, CancellationToken, Task<T?>> fetch,
        string paramName,
        CancellationToken cancellationToken)
        where T : class
    {
        var idArray = ValidateIds(ids, paramName);
        var results = new List<T>(idArray.Length);
        foreach (var id in idArray)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = await fetch(id, cancellationToken).ConfigureAwait(false);
            if (result is not null)
            {
                results.Add(result);
            }
        }
        return results;
    }
}
