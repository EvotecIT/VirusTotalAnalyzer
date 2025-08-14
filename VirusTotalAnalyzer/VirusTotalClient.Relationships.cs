using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

public sealed partial class VirusTotalClient
{
    public Task<IReadOnlyList<Submission>?> GetFileSubmissionsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetSubmissionsAsync(ResourceType.File, id, limit, cursor, cancellationToken);

    public Task<IReadOnlyList<Submission>?> GetUrlSubmissionsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetSubmissionsAsync(ResourceType.Url, id, limit, cursor, cancellationToken);

    public async Task<IReadOnlyList<Graph>> GetUrlGraphsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var relationships = await GetRelationshipsAsync(ResourceType.Url, id, "graphs", limit, cursor, cancellationToken).ConfigureAwait(false);
        if (relationships == null || relationships.Data.Count == 0)
        {
            return Array.Empty<Graph>();
        }

        var graphs = new List<Graph>(relationships.Data.Count);
        foreach (var relationship in relationships.Data)
        {
            var graph = await GetGraphAsync(relationship.Id, cancellationToken).ConfigureAwait(false);
            if (graph != null)
            {
                graphs.Add(graph);
            }
        }

        return graphs;
    }

    public Task<IReadOnlyList<Resolution>?> GetDomainResolutionsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetResolutionsAsync(ResourceType.Domain, id, limit, cursor, cancellationToken);

    public Task<IReadOnlyList<Submission>?> GetDomainSubmissionsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetSubmissionsAsync(ResourceType.Domain, id, limit, cursor, cancellationToken);

    public Task<IReadOnlyList<DomainSummary>?> GetDomainSubdomainsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetDomainRelationshipsAsync<DomainSubdomainsResponse, DomainSummary>(id, "subdomains", r => r.Data, limit, cursor, cancellationToken);

    public Task<IReadOnlyList<DomainSummary>?> GetDomainSiblingsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetDomainRelationshipsAsync<DomainSiblingsResponse, DomainSummary>(id, "siblings", r => r.Data, limit, cursor, cancellationToken);

    public Task<IReadOnlyList<UrlSummary>?> GetDomainUrlsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetDomainRelationshipsAsync<DomainUrlsResponse, UrlSummary>(id, "urls", r => r.Data, limit, cursor, cancellationToken);

    public Task<IReadOnlyList<DnsRecord>?> GetDomainDnsRecordsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetDomainRelationshipsAsync<DnsRecordsResponse, DnsRecord>(id, "dns_records", r => r.Data, limit, cursor, cancellationToken);

    public Task<IReadOnlyList<FileReport>?> GetDomainReferrerFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetDomainRelationshipsAsync<FileReportsResponse, FileReport>(id, "referrer_files", r => r.Data, limit, cursor, cancellationToken);

    public Task<IReadOnlyList<FileReport>?> GetDomainDownloadedFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetDomainRelationshipsAsync<FileReportsResponse, FileReport>(id, "downloaded_files", r => r.Data, limit, cursor, cancellationToken);

    public Task<IReadOnlyList<SslCertificate>?> GetDomainSslCertificatesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetDomainRelationshipsAsync<SslCertificatesResponse, SslCertificate>(id, "ssl_certificates", r => r.Data, limit, cursor, cancellationToken);

    public Task<IReadOnlyList<Resolution>?> GetIpAddressResolutionsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetResolutionsAsync(ResourceType.IpAddress, id, limit, cursor, cancellationToken);

    public Task<IReadOnlyList<Submission>?> GetIpAddressSubmissionsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetSubmissionsAsync(ResourceType.IpAddress, id, limit, cursor, cancellationToken);

    public async Task<IReadOnlyList<FileReport>?> GetIpAddressCommunicatingFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var path = new System.Text.StringBuilder($"ip_addresses/{Uri.EscapeDataString(id)}/communicating_files");
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

    public async Task<IReadOnlyList<FileReport>?> GetIpAddressDownloadedFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var path = new System.Text.StringBuilder($"ip_addresses/{Uri.EscapeDataString(id)}/downloaded_files");
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

    public async Task<IReadOnlyList<FileReport>?> GetIpAddressReferrerFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var path = new System.Text.StringBuilder($"ip_addresses/{Uri.EscapeDataString(id)}/referrer_files");
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

    public async Task<IReadOnlyList<UrlSummary>?> GetIpAddressUrlsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var path = new System.Text.StringBuilder($"ip_addresses/{Uri.EscapeDataString(id)}/urls");
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

    public async Task<IReadOnlyList<SslCertificate>?> GetIpAddressSslCertificatesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var path = new System.Text.StringBuilder($"ip_addresses/{Uri.EscapeDataString(id)}/ssl_certificates");
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
        var result = await JsonSerializer.DeserializeAsync<SslCertificatesResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    private async Task<IReadOnlyList<T>?> GetDomainRelationshipsAsync<TResponse, T>(
        string id,
        string relationship,
        Func<TResponse, List<T>> selector,
        int? limit,
        string? cursor,
        CancellationToken cancellationToken)
    {
        ValidateId(id, nameof(id));
        var path = new System.Text.StringBuilder($"domains/{Uri.EscapeDataString(id)}/{Uri.EscapeDataString(relationship)}");
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
        var result = await JsonSerializer.DeserializeAsync<TResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result == null ? null : selector(result);
    }

    private async Task<IReadOnlyList<Resolution>?> GetResolutionsAsync(
        ResourceType resourceType,
        string id,
        int? limit,
        string? cursor,
        CancellationToken cancellationToken)
    {
        ValidateId(id, nameof(id));
        var path = new System.Text.StringBuilder($"{GetPath(resourceType)}/{Uri.EscapeDataString(id)}/resolutions");
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
        var result = await JsonSerializer.DeserializeAsync<ResolutionsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    private async Task<IReadOnlyList<Submission>?> GetSubmissionsAsync(
        ResourceType resourceType,
        string id,
        int? limit,
        string? cursor,
        CancellationToken cancellationToken)
    {
        ValidateId(id, nameof(id));
        var path = new System.Text.StringBuilder($"{GetPath(resourceType)}/{Uri.EscapeDataString(id)}/submissions");
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
        var result = await JsonSerializer.DeserializeAsync<SubmissionsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }
}
