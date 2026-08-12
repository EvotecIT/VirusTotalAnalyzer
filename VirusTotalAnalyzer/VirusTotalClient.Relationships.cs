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
            var graphId = relationship.Id;
            if (string.IsNullOrEmpty(graphId))
            {
                continue;
            }
            var graph = await GetGraphAsync(graphId!, cancellationToken).ConfigureAwait(false);
            if (graph != null)
            {
                graphs.Add(graph);
            }
        }

        return graphs;
    }

    public async Task<IReadOnlyList<Resolution>?> GetDomainResolutionsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => (await GetDomainResolutionsPageAsync(id, limit, cursor, cancellationToken).ConfigureAwait(false))?.Data;

    /// <summary>Gets one page of domain resolutions together with its continuation cursor.</summary>
    public Task<PagedResponse<Resolution>?> GetDomainResolutionsPageAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetTypedRelationshipPageAsync<Resolution>(ResourceType.Domain, id, "resolutions", limit, cursor, cancellationToken);

    /// <summary>Gets historical WHOIS snapshots for a domain.</summary>
    public async Task<IReadOnlyList<WhoisRecord>?> GetDomainHistoricalWhoisAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => (await GetDomainHistoricalWhoisPageAsync(id, limit, cursor, cancellationToken).ConfigureAwait(false))?.Data;

    /// <summary>Gets one page of historical WHOIS snapshots for a domain together with its continuation cursor.</summary>
    public Task<PagedResponse<WhoisRecord>?> GetDomainHistoricalWhoisPageAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetTypedRelationshipPageAsync<WhoisRecord>(ResourceType.Domain, id, "historical_whois", limit, cursor, cancellationToken);

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

    public async Task<IReadOnlyList<FileReport>?> GetDomainReferrerFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => (await GetDomainReferrerFilesPageAsync(id, limit, cursor, cancellationToken).ConfigureAwait(false))?.Data;

    /// <summary>Gets one page of files referring to a domain together with its continuation cursor.</summary>
    public Task<PagedResponse<FileReport>?> GetDomainReferrerFilesPageAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetTypedRelationshipPageAsync<FileReport>(ResourceType.Domain, id, "referrer_files", limit, cursor, cancellationToken);

    public async Task<IReadOnlyList<FileReport>?> GetDomainCommunicatingFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => (await GetDomainCommunicatingFilesPageAsync(id, limit, cursor, cancellationToken).ConfigureAwait(false))?.Data;

    /// <summary>Gets one page of files communicating with a domain together with its continuation cursor.</summary>
    public Task<PagedResponse<FileReport>?> GetDomainCommunicatingFilesPageAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetTypedRelationshipPageAsync<FileReport>(ResourceType.Domain, id, "communicating_files", limit, cursor, cancellationToken);

    public Task<IReadOnlyList<FileReport>?> GetDomainDownloadedFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetDomainRelationshipsAsync<FileReportsResponse, FileReport>(id, "downloaded_files", r => r.Data, limit, cursor, cancellationToken);

    public async Task<IReadOnlyList<SslCertificate>?> GetDomainHistoricalSslCertificatesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => (await GetDomainHistoricalSslCertificatesPageAsync(id, limit, cursor, cancellationToken).ConfigureAwait(false))?.Data;

    /// <summary>Gets one page of historical SSL certificates for a domain together with its continuation cursor.</summary>
    public Task<PagedResponse<SslCertificate>?> GetDomainHistoricalSslCertificatesPageAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetTypedRelationshipPageAsync<SslCertificate>(ResourceType.Domain, id, "historical_ssl_certificates", limit, cursor, cancellationToken);

    public async Task<IReadOnlyList<Resolution>?> GetIpAddressResolutionsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => (await GetIpAddressResolutionsPageAsync(id, limit, cursor, cancellationToken).ConfigureAwait(false))?.Data;

    /// <summary>Gets one page of IP address resolutions together with its continuation cursor.</summary>
    public Task<PagedResponse<Resolution>?> GetIpAddressResolutionsPageAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetTypedRelationshipPageAsync<Resolution>(ResourceType.IpAddress, id, "resolutions", limit, cursor, cancellationToken);

    /// <summary>Gets historical WHOIS snapshots for an IP address.</summary>
    public async Task<IReadOnlyList<WhoisRecord>?> GetIpAddressHistoricalWhoisAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => (await GetIpAddressHistoricalWhoisPageAsync(id, limit, cursor, cancellationToken).ConfigureAwait(false))?.Data;

    /// <summary>Gets one page of historical WHOIS snapshots for an IP address together with its continuation cursor.</summary>
    public Task<PagedResponse<WhoisRecord>?> GetIpAddressHistoricalWhoisPageAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetTypedRelationshipPageAsync<WhoisRecord>(ResourceType.IpAddress, id, "historical_whois", limit, cursor, cancellationToken);

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
        => (await GetIpAddressCommunicatingFilesPageAsync(id, limit, cursor, cancellationToken).ConfigureAwait(false))?.Data;

    /// <summary>Gets one page of files communicating with an IP address together with its continuation cursor.</summary>
    public Task<PagedResponse<FileReport>?> GetIpAddressCommunicatingFilesPageAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetTypedRelationshipPageAsync<FileReport>(ResourceType.IpAddress, id, "communicating_files", limit, cursor, cancellationToken);

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
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<FileReportsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IReadOnlyList<FileReport>?> GetIpAddressReferrerFilesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => (await GetIpAddressReferrerFilesPageAsync(id, limit, cursor, cancellationToken).ConfigureAwait(false))?.Data;

    /// <summary>Gets one page of files referring to an IP address together with its continuation cursor.</summary>
    public Task<PagedResponse<FileReport>?> GetIpAddressReferrerFilesPageAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetTypedRelationshipPageAsync<FileReport>(ResourceType.IpAddress, id, "referrer_files", limit, cursor, cancellationToken);

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
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<UrlSummariesResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IReadOnlyList<SslCertificate>?> GetIpAddressHistoricalSslCertificatesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => (await GetIpAddressHistoricalSslCertificatesPageAsync(id, limit, cursor, cancellationToken).ConfigureAwait(false))?.Data;

    /// <summary>Gets one page of historical SSL certificates for an IP address together with its continuation cursor.</summary>
    public Task<PagedResponse<SslCertificate>?> GetIpAddressHistoricalSslCertificatesPageAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetTypedRelationshipPageAsync<SslCertificate>(ResourceType.IpAddress, id, "historical_ssl_certificates", limit, cursor, cancellationToken);

    private async Task<PagedResponse<T>?> GetTypedRelationshipPageAsync<T>(
        ResourceType resourceType,
        string id,
        string relationship,
        int? limit,
        string? cursor,
        CancellationToken cancellationToken)
    {
        ValidateId(id, nameof(id));
        ValidateLimit(limit, nameof(limit));
        var path = new System.Text.StringBuilder(
            $"{GetPath(resourceType)}/{Uri.EscapeDataString(id)}/{Uri.EscapeDataString(relationship)}");
        var hasQuery = false;
        if (limit.HasValue)
        {
            path.Append("?limit=").Append(limit.Value);
            hasQuery = true;
        }
        if (!string.IsNullOrEmpty(cursor))
            path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(cursor));

        using var response = await _httpClient.GetAsync(path.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<PagedResponse<T>>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
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
        ValidateLimit(limit, nameof(limit));
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
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<TResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result == null ? null : selector(result);
    }

    private async Task<IReadOnlyList<Submission>?> GetSubmissionsAsync(
        ResourceType resourceType,
        string id,
        int? limit,
        string? cursor,
        CancellationToken cancellationToken)
    {
        ValidateId(id, nameof(id));
        ValidateLimit(limit, nameof(limit));
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
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<SubmissionsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }
}
