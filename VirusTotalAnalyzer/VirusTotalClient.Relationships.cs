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
    public Task<IReadOnlyList<Submission>?> GetFileSubmissionsAsync(string id, CancellationToken cancellationToken = default)
        => GetSubmissionsAsync(ResourceType.File, id, cancellationToken);

    public Task<IReadOnlyList<Resolution>?> GetDomainResolutionsAsync(string id, CancellationToken cancellationToken = default)
        => GetResolutionsAsync(ResourceType.Domain, id, cancellationToken);

    public Task<IReadOnlyList<Submission>?> GetDomainSubmissionsAsync(string id, CancellationToken cancellationToken = default)
        => GetSubmissionsAsync(ResourceType.Domain, id, cancellationToken);

    public Task<IReadOnlyList<DomainSummary>?> GetDomainSubdomainsAsync(string id, CancellationToken cancellationToken = default)
        => GetDomainRelationshipsAsync<DomainSubdomainsResponse, DomainSummary>(id, "subdomains", r => r.Data, cancellationToken);

    public Task<IReadOnlyList<DomainSummary>?> GetDomainSiblingsAsync(string id, CancellationToken cancellationToken = default)
        => GetDomainRelationshipsAsync<DomainSiblingsResponse, DomainSummary>(id, "siblings", r => r.Data, cancellationToken);

    public Task<IReadOnlyList<UrlSummary>?> GetDomainUrlsAsync(string id, CancellationToken cancellationToken = default)
        => GetDomainRelationshipsAsync<DomainUrlsResponse, UrlSummary>(id, "urls", r => r.Data, cancellationToken);

    public Task<IReadOnlyList<DnsRecord>?> GetDomainDnsRecordsAsync(string id, CancellationToken cancellationToken = default)
        => GetDomainRelationshipsAsync<DnsRecordsResponse, DnsRecord>(id, "dns_records", r => r.Data, cancellationToken);

    public Task<IReadOnlyList<Resolution>?> GetIpAddressResolutionsAsync(string id, CancellationToken cancellationToken = default)
        => GetResolutionsAsync(ResourceType.IpAddress, id, cancellationToken);

    public Task<IReadOnlyList<Submission>?> GetIpAddressSubmissionsAsync(string id, CancellationToken cancellationToken = default)
        => GetSubmissionsAsync(ResourceType.IpAddress, id, cancellationToken);

    private async Task<IReadOnlyList<T>?> GetDomainRelationshipsAsync<TResponse, T>(
        string id,
        string relationship,
        Func<TResponse, List<T>> selector,
        CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync($"domains/{id}/{relationship}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<TResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result == null ? null : selector(result);
    }

    private async Task<IReadOnlyList<Resolution>?> GetResolutionsAsync(ResourceType resourceType, string id, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync($"{GetPath(resourceType)}/{id}/resolutions", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<ResolutionsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    private async Task<IReadOnlyList<Submission>?> GetSubmissionsAsync(ResourceType resourceType, string id, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync($"{GetPath(resourceType)}/{id}/submissions", cancellationToken).ConfigureAwait(false);
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
