using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

public sealed partial class VirusTotalClient
{
    /// <summary>Retrieves reports for multiple IP addresses with one V3 object request per id.</summary>
    public async Task<IReadOnlyList<IpAddressReport>> GetIpAddressReportsAsync(
        IEnumerable<string> ids,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        return await GetManyAsync(
                ids,
                (id, token) => GetIpAddressReportAsync(id, fields, relationships, token),
                nameof(ids),
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<IpAddressReport?> GetIpAddressReportAsync(
        string id,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var url = BuildObjectUrl("ip_addresses", id, fields, relationships);
        using var response = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
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
        return await DeserializeDataAsync<IpWhois>(stream, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Retrieves reports for multiple domains with one V3 object request per id.</summary>
    public async Task<IReadOnlyList<DomainReport>> GetDomainReportsAsync(
        IEnumerable<string> ids,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        return await GetManyAsync(
                ids,
                (id, token) => GetDomainReportAsync(id, fields, relationships, token),
                nameof(ids),
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<DomainReport?> GetDomainReportAsync(
        string id,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var url = BuildObjectUrl("domains", id, fields, relationships);
        using var response = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
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
        return await DeserializeDataAsync<DomainWhois>(stream, cancellationToken).ConfigureAwait(false);
    }

    private static string BuildObjectUrl(
        string resourcePath,
        string id,
        IEnumerable<string>? fields,
        IEnumerable<string>? relationships)
    {
        var url = new StringBuilder($"{resourcePath}/{Uri.EscapeDataString(id)}");
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
        return url.ToString();
    }
}
