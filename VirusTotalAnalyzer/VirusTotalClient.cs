using System;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

/// <summary>
/// Client for the VirusTotal v3 API.
/// </summary>
public sealed class VirusTotalClient
{
    private readonly HttpClient _httpClient;
    private readonly JsonSerializerOptions _jsonOptions;

    public VirusTotalClient(HttpClient httpClient)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
        _jsonOptions.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
    }

    public async Task<FileReport?> GetFileReportAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"files/{id}", cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<FileReport>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<UrlReport?> GetUrlReportAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"urls/{id}", cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<UrlReport>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<IpAddressReport?> GetIpAddressReportAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"ip_addresses/{id}", cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
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
        response.EnsureSuccessStatusCode();
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
        response.EnsureSuccessStatusCode();
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<AnalysisReport>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }
}
