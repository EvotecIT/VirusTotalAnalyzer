using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
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
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
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
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
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
            if (report?.Data.Attributes.Status == AnalysisStatus.Completed)
            {
                return report;
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

    public async Task<IReadOnlyList<Comment>?> GetCommentsAsync(ResourceType resourceType, string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"{GetPath(resourceType)}/{id}/comments", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<CommentsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IReadOnlyList<Vote>?> GetVotesAsync(ResourceType resourceType, string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"{GetPath(resourceType)}/{id}/votes", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<VotesResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<RelationshipResponse?> GetRelationshipsAsync(ResourceType resourceType, string id, string relationship, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"{GetPath(resourceType)}/{id}/relationships/{relationship}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<RelationshipResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<SearchResponse?> SearchAsync(string query, CancellationToken cancellationToken = default)
    {
        var encoded = Uri.EscapeDataString(query);
        using var response = await _httpClient.GetAsync($"intelligence/search?query={encoded}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<SearchResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<FeedResponse?> GetFeedAsync(ResourceType resourceType, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"feeds/{GetPath(resourceType)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<FeedResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Uri?> GetUploadUrlAsync(CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync("files/upload_url", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<UploadUrlResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        if (result is null || string.IsNullOrEmpty(result.Data))
        {
            return null;
        }
        return new Uri(result.Data);
    }

    public async Task<AnalysisReport?> SubmitFileAsync(Stream stream, string fileName, AnalysisType analysisType = AnalysisType.File, string? password = null, CancellationToken cancellationToken = default)
    {
        if (analysisType != AnalysisType.File)
        {
            throw new ArgumentOutOfRangeException(nameof(analysisType));
        }

        string requestUrl = "files";
        if (stream.CanSeek && stream.Length > 33554432)
        {
            var uploadUrl = await GetUploadUrlAsync(cancellationToken).ConfigureAwait(false);
            if (uploadUrl is null)
            {
                throw new InvalidOperationException("Upload URL was not provided by the API.");
            }
            requestUrl = uploadUrl.ToString();
        }

        using var content = MultipartFormDataHelper.Create(stream, fileName);
        using var request = new HttpRequestMessage(HttpMethod.Post, requestUrl)
        {
            Content = content
        };
        if (!string.IsNullOrEmpty(password))
        {
            request.Headers.Add("password", password);
        }
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var respStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var respStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<AnalysisReport>(respStream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public Task<AnalysisReport?> SubmitFileAsync(Stream stream, string fileName, CancellationToken cancellationToken = default)
        => SubmitFileAsync(stream, fileName, AnalysisType.File, null, cancellationToken);

    public async Task<AnalysisReport?> ReanalyzeHashAsync(string hash, AnalysisType analysisType = AnalysisType.File, CancellationToken cancellationToken = default)
    {
        var path = $"{GetPath(analysisType)}/{hash}/analyse";
        using var response = await _httpClient.PostAsync(path, content: null, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<AnalysisReport>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public Task<AnalysisReport?> ReanalyzeFileAsync(string hash, CancellationToken cancellationToken = default)
        => ReanalyzeHashAsync(hash, AnalysisType.File, cancellationToken);

    public Task<AnalysisReport?> ReanalyzeUrlAsync(string id, CancellationToken cancellationToken = default)
        => ReanalyzeHashAsync(id, AnalysisType.Url, cancellationToken);

    public async Task<AnalysisReport?> SubmitUrlAsync(string url, AnalysisType analysisType = AnalysisType.Url, CancellationToken cancellationToken = default)
    {
        if (analysisType != AnalysisType.Url)
        {
            throw new ArgumentOutOfRangeException(nameof(analysisType));
        }
        using var content = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("url", url) });
        using var response = await _httpClient.PostAsync("urls", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<AnalysisReport>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public Task<AnalysisReport?> SubmitUrlAsync(string url, CancellationToken cancellationToken = default)
        => SubmitUrlAsync(url, AnalysisType.Url, cancellationToken);

    private static string GetPath(AnalysisType type)
        => type switch
        {
            AnalysisType.File => "files",
            AnalysisType.Url => "urls",
            _ => throw new ArgumentOutOfRangeException(nameof(type))
        };

    private static string GetPath(ResourceType type)
        => type switch
        {
            ResourceType.File => "files",
            ResourceType.Url => "urls",
            ResourceType.IpAddress => "ip_addresses",
            ResourceType.Domain => "domains",
            ResourceType.Analysis => "analyses",
            _ => throw new ArgumentOutOfRangeException(nameof(type))
        };

    private async Task EnsureSuccessAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        ApiError? error = null;
        try
        {
#if NET472
            using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
            var wrapper = await JsonSerializer.DeserializeAsync<ApiErrorResponse>(stream, _jsonOptions, cancellationToken)
                .ConfigureAwait(false);
            error = wrapper?.Error;
        }
        catch
        {
            // ignore deserialization errors
        }

        if ((int)response.StatusCode == 429)
        {
            TimeSpan? retryAfter = null;
            if (response.Headers.TryGetValues("Retry-After", out var values))
            {
                var raw = values.FirstOrDefault();
                if (int.TryParse(raw, out var seconds))
                {
                    retryAfter = TimeSpan.FromSeconds(seconds);
                }
                else if (DateTimeOffset.TryParse(raw, out var date))
                {
                    retryAfter = date - DateTimeOffset.UtcNow;
                }
            }

            int? remainingQuota = null;
            if (response.Headers.TryGetValues("X-RateLimit-Remaining", out var quotaValues))
            {
                var raw = quotaValues.FirstOrDefault();
                if (int.TryParse(raw, out var q))
                {
                    remainingQuota = q;
                }
            }

            throw new RateLimitExceededException(error, retryAfter, remainingQuota);
        }

        throw new ApiException(error);
    }
}
