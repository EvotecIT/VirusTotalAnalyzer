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

/// <summary>
/// Client for the VirusTotal v3 API.
/// </summary>
/// <remarks>
/// <para>Use <see cref="Create(string)"/> for a self-contained client:</para>
/// <code>using var client = VirusTotalClient.Create("YOUR_API_KEY");</code>
/// <para>
/// When providing an existing <see cref="HttpClient"/>, specify whether the client should
/// dispose it by setting the <c>disposeClient</c> parameter in the constructor.
/// </para>
/// </remarks>
public sealed class VirusTotalClient : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly JsonSerializerOptions _jsonOptions;
    private readonly bool _disposeClient;
    private bool _disposed;
    /// <summary>
    /// Initializes a new instance of the <see cref="VirusTotalClient"/> class using an existing
    /// <see cref="HttpClient"/>.
    /// </summary>
    /// <param name="httpClient">The <see cref="HttpClient"/> to use for requests.</param>
    /// <param name="disposeClient">
    /// Set to <see langword="true"/> to dispose <paramref name="httpClient"/> when this instance
    /// is disposed.
    /// </param>
    /// <remarks>
    /// Pass <paramref name="disposeClient"/> as <see langword="false"/> when the lifetime of the
    /// provided <paramref name="httpClient"/> is managed externally.
    /// </remarks>
    public VirusTotalClient(HttpClient httpClient, bool disposeClient = false)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _disposeClient = disposeClient;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
        _jsonOptions.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
        _jsonOptions.Converters.Add(new UnixTimestampConverter());
    }

    /// <summary>
    /// Creates a new <see cref="VirusTotalClient"/> configured with the specified API key.
    /// </summary>
    /// <param name="apiKey">The API key used for authenticated requests.</param>
    /// <returns>A <see cref="VirusTotalClient"/> that owns its underlying <see cref="HttpClient"/>.</returns>
    public static VirusTotalClient Create(string apiKey)
    {
        if (string.IsNullOrWhiteSpace(apiKey)) throw new ArgumentException("Value cannot be null or whitespace.", nameof(apiKey));
        var httpClient = new HttpClient
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        httpClient.DefaultRequestHeaders.Add("x-apikey", apiKey);
        return new VirusTotalClient(httpClient, disposeClient: true);
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

    public Task<Comment?> CreateCommentAsync(ResourceType resourceType, string id, string text, CancellationToken cancellationToken = default)
    {
        var request = new CommentRequestBuilder()
            .WithText(text)
            .Build();
        return CreateCommentAsync(resourceType, id, request, cancellationToken);
    }

    public async Task<Comment?> CreateCommentAsync(ResourceType resourceType, string id, CreateCommentRequest request, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync($"{GetPath(resourceType)}/{id}/comments", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<CommentResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public Task<Vote?> CreateVoteAsync(ResourceType resourceType, string id, VoteVerdict verdict, CancellationToken cancellationToken = default)
    {
        var request = new VoteRequestBuilder()
            .WithVerdict(verdict)
            .Build();
        return CreateVoteAsync(resourceType, id, request, cancellationToken);
    }

    public async Task<Vote?> CreateVoteAsync(ResourceType resourceType, string id, CreateVoteRequest request, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync($"{GetPath(resourceType)}/{id}/votes", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<VoteResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task DeleteItemAsync(ResourceType resourceType, string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.DeleteAsync($"{GetPath(resourceType)}/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }

    public async Task<User?> GetUserAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"users/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<User>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Graph?> GetGraphAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"graphs/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<Graph>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Graph?> CreateGraphAsync(CreateGraphRequest request, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync("graphs", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<Graph>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Graph?> UpdateGraphAsync(string id, UpdateGraphRequest request, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var message = new HttpRequestMessage(new HttpMethod("PATCH"), $"graphs/{id}") { Content = content };
        using var response = await _httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<Graph>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteGraphAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.DeleteAsync($"graphs/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Collection?> GetCollectionAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"collections/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<Collection>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Collection?> CreateCollectionAsync(CreateCollectionRequest request, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync("collections", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<Collection>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Collection?> UpdateCollectionAsync(string id, UpdateCollectionRequest request, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var message = new HttpRequestMessage(new HttpMethod("PATCH"), $"collections/{id}") { Content = content };
        using var response = await _httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<Collection>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteCollectionAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.DeleteAsync($"collections/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Bundle?> GetBundleAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"bundles/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<Bundle>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Bundle?> CreateBundleAsync(CreateBundleRequest request, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync("bundles", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<Bundle>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Bundle?> UpdateBundleAsync(string id, UpdateBundleRequest request, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var message = new HttpRequestMessage(new HttpMethod("PATCH"), $"bundles/{id}") { Content = content };
        using var response = await _httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<Bundle>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteBundleAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.DeleteAsync($"bundles/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }

    public async Task<LivehuntNotification?> GetLivehuntNotificationAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"{GetPath(ResourceType.LivehuntNotification)}/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<LivehuntNotification>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<LivehuntNotification>> ListLivehuntNotificationsAsync(int limit = 10, CancellationToken cancellationToken = default)
    {
        var results = new List<LivehuntNotification>();
        string? cursor = null;

        do
        {
            var url = $"intelligence/hunting_notifications?limit={limit}";
            if (!string.IsNullOrEmpty(cursor))
            {
                url += $"&cursor={Uri.EscapeDataString(cursor)}";
            }
            using var response = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
            await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
            using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
            var page = await JsonSerializer.DeserializeAsync<LivehuntNotificationsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
            if (page?.Data != null)
            {
                results.AddRange(page.Data);
            }
            cursor = page?.Meta?.Cursor;
        }
        while (!string.IsNullOrEmpty(cursor));

        return results;
    }

    public async Task<RetrohuntJob?> GetRetrohuntJobAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"{GetPath(ResourceType.RetrohuntJob)}/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<RetrohuntJob>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<RetrohuntJob>> ListRetrohuntJobsAsync(int limit = 10, CancellationToken cancellationToken = default)
    {
        var results = new List<RetrohuntJob>();
        string? cursor = null;

        do
        {
            var url = $"intelligence/retrohunt_jobs?limit={limit}";
            if (!string.IsNullOrEmpty(cursor))
            {
                url += $"&cursor={Uri.EscapeDataString(cursor)}";
            }
            using var response = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
            await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
            using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
            var page = await JsonSerializer.DeserializeAsync<RetrohuntJobsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
            if (page?.Data != null)
            {
                results.AddRange(page.Data);
            }
            cursor = page?.Meta?.Cursor;
        }
        while (!string.IsNullOrEmpty(cursor));

        return results;
    }

    public async Task<RetrohuntNotification?> GetRetrohuntNotificationAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"{GetPath(ResourceType.RetrohuntNotification)}/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<RetrohuntNotification>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<MonitorItem?> GetMonitorItemAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"{GetPath(ResourceType.MonitorItem)}/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<MonitorItem>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
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

    public async Task<SearchResponse?> SearchAsync(string query, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default)
    {
        var sb = new StringBuilder($"intelligence/search?query={Uri.EscapeDataString(query)}");
        if (limit.HasValue)
        {
            sb.Append("&limit=").Append(limit.Value);
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            sb.Append("&cursor=").Append(Uri.EscapeDataString(cursor));
        }
        using var response = await _httpClient.GetAsync(sb.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<SearchResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<FeedResponse?> GetFeedAsync(ResourceType resourceType, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default)
    {
        var path = new StringBuilder($"feeds/{GetPath(resourceType)}");
        var hasQuery = false;
        if (limit.HasValue)
        {
            path.Append(hasQuery ? '&' : '?').Append("limit=").Append(limit.Value);
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

        var builder = new MultipartFormDataBuilder(stream, fileName);
        using var content = builder.Build();
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

    public async Task<PrivateAnalysis?> SubmitPrivateFileAsync(
        Stream stream,
        string fileName,
        string? password = null,
        CancellationToken cancellationToken = default)
    {
        var builder = new MultipartFormDataBuilder(stream, fileName);
        using var content = builder.Build();
        using var request = new HttpRequestMessage(HttpMethod.Post, "private/analyses")
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
        return await JsonSerializer.DeserializeAsync<PrivateAnalysis>(respStream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }


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
            AnalysisType.PrivateFile => "private/files",
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
            ResourceType.PrivateAnalysis => "private/analyses",
            ResourceType.Comment => "comments",
            ResourceType.Vote => "votes",
            ResourceType.Relationship => "relationships",
            ResourceType.Search => "intelligence/search",
            ResourceType.Feed => "feeds",
            ResourceType.Graph => "graphs",
            ResourceType.User => "users",
            ResourceType.Collection => "collections",
            ResourceType.Bundle => "bundles",
            ResourceType.LivehuntNotification => "livehunt_notifications",
            ResourceType.RetrohuntJob => "retrohunt_jobs",
            ResourceType.RetrohuntNotification => "retrohunt_notifications",
            ResourceType.MonitorItem => "monitor/items",
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

    /// <summary>
    /// Releases resources used by the client.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (_disposeClient)
        {
            _httpClient.Dispose();
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
