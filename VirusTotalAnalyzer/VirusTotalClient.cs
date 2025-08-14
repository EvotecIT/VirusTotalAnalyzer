using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
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
public sealed partial class VirusTotalClient : IDisposable
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
    public VirusTotalClient(HttpClient httpClient, bool disposeClient = false, string? userAgent = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _disposeClient = disposeClient;
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = SnakeCaseNamingPolicy.Instance
        };
        _jsonOptions.Converters.Add(new JsonStringEnumMemberConverter());
        _jsonOptions.Converters.Add(new UnixTimestampConverter());
        UserAgent = userAgent;
    }

    /// <summary>
    /// Creates a new <see cref="VirusTotalClient"/> configured with the specified API key.
    /// </summary>
    /// <param name="apiKey">The API key used for authenticated requests.</param>
    /// <returns>A <see cref="VirusTotalClient"/> that owns its underlying <see cref="HttpClient"/>.</returns>
    public static VirusTotalClient Create(string apiKey, string? userAgent = null)
    {
        if (string.IsNullOrWhiteSpace(apiKey)) throw new ArgumentException("Value cannot be null or whitespace.", nameof(apiKey));
        var httpClient = new HttpClient
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        httpClient.DefaultRequestHeaders.Add("x-apikey", apiKey);
        return new VirusTotalClient(httpClient, disposeClient: true, userAgent: userAgent);
    }

    /// <summary>
    /// Gets or sets the user agent used for outgoing requests.
    /// </summary>
    public string UserAgent
    {
        get => _httpClient.DefaultRequestHeaders.UserAgent.ToString();
        set
        {
            var agent = string.IsNullOrWhiteSpace(value) ? GetDefaultUserAgent() : value;
            _httpClient.DefaultRequestHeaders.UserAgent.Clear();
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(agent);
        }
    }

    private static string GetDefaultUserAgent()
    {
        var asm = typeof(VirusTotalClient).Assembly.GetName();
        var version = asm.Version?.ToString() ?? "1.0.0.0";
        return $"{asm.Name}/{version}";
    }

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
            ResourceType.MonitorEvent => "monitor/events",
            ResourceType.IntelligenceHuntingRuleset => "intelligence/hunting_rulesets",
            ResourceType.FileBehaviour => "file-behaviour",
            _ => throw new ArgumentOutOfRangeException(nameof(type))
        };

    private static void ValidateId(string id, string paramName)
    {
        if (id is null)
        {
            throw new ArgumentNullException(paramName);
        }
        if (id.Length == 0)
        {
            throw new ArgumentException("Id must not be empty.", paramName);
        }
    }

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

    public async Task<(List<FileNameInfo> Names, string? Cursor)> GetFileNamesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        if (limit == 0)
        {
            return (new List<FileNameInfo>(), cursor);
        }

        var results = new List<FileNameInfo>();
        var remaining = limit;
        var nextCursor = cursor;

        do
        {
            var url = new StringBuilder($"files/{Uri.EscapeDataString(id)}/names");
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
            var page = await JsonSerializer.DeserializeAsync<FileNamesResponse>(stream, _jsonOptions, cancellationToken)
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

    public async Task<Stream> DownloadLivehuntNotificationFileAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var response = await _httpClient.GetAsync($"intelligence/hunting_notification_files/{Uri.EscapeDataString(id)}", HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        return await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        return await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
    }

    public async Task<Stream> DownloadRetrohuntNotificationFileAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var response = await _httpClient
            .GetAsync($"intelligence/retrohunt_notification_files/{Uri.EscapeDataString(id)}", HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return new StreamWithResponse(response, stream);
    }

    public async Task<Stream> DownloadPcapAsync(string analysisId, CancellationToken cancellationToken = default)
    {
        var response = await _httpClient
            .GetAsync($"analyses/{Uri.EscapeDataString(analysisId)}/pcap", HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return new StreamWithResponse(response, stream);
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

