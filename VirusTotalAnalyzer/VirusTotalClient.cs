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
public sealed partial class VirusTotalClient : IVirusTotalClient
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
        UserAgent = userAgent ?? string.Empty;
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
            ResourceType.SslCertificate => "ssl_certificates",
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

    private static string GetFeedPath(ResourceType type)
        => type switch
        {
            ResourceType.FileBehaviour => "file-behaviours",
            _ => GetPath(type)
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

        var requestId = TryGetHeaderValue(response.Headers, "x-request-id")
            ?? TryGetHeaderValue(response.Headers, "x-correlation-id");

        string? rawBody = null;
        try
        {
            rawBody = await response.Content.ReadContentStringAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // ignore content read errors
        }

        var error = TryParseApiError(rawBody);

        if ((int)response.StatusCode == 429)
        {
            TimeSpan? retryAfter = null;
            if (response.Headers.TryGetValues("Retry-After", out var values))
            {
                var raw = values.FirstOrDefault();
                if (int.TryParse(raw, out var seconds))
                {
                    if (seconds < 0)
                    {
                        seconds = 0;
                    }
                    retryAfter = TimeSpan.FromSeconds(seconds);
                }
                else if (DateTimeOffset.TryParse(raw, out var date))
                {
                    var delta = date - DateTimeOffset.UtcNow;
                    retryAfter = delta < TimeSpan.Zero ? TimeSpan.Zero : delta;
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

            throw new RateLimitExceededException(error, retryAfter, remainingQuota, response.StatusCode, requestId);
        }

        throw new ApiException(error, null, response.StatusCode, requestId);
    }

    private static string? TryGetHeaderValue(HttpHeaders headers, string name)
    {
        if (headers.TryGetValues(name, out var values))
        {
            return values.FirstOrDefault();
        }

        return null;
    }

    private ApiError? TryParseApiError(string? rawBody)
    {
        if (string.IsNullOrWhiteSpace(rawBody))
        {
            return null;
        }

        var body = rawBody!;
        try
        {
            var wrapper = JsonSerializer.Deserialize<ApiErrorResponse>(body, _jsonOptions);
            if (wrapper?.Error != null)
            {
                return wrapper.Error;
            }
        }
        catch
        {
            // ignore deserialization errors
        }

        return new ApiError { Message = BuildRawErrorMessage(body) };
    }

    private static string BuildRawErrorMessage(string rawBody)
    {
        var trimmed = rawBody.Trim();
        const int maxLength = 2048;
        if (trimmed.Length > maxLength)
        {
            trimmed = trimmed.Substring(0, maxLength) + "...";
        }

        return $"Raw error response: {trimmed}";
    }

    public Task<PagedResponse<FileNameInfo>?> GetFileNamesPagedAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        bool fetchAll = false,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        return GetPagedAsync<FileNameInfo>(async (c, token) =>
        {
            var url = new StringBuilder($"files/{Uri.EscapeDataString(id)}/names");
            var hasQuery = false;
            if (limit.HasValue)
            {
                url.Append("?limit=").Append(limit.Value);
                hasQuery = true;
            }
            if (!string.IsNullOrEmpty(c))
            {
                url.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(c));
            }

            using var response = await _httpClient.GetAsync(url.ToString(), token).ConfigureAwait(false);
            await EnsureSuccessAsync(response, token).ConfigureAwait(false);
            using var stream = await response.Content.ReadContentStreamAsync(token).ConfigureAwait(false);
            return await JsonSerializer.DeserializeAsync<PagedResponse<FileNameInfo>>(stream, _jsonOptions, token)
                .ConfigureAwait(false);
        }, cursor, fetchAll, cancellationToken);
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
            var page = await GetFileNamesPagedAsync(id, remaining, nextCursor, fetchAll: false, cancellationToken)
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

    public IAsyncEnumerable<FileNameInfo> GetFileNamesAsyncEnumerable(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        if (limit == 0)
        {
            return Empty();
        }

        var remaining = limit;
        return GetPagedAsyncEnumerable<FileNameInfo>(async (c, token) =>
        {
            if (remaining.HasValue && remaining <= 0)
            {
                return null;
            }

            var page = await GetFileNamesPagedAsync(id, remaining, c, fetchAll: false, token).ConfigureAwait(false);
            if (page != null && remaining.HasValue)
            {
                remaining -= page.Data.Count;
            }
            return page;
        }, cursor, cancellationToken);

        static async IAsyncEnumerable<FileNameInfo> Empty()
        {
            await Task.CompletedTask;
            yield break;
        }
    }

    public async Task<Stream> DownloadLivehuntNotificationFileAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var response = await _httpClient
            .GetAsync($"intelligence/hunting_notification_files/{Uri.EscapeDataString(id)}", HttpCompletionOption.ResponseHeadersRead, cancellationToken)
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

    public async Task<Stream> DownloadRetrohuntNotificationFileAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var response = await _httpClient
            .GetAsync($"intelligence/retrohunt_notification_files/{Uri.EscapeDataString(id)}", HttpCompletionOption.ResponseHeadersRead, cancellationToken)
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

    public async Task<Stream> DownloadPcapAsync(string analysisId, CancellationToken cancellationToken = default)
    {
        ValidateId(analysisId, nameof(analysisId));
        var response = await _httpClient
            .GetAsync($"analyses/{Uri.EscapeDataString(analysisId)}/pcap", HttpCompletionOption.ResponseHeadersRead, cancellationToken)
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
