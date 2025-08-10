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

public sealed partial class VirusTotalClient : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly JsonSerializerOptions _jsonOptions;
    private readonly bool _disposeClient;
    private bool _disposed;

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
            ResourceType.IntelligenceHuntingRuleset => "intelligence/hunting_rulesets",
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

