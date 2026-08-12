using System;
using System.Collections.Generic;
using System.Globalization;
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

public sealed partial class VirusTotalClient
{
    public async Task<LivehuntNotification?> GetLivehuntNotificationAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"intelligence/hunting_notifications/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<LivehuntNotificationResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<Page<LivehuntNotification>> ListLivehuntNotificationsAsync(int limit = 10, string? cursor = null, bool fetchAll = false, CancellationToken cancellationToken = default)
    {
        var results = new List<LivehuntNotification>();
        var nextCursor = cursor;

        do
        {
            var url = $"intelligence/hunting_notifications?limit={limit}";
            if (!string.IsNullOrEmpty(nextCursor))
            {
                url += $"&cursor={Uri.EscapeDataString(nextCursor)}";
            }
            using var response = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
            await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
            using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
            var page = await JsonSerializer.DeserializeAsync<LivehuntNotificationsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
            if (page?.Data != null)
            {
                results.AddRange(page.Data);
            }
            nextCursor = page?.Meta?.Cursor;
            if (!fetchAll)
            {
                break;
            }
        }
        while (!string.IsNullOrEmpty(nextCursor));

        return new Page<LivehuntNotification>(results, nextCursor);
    }

    public async Task DeleteLivehuntNotificationAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.DeleteAsync($"intelligence/hunting_notifications/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }

    public async Task AcknowledgeLivehuntNotificationAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.PostAsync($"intelligence/hunting_notifications/{Uri.EscapeDataString(id)}/acknowledge", null, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }

    public async Task<RetrohuntJob?> GetRetrohuntJobAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"intelligence/retrohunt_jobs/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<RetrohuntJob>(stream, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Page<RetrohuntJob>> ListRetrohuntJobsAsync(int limit = 10, string? cursor = null, bool fetchAll = false, CancellationToken cancellationToken = default)
    {
        var results = new List<RetrohuntJob>();
        var nextCursor = cursor;

        do
        {
            var url = $"intelligence/retrohunt_jobs?limit={limit}";
            if (!string.IsNullOrEmpty(nextCursor))
            {
                url += $"&cursor={Uri.EscapeDataString(nextCursor)}";
            }
            using var response = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
            await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
            using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
            var page = await JsonSerializer.DeserializeAsync<RetrohuntJobsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
            if (page?.Data != null)
            {
                results.AddRange(page.Data);
            }
            nextCursor = page?.Meta?.Cursor;
            if (!fetchAll)
            {
                break;
            }
        }
        while (!string.IsNullOrEmpty(nextCursor));

        return new Page<RetrohuntJob>(results, nextCursor);
    }

    public async Task<RetrohuntJob?> CreateRetrohuntJobAsync(RetrohuntJobRequest request, CancellationToken cancellationToken = default)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync("intelligence/retrohunt_jobs", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<RetrohuntJobResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task DeleteRetrohuntJobAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.DeleteAsync($"intelligence/retrohunt_jobs/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }

    public async Task<RetrohuntNotification?> GetRetrohuntNotificationAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"intelligence/retrohunt_notifications/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<RetrohuntNotification>(stream, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Page<RetrohuntNotification>> ListRetrohuntNotificationsAsync(int limit = 10, string? cursor = null, bool fetchAll = false, CancellationToken cancellationToken = default)
    {
        var results = new List<RetrohuntNotification>();
        var nextCursor = cursor;

        do
        {
            var url = $"intelligence/retrohunt_notifications?limit={limit}";
            if (!string.IsNullOrEmpty(nextCursor))
            {
                url += $"&cursor={Uri.EscapeDataString(nextCursor)}";
            }
            using var response = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
            await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
            using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
            var page = await JsonSerializer.DeserializeAsync<RetrohuntNotificationsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
            if (page?.Data != null)
            {
                results.AddRange(page.Data);
            }
            nextCursor = page?.Meta?.Cursor;
            if (!fetchAll)
            {
                break;
            }
        }
        while (!string.IsNullOrEmpty(nextCursor));

        return new Page<RetrohuntNotification>(results, nextCursor);
    }

    public async Task DeleteRetrohuntNotificationAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.DeleteAsync($"intelligence/retrohunt_notifications/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Page<YaraRuleset>> ListYaraRulesetsAsync(int? limit = null, string? cursor = null, bool fetchAll = true, CancellationToken cancellationToken = default)
    {
        var results = new List<YaraRuleset>();
        var nextCursor = cursor;

        do
        {
            var url = new StringBuilder("intelligence/hunting_rulesets");
            var hasQuery = false;
            if (limit.HasValue)
            {
                url.Append("?limit=").Append(limit.Value);
                hasQuery = true;
            }
            if (!string.IsNullOrEmpty(nextCursor))
            {
                url.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(nextCursor));
            }
            using var response = await _httpClient.GetAsync(url.ToString(), cancellationToken).ConfigureAwait(false);
            await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
            using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
            var page = await JsonSerializer.DeserializeAsync<YaraRulesetsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
            if (page?.Data != null)
            {
                results.AddRange(page.Data);
            }
            nextCursor = page?.Meta?.Cursor;
            if (!fetchAll)
            {
                break;
            }
        }
        while (!string.IsNullOrEmpty(nextCursor));

        return new Page<YaraRuleset>(results, nextCursor);
    }

    public async Task<YaraRuleset?> GetYaraRulesetAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"intelligence/hunting_rulesets/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<YaraRuleset>(stream, cancellationToken).ConfigureAwait(false);
    }

    public async Task<YaraRuleset?> CreateYaraRulesetAsync(YaraRulesetRequest request, CancellationToken cancellationToken = default)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync("intelligence/hunting_rulesets", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<YaraRulesetResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<YaraRuleset?> UpdateYaraRulesetAsync(string id, YaraRulesetRequest request, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var message = new HttpRequestMessage(new HttpMethod("PATCH"), $"intelligence/hunting_rulesets/{Uri.EscapeDataString(id)}")
        {
            Content = content
        };
        using var response = await _httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<YaraRulesetResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task DeleteYaraRulesetAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.DeleteAsync($"intelligence/hunting_rulesets/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<YaraWatcher>?> GetYaraRulesetWatchersAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync($"intelligence/hunting_rulesets/{Uri.EscapeDataString(id)}/watchers", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<YaraWatcherResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<IReadOnlyList<YaraWatcher>?> AddYaraRulesetWatchersAsync(string id, YaraWatcherRequest request, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync($"intelligence/hunting_rulesets/{Uri.EscapeDataString(id)}/watchers", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<YaraWatcherResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task RemoveYaraRulesetWatcherAsync(string id, string watcherId, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.DeleteAsync($"intelligence/hunting_rulesets/{Uri.EscapeDataString(id)}/watchers/{Uri.EscapeDataString(watcherId)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }

    public Task<Stream> DownloadYaraRulesetAsync(string id, CancellationToken ct = default)
    {
        ValidateId(id, nameof(id));
        return DownloadFromAuthenticatedEndpointAsync(
            $"intelligence/hunting_rulesets/{Uri.EscapeDataString(id)}/download",
            ct);
    }

    public async Task<Relationship?> GetYaraRulesetOwnerAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var response = await GetRelationshipsAsync(ResourceType.IntelligenceHuntingRuleset, id, "owner", cancellationToken: cancellationToken).ConfigureAwait(false);
        return response?.Data.FirstOrDefault();
    }

    public async Task<IReadOnlyList<Relationship>?> GetYaraRulesetEditorsAsync(string id, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var response = await GetRelationshipsAsync(ResourceType.IntelligenceHuntingRuleset, id, "editors", limit, cursor, cancellationToken).ConfigureAwait(false);
        return response?.Data;
    }

    public async Task<RelationshipResponse?> GetRelationshipsAsync(ResourceType resourceType, string id, string relationship, int? limit = null, string? cursor = null, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var sb = new StringBuilder($"{GetPath(resourceType)}/{Uri.EscapeDataString(id)}/relationships/{Uri.EscapeDataString(relationship)}");
        var hasQuery = false;
        if (limit.HasValue)
        {
            sb.Append("?limit=").Append(limit.Value);
            hasQuery = true;
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            sb.Append(hasQuery ? "&" : "?").Append("cursor=").Append(Uri.EscapeDataString(cursor));
        }

        using var response = await _httpClient.GetAsync(sb.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<RelationshipResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<string>> GetPopularThreatCategoriesAsync(CancellationToken ct = default)
    {
        using var response = await _httpClient.GetAsync("popular_threat_categories", ct).ConfigureAwait(false);
        await EnsureSuccessAsync(response, ct).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(ct).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<ThreatCategoriesResponse>(stream, _jsonOptions, ct).ConfigureAwait(false);
        return result?.Data ?? new List<string>();
    }

    /// <summary>Searches the public VirusTotal corpus for an exact IOC or comment tag.</summary>
    public Task<SearchResponse?> SearchAsync(
        string query,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => SearchCoreAsync("search", query, limit, cursor, null, null, cancellationToken);

    /// <summary>Runs a VirusTotal Intelligence advanced corpus search.</summary>
    public Task<SearchResponse?> SearchIntelligenceAsync(
        string query,
        int? limit = null,
        string? cursor = null,
        string? order = null,
        string? descriptor = null,
        CancellationToken cancellationToken = default)
        => SearchCoreAsync("intelligence/search", query, limit, cursor, order, descriptor, cancellationToken);

    private async Task<SearchResponse?> SearchCoreAsync(
        string path,
        string query,
        int? limit,
        string? cursor,
        string? order,
        string? descriptor,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            throw new ArgumentException("Search query must not be empty or whitespace.", nameof(query));
        }
        ValidateLimit(limit, nameof(limit));
        ThrowIfDisposed();

        var sb = new StringBuilder($"{path}?query={Uri.EscapeDataString(query)}");
        if (limit.HasValue)
        {
            sb.Append("&limit=").Append(limit.Value);
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            sb.Append("&cursor=").Append(Uri.EscapeDataString(cursor));
        }
        if (!string.IsNullOrEmpty(order))
        {
            sb.Append("&order=").Append(Uri.EscapeDataString(order));
        }
        if (!string.IsNullOrEmpty(descriptor))
        {
            sb.Append("&descriptor=").Append(Uri.EscapeDataString(descriptor));
        }
        using var response = await _httpClient.GetAsync(sb.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<SearchResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IocStreamResponse?> GetIocStreamAsync(
        string? filter = null,
        int? limit = null,
        bool descriptorsOnly = false,
        string? cursor = null,
        string? order = null,
        CancellationToken ct = default)
    {
        if (filter is not null && string.IsNullOrWhiteSpace(filter))
        {
            throw new ArgumentException("IoC Stream filter must not be empty or whitespace.", nameof(filter));
        }
        if (limit is < 1 or > 40)
        {
            throw new ArgumentOutOfRangeException(nameof(limit), "IoC Stream limit must be between 1 and 40.");
        }

        var parameters = new List<string>();
        if (filter is not null)
        {
            parameters.Add($"filter={Uri.EscapeDataString(filter)}");
        }
        if (limit.HasValue)
        {
            parameters.Add($"limit={limit.Value}");
        }
        if (descriptorsOnly)
        {
            parameters.Add("descriptors_only=true");
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            parameters.Add($"cursor={Uri.EscapeDataString(cursor)}");
        }
        if (!string.IsNullOrEmpty(order))
        {
            parameters.Add($"order={Uri.EscapeDataString(order)}");
        }
        var path = parameters.Count == 0 ? "ioc_stream" : $"ioc_stream?{string.Join("&", parameters)}";
        using var response = await _httpClient.GetAsync(path, ct).ConfigureAwait(false);
        await EnsureSuccessAsync(response, ct).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(ct).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<IocStreamResponse>(stream, _jsonOptions, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Downloads a compressed licensed feed batch. Minute batches are bzip2 JSONL; hour batches
    /// are tar.bz2 archives containing the minute batches.
    /// </summary>
    public Task<Stream> DownloadFeedBatchAsync(
        FeedType feedType,
        DateTimeOffset time,
        FeedGranularity granularity,
        CancellationToken cancellationToken = default)
    {
        var feedPath = feedType switch
        {
            FeedType.Files => "files",
            FeedType.FileBehaviors => "file_behaviours",
            FeedType.Domains => "domains",
            FeedType.IpAddresses => "ip_addresses",
            FeedType.Urls => "urls",
            _ => throw new ArgumentOutOfRangeException(nameof(feedType))
        };
        var utc = time.ToUniversalTime();
        var timestamp = granularity switch
        {
            FeedGranularity.Minute => utc.ToString("yyyyMMddHHmm", CultureInfo.InvariantCulture),
            FeedGranularity.Hour => utc.ToString("yyyyMMddHH", CultureInfo.InvariantCulture),
            _ => throw new ArgumentOutOfRangeException(nameof(granularity))
        };
        var path = granularity == FeedGranularity.Hour
            ? $"feeds/{feedPath}/hourly/{timestamp}"
            : $"feeds/{feedPath}/{timestamp}";
        return DownloadFromAuthenticatedEndpointAsync(path, cancellationToken);
    }
}
