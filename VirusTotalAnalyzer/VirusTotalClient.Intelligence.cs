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

public sealed partial class VirusTotalClient
{
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

    public async Task<IReadOnlyList<YaraRuleset>?> ListYaraRulesetsAsync(int? limit = null, string? cursor = null, CancellationToken cancellationToken = default)
    {
        var url = new StringBuilder("intelligence/hunting_rulesets");
        var hasQuery = false;
        if (limit.HasValue)
        {
            url.Append("?limit=").Append(limit.Value);
            hasQuery = true;
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            url.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(cursor));
        }
        using var response = await _httpClient.GetAsync(url.ToString(), cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<YaraRulesetsResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<YaraRuleset?> GetYaraRulesetAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync($"intelligence/hunting_rulesets/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<YaraRuleset>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<YaraRuleset?> CreateYaraRulesetAsync(YaraRulesetRequest request, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync("intelligence/hunting_rulesets", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<YaraRulesetResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task<YaraRuleset?> UpdateYaraRulesetAsync(string id, YaraRulesetRequest request, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var message = new HttpRequestMessage(new HttpMethod("PATCH"), $"intelligence/hunting_rulesets/{id}")
        {
            Content = content
        };
        using var response = await _httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<YaraRulesetResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return result?.Data;
    }

    public async Task DeleteYaraRulesetAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.DeleteAsync($"intelligence/hunting_rulesets/{id}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
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


}}
