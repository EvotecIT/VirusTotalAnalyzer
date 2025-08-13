using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

public sealed partial class VirusTotalClient
{
    public async Task<PagedResponse<MonitorEvent>?> ListMonitorEventsAsync(string? filter = null, int? limit = null, string? cursor = null, CancellationToken ct = default)
    {
        var path = new StringBuilder("monitor/events");
        var hasQuery = false;
        if (!string.IsNullOrEmpty(filter))
        {
            path.Append("?filter=").Append(Uri.EscapeDataString(filter));
            hasQuery = true;
        }
        if (limit.HasValue)
        {
            path.Append(hasQuery ? '&' : '?').Append("limit=").Append(limit.Value);
            hasQuery = true;
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(cursor));
        }
        using var response = await _httpClient.GetAsync(path.ToString(), ct).ConfigureAwait(false);
        await EnsureSuccessAsync(response, ct).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<PagedResponse<MonitorEvent>>(stream, _jsonOptions, ct).ConfigureAwait(false);
    }

    public async Task<PagedResponse<MonitorItem>?> ListMonitorItemsAsync(int? limit = null, string? cursor = null, CancellationToken cancellationToken = default)
    {
        var path = new StringBuilder("monitor/items");
        var hasQuery = false;
        if (limit.HasValue)
        {
            path.Append("?limit=").Append(limit.Value);
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
        return await JsonSerializer.DeserializeAsync<PagedResponse<MonitorItem>>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<MonitorItem?> CreateMonitorItemAsync(CreateMonitorItemRequest request, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync("monitor/items", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<MonitorItem>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<MonitorItem?> UpdateMonitorItemAsync(string id, UpdateMonitorItemRequest request, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var message = new HttpRequestMessage(new HttpMethod("PATCH"), $"monitor/items/{Uri.EscapeDataString(id)}") { Content = content };
        using var response = await _httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<MonitorItem>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteMonitorItemAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.DeleteAsync($"monitor/items/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }
}
