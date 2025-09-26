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
    public Task<PagedResponse<MonitorEvent>?> ListMonitorEventsAsync(string? filter = null, int? limit = null, string? cursor = null, bool fetchAll = false, CancellationToken ct = default)
        => GetPagedAsync<MonitorEvent>(async (c, token) =>
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
            if (!string.IsNullOrEmpty(c))
            {
                path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(c));
            }
            using var response = await _httpClient.GetAsync(path.ToString(), token).ConfigureAwait(false);
            await EnsureSuccessAsync(response, token).ConfigureAwait(false);
            using var stream = await response.Content.ReadContentStreamAsync(token).ConfigureAwait(false);
            return await JsonSerializer.DeserializeAsync<PagedResponse<MonitorEvent>>(stream, _jsonOptions, token).ConfigureAwait(false);
        }, cursor, fetchAll, ct);

    public Task<PagedResponse<MonitorItem>?> ListMonitorItemsAsync(int? limit = null, string? cursor = null, bool fetchAll = false, CancellationToken cancellationToken = default)
        => GetPagedAsync<MonitorItem>(async (c, token) =>
        {
            var path = new StringBuilder("monitor/items");
            var hasQuery = false;
            if (limit.HasValue)
            {
                path.Append("?limit=").Append(limit.Value);
                hasQuery = true;
            }
            if (!string.IsNullOrEmpty(c))
            {
                path.Append(hasQuery ? '&' : '?').Append("cursor=").Append(Uri.EscapeDataString(c));
            }
            using var response = await _httpClient.GetAsync(path.ToString(), token).ConfigureAwait(false);
            await EnsureSuccessAsync(response, token).ConfigureAwait(false);
            using var stream = await response.Content.ReadContentStreamAsync(token).ConfigureAwait(false);
            return await JsonSerializer.DeserializeAsync<PagedResponse<MonitorItem>>(stream, _jsonOptions, token).ConfigureAwait(false);
        }, cursor, fetchAll, cancellationToken);

    public async Task<MonitorItem?> CreateMonitorItemAsync(CreateMonitorItemRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync("monitor/items", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<MonitorItem>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task<MonitorItem?> UpdateMonitorItemAsync(string id, UpdateMonitorItemRequest request, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        ArgumentNullException.ThrowIfNull(request);
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var message = new HttpRequestMessage(new HttpMethod("PATCH"), $"monitor/items/{Uri.EscapeDataString(id)}") { Content = content };
        using var response = await _httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<MonitorItem>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteMonitorItemAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.DeleteAsync($"monitor/items/{Uri.EscapeDataString(id)}", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }
}
