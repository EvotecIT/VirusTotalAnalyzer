using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

public sealed partial class VirusTotalClient
{
    private async Task<T?> GetDataAsync<T>(string path, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        using var response = await _httpClient.GetAsync(path, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<T>(stream, cancellationToken).ConfigureAwait(false);
    }

    private async Task<PagedResponse<T>?> GetPageAsync<T>(
        string path,
        int? limit,
        string? cursor,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        ValidateLimit(limit, nameof(limit));
        var requestPath = AppendPagination(path, limit, cursor);
        using var response = await _httpClient.GetAsync(requestPath, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<PagedResponse<T>>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<T?> SendJsonDataAsync<TRequest, T>(
        HttpMethod method,
        string path,
        TRequest request,
        CancellationToken cancellationToken)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        ThrowIfDisposed();
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var message = new HttpRequestMessage(method, path) { Content = content };
        using var response = await _httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<T>(stream, cancellationToken).ConfigureAwait(false);
    }

    private async Task<TResponse?> SendJsonResponseAsync<TRequest, TResponse>(
        HttpMethod method,
        string path,
        TRequest request,
        CancellationToken cancellationToken)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        ThrowIfDisposed();
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var message = new HttpRequestMessage(method, path) { Content = content };
        using var response = await _httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<TResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task SendJsonAsync<TRequest>(
        HttpMethod method,
        string path,
        TRequest request,
        CancellationToken cancellationToken)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        ThrowIfDisposed();
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var message = new HttpRequestMessage(method, path) { Content = content };
        using var response = await _httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }

    private static string AppendPagination(string path, int? limit, string? cursor)
    {
        var builder = new StringBuilder(path);
        var separator = path.IndexOf('?') >= 0 ? '&' : '?';
        if (limit.HasValue)
        {
            builder.Append(separator).Append("limit=").Append(limit.Value);
            separator = '&';
        }
        if (!string.IsNullOrEmpty(cursor))
        {
            builder.Append(separator).Append("cursor=").Append(Uri.EscapeDataString(cursor));
        }
        return builder.ToString();
    }
}
