using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

public sealed partial class VirusTotalClient
{
    private const long MonitorDirectUploadLimit = 32L * 1024L * 1024L;

    public async Task<MonitorUploadResult> UploadMonitorFileAsync(
        string filePath,
        MonitorUploadOptions options,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new ArgumentException("File path must not be null or whitespace.", nameof(filePath));
        }

        using var stream = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            81920,
            useAsync: true);
        return await UploadMonitorFileAsync(stream, Path.GetFileName(filePath), options, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<MonitorUploadResult> UploadMonitorFileAsync(
        Stream stream,
        string fileName,
        MonitorUploadOptions options,
        CancellationToken cancellationToken = default)
    {
        if (stream is null)
        {
            throw new ArgumentNullException(nameof(stream));
        }
        if (!stream.CanRead)
        {
            throw new ArgumentException("The upload stream must be readable.", nameof(stream));
        }
        if (string.IsNullOrWhiteSpace(fileName))
        {
            throw new ArgumentException("File name must not be null or whitespace.", nameof(fileName));
        }
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        ValidateMonitorUploadOptions(options);

        using var prepared = await PreparedMonitorUpload.CreateAsync(stream, cancellationToken).ConfigureAwait(false);
        var useLargeUploadUrl = prepared.Length > MonitorDirectUploadLimit;
        var requestUrl = useLargeUploadUrl
            ? (await GetMonitorUploadUrlAsync(cancellationToken).ConfigureAwait(false)).ToString()
            : "monitor/items";

        var builder = new MultipartFormDataBuilder(prepared.Stream, fileName);
        if (!string.IsNullOrEmpty(options.Path))
        {
            builder.WithFormField("path", options.Path!);
        }
        else
        {
            builder.WithFormField("item", options.ExistingItemId!);
        }

        using var content = builder.Build();
        using var request = new HttpRequestMessage(HttpMethod.Post, requestUrl) { Content = content };
        using var response = await _httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var responseStream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var item = await DeserializeDataAsync<MonitorItem>(responseStream, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException("VirusTotal Monitor returned no item in the upload response.");

        if (options.Details is not null)
        {
            if (string.IsNullOrWhiteSpace(item.Id))
            {
                throw new InvalidDataException("VirusTotal Monitor returned an upload response without an item id.");
            }

            item = await ConfigureMonitorItemAsync(item.Id, options.Details, cancellationToken).ConfigureAwait(false)
                ?? item;
        }

        var result = new MonitorUploadResult
        {
            Item = item,
            LocalSha256 = prepared.Sha256,
            RemoteSha256 = item.Attributes.Sha256,
            DestinationPath = options.Path,
            UsedExistingItemId = !string.IsNullOrEmpty(options.ExistingItemId),
            UsedLargeFileUploadUrl = useLargeUploadUrl,
            VerificationStatus = options.VerifySha256
                ? MonitorUploadVerificationStatus.Pending
                : MonitorUploadVerificationStatus.NotRequested
        };

        if (!options.VerifySha256)
        {
            return result;
        }

        if (string.IsNullOrWhiteSpace(item.Id))
        {
            throw new InvalidDataException("VirusTotal Monitor returned an upload response without an item id.");
        }

        return await VerifyMonitorUploadAsync(result, options, cancellationToken).ConfigureAwait(false);
    }

    public async Task<MonitorItem?> CreateMonitorFolderAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        ValidateMonitorFolderPath(path, nameof(path));
        using var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("path", path)
        });
        using var response = await _httpClient.PostAsync("monitor/items", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<MonitorItem>(stream, cancellationToken).ConfigureAwait(false);
    }

    public async Task<MonitorItem?> ConfigureMonitorItemAsync(
        string id,
        string details,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        if (details is null)
        {
            throw new ArgumentNullException(nameof(details));
        }

        var request = new ConfigureMonitorItemRequest
        {
            Data = new ConfigureMonitorItemData
            {
                Id = id,
                Attributes = new ConfigureMonitorItemAttributes { Details = details }
            }
        };
        var json = JsonSerializer.Serialize(request, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var message = new HttpRequestMessage(
            new HttpMethod("PATCH"),
            $"monitor/items/{Uri.EscapeDataString(id)}/config")
        {
            Content = content
        };
        using var response = await _httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<MonitorItem>(stream, cancellationToken).ConfigureAwait(false);
    }

    public async Task<MonitorItem?> GetMonitorItemAsync(
        string id,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync(
            $"monitor/items/{Uri.EscapeDataString(id)}",
            cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<MonitorItem>(stream, cancellationToken).ConfigureAwait(false);
    }

    public async Task<PagedResponse<MonitorItem>?> ListMonitorItemsAsync(
        string? filter = null,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        var path = BuildMonitorQuery("monitor/items", filter, limit, cursor, null);
        using var response = await _httpClient.GetAsync(path, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<PagedResponse<MonitorItem>>(
            stream,
            _jsonOptions,
            cancellationToken).ConfigureAwait(false);
    }

    public Task<PagedResponse<MonitorItem>?> ListMonitorItemsAsync(
        MonitorItemFilter filter,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        if (filter is null)
        {
            throw new ArgumentNullException(nameof(filter));
        }

        return ListMonitorItemsAsync(filter.Expression, limit, cursor, cancellationToken);
    }

    public IAsyncEnumerable<MonitorItem> EnumerateMonitorItemsAsync(
        string? filter = null,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
        => GetPagedAsyncEnumerable<MonitorItem>(
            (nextCursor, token) => ListMonitorItemsAsync(filter, limit, nextCursor, token),
            cursor,
            cancellationToken);

    public IAsyncEnumerable<MonitorItem> EnumerateMonitorItemsAsync(
        MonitorItemFilter filter,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        if (filter is null)
        {
            throw new ArgumentNullException(nameof(filter));
        }

        return EnumerateMonitorItemsAsync(filter.Expression, limit, cursor, cancellationToken);
    }

    public async Task<PagedResponse<MonitorAnalysis>?> GetMonitorItemAnalysesAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var path = BuildMonitorQuery(
            $"monitor/items/{Uri.EscapeDataString(id)}/analyses",
            null,
            limit,
            cursor,
            null);
        using var response = await _httpClient.GetAsync(path, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<PagedResponse<MonitorAnalysis>>(
            stream,
            _jsonOptions,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<PagedResponse<MonitorItemComment>?> GetMonitorItemCommentsAsync(
        string id,
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        var path = BuildMonitorQuery(
            $"monitor/items/{Uri.EscapeDataString(id)}/comments",
            null,
            limit,
            cursor,
            null);
        using var response = await _httpClient.GetAsync(path, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<PagedResponse<MonitorItemComment>>(
            stream,
            _jsonOptions,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<PagedResponse<MonitorEvent>?> ListMonitorEventsAsync(
        string? filter = null,
        string? cursor = null,
        string? jobId = null,
        CancellationToken cancellationToken = default)
    {
        var path = BuildMonitorQuery("monitor/events", filter, null, cursor, jobId);
        using var response = await _httpClient.GetAsync(path, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<PagedResponse<MonitorEvent>>(
            stream,
            _jsonOptions,
            cancellationToken).ConfigureAwait(false);
    }

    public async IAsyncEnumerable<MonitorEvent> EnumerateMonitorEventsAsync(
        string? filter = null,
        string? cursor = null,
        string? jobId = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var nextCursor = cursor;
        var nextJobId = jobId;
        while (true)
        {
            var page = await ListMonitorEventsAsync(filter, nextCursor, nextJobId, cancellationToken)
                .ConfigureAwait(false);
            if (page is null)
            {
                yield break;
            }

            foreach (var item in page.Data)
            {
                yield return item;
            }

            nextCursor = page.Meta?.Cursor;
            nextJobId = page.Meta?.JobId;
            if (string.IsNullOrEmpty(nextCursor))
            {
                yield break;
            }
        }
    }

    public async Task<MonitorStatisticsResponse?> GetMonitorStatisticsAsync(
        int? limit = null,
        string? cursor = null,
        CancellationToken cancellationToken = default)
    {
        var path = BuildMonitorQuery("monitor/statistics", null, limit, cursor, null);
        using var response = await _httpClient.GetAsync(path, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await JsonSerializer.DeserializeAsync<MonitorStatisticsResponse>(
            stream,
            _jsonOptions,
            cancellationToken).ConfigureAwait(false);
    }

    public Task<Stream> DownloadMonitorItemAsync(string id, CancellationToken cancellationToken = default)
        => DownloadMonitorItemCoreAsync(id, cancellationToken);

    public async Task<Uri?> GetMonitorItemDownloadUrlAsync(
        string id,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.GetAsync(
            $"monitor/items/{Uri.EscapeDataString(id)}/download_url",
            cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var value = await DeserializeDataAsync<string>(stream, cancellationToken).ConfigureAwait(false);
        return Uri.TryCreate(value, UriKind.Absolute, out var uri)
            ? ValidateSignedDownloadUri(uri)
            : null;
    }

    public async Task DeleteMonitorItemAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        using var response = await _httpClient.DeleteAsync(
            $"monitor/items/{Uri.EscapeDataString(id)}",
            cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }

    private async Task<Stream> DownloadMonitorItemCoreAsync(string id, CancellationToken cancellationToken)
    {
        var downloadUri = await GetMonitorItemDownloadUrlAsync(id, cancellationToken).ConfigureAwait(false);
        return await DownloadFromSignedUrlAsync(
            downloadUri ?? throw new InvalidDataException("VirusTotal Monitor returned no signed download URL."),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<Uri> GetMonitorUploadUrlAsync(CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync(
            "monitor/items/upload_url",
            cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var value = await DeserializeDataAsync<string>(stream, cancellationToken).ConfigureAwait(false);
        if (!TryNormalizeVirusTotalUploadUri(value, out var uri) || uri is null)
        {
            throw new InvalidDataException("VirusTotal Monitor returned an invalid or untrusted upload URL.");
        }

        return uri;
    }

    private async Task<MonitorUploadResult> VerifyMonitorUploadAsync(
        MonitorUploadResult result,
        MonitorUploadOptions options,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(result.RemoteSha256))
        {
            if (MonitorHashesMatch(result.LocalSha256, result.RemoteSha256!))
            {
                result.VerificationStatus = MonitorUploadVerificationStatus.Verified;
                return result;
            }

            if (!result.UsedExistingItemId)
            {
                EnsureMonitorHashMatches(result.LocalSha256, result.RemoteSha256!);
            }
        }

        var stopwatch = Stopwatch.StartNew();
        while (true)
        {
            var item = await GetMonitorItemAsync(result.Item.Id, cancellationToken).ConfigureAwait(false);
            if (item is not null)
            {
                result.Item = item;
                result.RemoteSha256 = item.Attributes.Sha256;
                if (!string.IsNullOrWhiteSpace(result.RemoteSha256))
                {
                    if (MonitorHashesMatch(result.LocalSha256, result.RemoteSha256!))
                    {
                        result.VerificationStatus = MonitorUploadVerificationStatus.Verified;
                        return result;
                    }

                    if (!result.UsedExistingItemId)
                    {
                        EnsureMonitorHashMatches(result.LocalSha256, result.RemoteSha256!);
                    }
                }
            }

            var remaining = options.VerificationTimeout - stopwatch.Elapsed;
            if (remaining <= TimeSpan.Zero)
            {
                if (!string.IsNullOrWhiteSpace(result.RemoteSha256))
                {
                    EnsureMonitorHashMatches(result.LocalSha256, result.RemoteSha256!);
                }
                throw new TimeoutException(
                    "VirusTotal Monitor did not provide a remote SHA-256 before the verification timeout.");
            }

            var delay = options.PollingInterval < remaining ? options.PollingInterval : remaining;
            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
        }
    }

    private static void EnsureMonitorHashMatches(string localSha256, string remoteSha256)
    {
        if (!MonitorHashesMatch(localSha256, remoteSha256))
        {
            throw new InvalidDataException(
                $"VirusTotal Monitor SHA-256 mismatch. Local '{localSha256}', remote '{remoteSha256}'.");
        }
    }

    private static bool MonitorHashesMatch(string localSha256, string remoteSha256)
        => string.Equals(localSha256, remoteSha256, StringComparison.OrdinalIgnoreCase);

    private static string BuildMonitorQuery(
        string path,
        string? filter,
        int? limit,
        string? cursor,
        string? jobId)
    {
        if (limit <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(limit), "Limit must be positive when specified.");
        }

        var builder = new StringBuilder(path);
        var separator = '?';
        AppendQueryParameter(builder, ref separator, "filter", filter);
        AppendQueryParameter(builder, ref separator, "limit", limit?.ToString());
        AppendQueryParameter(builder, ref separator, "cursor", cursor);
        AppendQueryParameter(builder, ref separator, "job_id", jobId);
        return builder.ToString();
    }

    private static void AppendQueryParameter(
        StringBuilder builder,
        ref char separator,
        string name,
        string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return;
        }

        builder.Append(separator)
            .Append(name)
            .Append('=')
            .Append(Uri.EscapeDataString(value));
        separator = '&';
    }

    private static void ValidateMonitorUploadOptions(MonitorUploadOptions options)
    {
        var hasPath = !string.IsNullOrWhiteSpace(options.Path);
        var hasItem = !string.IsNullOrWhiteSpace(options.ExistingItemId);
        if (hasPath == hasItem)
        {
            throw new ArgumentException(
                "Specify exactly one of Path or ExistingItemId for a Monitor upload.",
                nameof(options));
        }

        if (hasPath)
        {
            ValidateMonitorFilePath(options.Path!, nameof(options));
        }
        else
        {
            ValidateId(options.ExistingItemId!, nameof(options));
        }

        if (options.VerificationTimeout < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Verification timeout must not be negative.");
        }
        if (options.PollingInterval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Polling interval must be positive.");
        }
    }

    private static void ValidateMonitorFilePath(string path, string paramName)
    {
        if (!path.StartsWith("/", StringComparison.Ordinal) || path.EndsWith("/", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "A Monitor file path must start with '/' and include a file name.",
                paramName);
        }
    }

    private static void ValidateMonitorFolderPath(string path, string paramName)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            !path.StartsWith("/", StringComparison.Ordinal) ||
            !path.EndsWith("/", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "A Monitor folder path must start and end with '/'.",
                paramName);
        }
    }
}
