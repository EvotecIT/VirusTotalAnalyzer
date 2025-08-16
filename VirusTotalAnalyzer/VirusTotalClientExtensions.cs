using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

public static class VirusTotalClientExtensions
{
    public static bool TryGetUrlId(string url, out string? id)
    {
        if (url == null) throw new ArgumentNullException(nameof(url));

        id = null;
        try
        {
            var uri = new Uri(url, UriKind.Absolute);
            var builder = new UriBuilder(uri)
            {
                Fragment = string.Empty
            };

            if ((builder.Scheme == Uri.UriSchemeHttp && builder.Port == 80) ||
                (builder.Scheme == Uri.UriSchemeHttps && builder.Port == 443))
            {
                builder.Port = -1;
            }

            if (string.IsNullOrEmpty(builder.Path))
            {
                builder.Path = "/";
            }

            var canonical = builder.Uri.GetComponents(UriComponents.AbsoluteUri, UriFormat.SafeUnescaped);
            var bytes = Encoding.UTF8.GetBytes(canonical);
            id = Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            return true;
        }
        catch (UriFormatException)
        {
            return false;
        }
    }

    public static string GetUrlId(string url)
    {
        return TryGetUrlId(url, out var id) ? id! : throw new UriFormatException("Invalid URL");
    }

    public static Task<AnalysisReport?> ScanFileAsync(this VirusTotalClient client, string filePath, string? password = null, CancellationToken cancellationToken = default)
    {
        if (client == null) throw new ArgumentNullException(nameof(client));
        return ScanFileInternalAsync(client, filePath, password, cancellationToken);
    }

    public static Task<IReadOnlyList<AnalysisReport?>> ScanFilesAsync(
        this VirusTotalClient client,
        IEnumerable<string> paths,
        int maxConcurrency,
        string? password = null,
        CancellationToken cancellationToken = default)
    {
        if (client == null) throw new ArgumentNullException(nameof(client));
        if (paths == null) throw new ArgumentNullException(nameof(paths));
        if (maxConcurrency <= 0) throw new ArgumentOutOfRangeException(nameof(maxConcurrency));
        return ScanFilesInternalAsync(client, paths, maxConcurrency, password, cancellationToken);
    }

    private static async Task<AnalysisReport?> ScanFileInternalAsync(VirusTotalClient client, string filePath, string? password, CancellationToken cancellationToken)
    {
        using var stream = File.OpenRead(filePath);
        return await client.SubmitFileAsync(stream, Path.GetFileName(filePath), password, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<IReadOnlyList<AnalysisReport?>> ScanFilesInternalAsync(
        VirusTotalClient client,
        IEnumerable<string> paths,
        int maxConcurrency,
        string? password,
        CancellationToken cancellationToken)
    {
        using var semaphore = new SemaphoreSlim(maxConcurrency);
        var tasks = new List<Task<AnalysisReport?>>();
        foreach (var path in paths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            tasks.Add(UploadAsync(path));
        }

        var results = await Task.WhenAll(tasks).ConfigureAwait(false);
        return results;

        async Task<AnalysisReport?> UploadAsync(string filePath)
        {
            await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                using var stream = File.OpenRead(filePath);
                return await client.SubmitFileAsync(stream, Path.GetFileName(filePath), password, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                semaphore.Release();
            }
        }
    }

    public static Task<AnalysisReport?> ScanUrlAsync(this VirusTotalClient client, string url, CancellationToken cancellationToken = default)
    {
        if (client == null) throw new ArgumentNullException(nameof(client));
        return client.SubmitUrlAsync(url, cancellationToken);
    }

    public static Task<Comment?> AddCommentAsync(this VirusTotalClient client, ResourceType resourceType, string id, string text, CancellationToken cancellationToken = default)
    {
        if (client == null) throw new ArgumentNullException(nameof(client));
        return client.CreateCommentAsync(resourceType, id, text, cancellationToken);
    }

    public static Task<Comment?> AddCommentAsync(this VirusTotalClient client, ResourceType resourceType, string id, CreateCommentRequest request, CancellationToken cancellationToken = default)
    {
        if (client == null) throw new ArgumentNullException(nameof(client));
        return client.CreateCommentAsync(resourceType, id, request, cancellationToken);
    }

    public static Task<Vote?> VoteAsync(this VirusTotalClient client, ResourceType resourceType, string id, VoteVerdict verdict, CancellationToken cancellationToken = default)
    {
        if (client == null) throw new ArgumentNullException(nameof(client));
        return client.CreateVoteAsync(resourceType, id, verdict, cancellationToken);
    }

    public static Task<Vote?> VoteAsync(this VirusTotalClient client, ResourceType resourceType, string id, CreateVoteRequest request, CancellationToken cancellationToken = default)
    {
        if (client == null) throw new ArgumentNullException(nameof(client));
        return client.CreateVoteAsync(resourceType, id, request, cancellationToken);
    }

    public static Task DeleteAsync(this VirusTotalClient client, ResourceType resourceType, string id, CancellationToken cancellationToken = default)
    {
        if (client == null) throw new ArgumentNullException(nameof(client));
        return client.DeleteItemAsync(resourceType, id, cancellationToken);
    }

    /// <summary>
    /// Executes an operation and automatically retries when a <see cref="RateLimitExceededException"/> is thrown.
    /// Retries up to <paramref name="maxRetries"/> times, waiting for the server-supplied delay when available,
    /// otherwise using <paramref name="defaultRetryDelay"/> (one second if not specified).
    /// </summary>
    public static async Task<T?> ExecuteWithRateLimitRetryAsync<T>(this VirusTotalClient client, Func<VirusTotalClient, Task<T?>> operation, int maxRetries = 3, TimeSpan? defaultRetryDelay = null, CancellationToken cancellationToken = default)
    {
        if (client == null) throw new ArgumentNullException(nameof(client));
        if (operation == null) throw new ArgumentNullException(nameof(operation));
        var attempts = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return await operation(client).ConfigureAwait(false);
            }
            catch (RateLimitExceededException ex) when (attempts < maxRetries)
            {
                attempts++;
                var delay = ex.RetryAfter ?? defaultRetryDelay ?? TimeSpan.FromSeconds(1);
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Executes an operation and automatically retries when a <see cref="RateLimitExceededException"/> is thrown.
    /// Retries up to <paramref name="maxRetries"/> times, waiting for the server-supplied delay when available,
    /// otherwise using <paramref name="defaultRetryDelay"/> (one second if not specified).
    /// </summary>
    public static async Task ExecuteWithRateLimitRetryAsync(this VirusTotalClient client, Func<VirusTotalClient, Task> operation, int maxRetries = 3, TimeSpan? defaultRetryDelay = null, CancellationToken cancellationToken = default)
    {
        if (client == null) throw new ArgumentNullException(nameof(client));
        if (operation == null) throw new ArgumentNullException(nameof(operation));
        var attempts = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                await operation(client).ConfigureAwait(false);
                return;
            }
            catch (RateLimitExceededException ex) when (attempts < maxRetries)
            {
                attempts++;
                var delay = ex.RetryAfter ?? defaultRetryDelay ?? TimeSpan.FromSeconds(1);
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}
