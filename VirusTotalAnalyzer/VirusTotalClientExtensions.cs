using System;
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
#if NET472
        return ScanFileFrameworkAsync(client, filePath, password, cancellationToken);
#else
        return ScanFileInternalAsync(client, filePath, password, cancellationToken);
#endif
    }

#if NET472
    private static async Task<AnalysisReport?> ScanFileFrameworkAsync(VirusTotalClient client, string filePath, string? password, CancellationToken cancellationToken)
    {
        using var stream = File.OpenRead(filePath);
        return await client.SubmitFileAsync(stream, Path.GetFileName(filePath), password, cancellationToken).ConfigureAwait(false);
    }
#else
    private static async Task<AnalysisReport?> ScanFileInternalAsync(VirusTotalClient client, string filePath, string? password, CancellationToken cancellationToken)
    {
        await using var stream = File.OpenRead(filePath);
        return await client.SubmitFileAsync(stream, Path.GetFileName(filePath), password, cancellationToken).ConfigureAwait(false);
    }
#endif

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
#if NET472
                await Task.Delay(delay).ConfigureAwait(false);
#else
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
#endif
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
#if NET472
                await Task.Delay(delay).ConfigureAwait(false);
#else
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
#endif
            }
        }
    }
}
