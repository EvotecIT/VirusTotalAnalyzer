using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

public static class VirusTotalClientExtensions
{
    public static Task<AnalysisReport?> ScanFileAsync(this VirusTotalClient client, string filePath, CancellationToken cancellationToken = default)
    {
        if (client == null) throw new ArgumentNullException(nameof(client));
#if NET472
        return ScanFileFrameworkAsync(client, filePath, cancellationToken);
#else
        return ScanFileInternalAsync(client, filePath, cancellationToken);
#endif
    }

#if NET472
    private static async Task<AnalysisReport?> ScanFileFrameworkAsync(VirusTotalClient client, string filePath, CancellationToken cancellationToken)
    {
        using var stream = File.OpenRead(filePath);
        return await client.SubmitFileAsync(stream, Path.GetFileName(filePath), cancellationToken).ConfigureAwait(false);
    }
#else
    private static async Task<AnalysisReport?> ScanFileInternalAsync(VirusTotalClient client, string filePath, CancellationToken cancellationToken)
    {
        await using var stream = File.OpenRead(filePath);
        return await client.SubmitFileAsync(stream, Path.GetFileName(filePath), cancellationToken).ConfigureAwait(false);
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
}
