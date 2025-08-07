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
        using var stream = File.OpenRead(filePath);
        return client.SubmitFileAsync(stream, Path.GetFileName(filePath), cancellationToken);
#else
        return ScanFileInternalAsync(client, filePath, cancellationToken);
#endif
    }

#if !NET472
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
}
