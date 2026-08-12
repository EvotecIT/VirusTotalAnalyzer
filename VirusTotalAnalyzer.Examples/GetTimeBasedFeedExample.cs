using System;
using System.IO;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetTimeBasedFeedExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            using var feed = await client.DownloadFeedBatchAsync(
                FeedType.FileBehaviors,
                DateTimeOffset.UtcNow.AddHours(-2),
                FeedGranularity.Hour);
            const string outputPath = "file-behaviours-hour.tar.bz2";
            using var output = File.Create(outputPath);
            await feed.CopyToAsync(output);
            Console.WriteLine($"Saved {output.Position} bytes to {outputPath}.");
        }
        catch (RateLimitExceededException ex)
        {
            Console.WriteLine($"Rate limit exceeded. Retry after: {ex.RetryAfter}, remaining quota: {ex.RemainingQuota}");
        }
        catch (ApiException ex)
        {
            Console.WriteLine($"API error: {ex.Error?.Message}");
        }
    }
}
