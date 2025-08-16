using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetFeedExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var feed = await client.GetFeedAsync(ResourceType.File, limit: 10);
            Console.WriteLine(feed?.Data.Count);
            if (!string.IsNullOrEmpty(feed?.Meta?.Cursor))
            {
                var next = await client.GetFeedAsync(ResourceType.File, cursor: feed.Meta.Cursor);
                Console.WriteLine(next?.Data.Count);
            }
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
