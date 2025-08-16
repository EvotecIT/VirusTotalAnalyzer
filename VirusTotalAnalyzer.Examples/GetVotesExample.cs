using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetVotesExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var first = await client.GetVotesAsync(ResourceType.File, "file-id", limit: 10);
            Console.WriteLine(first?.Data.Count);
            var cursor = first?.Meta?.Cursor;
            if (!string.IsNullOrEmpty(cursor))
            {
                var next = await client.GetVotesAsync(ResourceType.File, "file-id", cursor: cursor);
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
