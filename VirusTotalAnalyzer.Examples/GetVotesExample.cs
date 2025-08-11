using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetVotesExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var first = await client.GetVotesAsync(ResourceType.File, "file-id", limit: 10);
            Console.WriteLine(first?.Data.Count);
            if (!string.IsNullOrEmpty(first?.Meta?.Cursor))
            {
                var next = await client.GetVotesAsync(ResourceType.File, "file-id", cursor: first.Meta.Cursor);
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
