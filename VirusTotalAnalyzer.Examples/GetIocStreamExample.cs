using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetIocStreamExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var stream = await client.GetIocStreamAsync("type:file", limit: 10, descriptorsOnly: true);
            Console.WriteLine(stream?.Data.Count);
            if (!string.IsNullOrEmpty(stream?.Meta?.Cursor))
            {
                var next = await client.GetIocStreamAsync("type:file", cursor: stream.Meta.Cursor);
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
