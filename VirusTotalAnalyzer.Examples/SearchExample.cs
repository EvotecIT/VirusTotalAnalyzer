using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class SearchExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var response = await client.SearchAsync("type:file", limit: 10);
            Console.WriteLine(response?.Data.Count);
            if (!string.IsNullOrEmpty(response?.Meta?.Cursor))
            {
                var nextPage = await client.SearchAsync("type:file", cursor: response.Meta.Cursor);
                Console.WriteLine(nextPage?.Data.Count);
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
