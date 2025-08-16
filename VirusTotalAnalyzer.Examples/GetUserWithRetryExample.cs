using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetUserWithRetryExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            // Retries up to 5 times, waiting the server-provided delay when available or 4 seconds otherwise
            var user = await client.ExecuteWithRateLimitRetryAsync(
                c => c.GetUserAsync("user-id"),
                maxRetries: 5,
                defaultRetryDelay: TimeSpan.FromSeconds(4));
            Console.WriteLine(user?.Id);
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
