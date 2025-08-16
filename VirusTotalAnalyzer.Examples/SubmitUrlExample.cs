using System;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class SubmitUrlExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var report = await client.SubmitUrlAsync("https://example.com", waitForCompletion: true);
            Console.WriteLine(report?.Id);

            var options = new SubmitUrlOptions { WaitForCompletion = true, Analyze = false };
            var simple = await client.SubmitUrlAsync("https://example.org", options, CancellationToken.None);
            Console.WriteLine(simple?.Id);
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
