using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetIpAddressReportExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var report = await client.GetIpAddressReportAsync("8.8.8.8");
            Console.WriteLine(report?.Id);
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
