using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetUrlReportFromUrlExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var report = await client.GetUrlReportAsync(
                new Uri("https://example.com"),
                fields: new[] { "last_analysis_date" },
                relationships: new[] { "last_serving_ip_address" });
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
