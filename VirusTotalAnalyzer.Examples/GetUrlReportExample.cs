using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetUrlReportExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var report = await client.GetUrlReportAsync(
                "url-id",
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
