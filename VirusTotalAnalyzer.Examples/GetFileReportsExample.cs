using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetFileReportsExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var reports = await client.GetFileReportsAsync(new[]
            {
                "44d88612fea8a8f36de82e1278abb02f",
                "275a021bbfb6480f86abdb2d8d0060dd"
            });
            foreach (var report in reports ?? Array.Empty<FileReport>())
            {
                Console.WriteLine(report.Id);
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
