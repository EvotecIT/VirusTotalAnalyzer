using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class ScanFilesExample
{
    public static async Task RunAsync()
    {
        var paths = new List<string> { "sample1.txt", "sample2.txt" };
        foreach (var p in paths)
        {
            if (!File.Exists(p))
            {
                Console.WriteLine($"File not found: {p}");
                return;
            }
        }

        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var reports = await client.ScanFilesAsync(paths, maxConcurrency: 2);
            foreach (var report in reports)
            {
                Console.WriteLine(report?.Id);
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
