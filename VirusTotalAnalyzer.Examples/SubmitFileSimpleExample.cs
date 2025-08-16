using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class SubmitFileSimpleExample
{
    public static async Task RunAsync()
    {
        var path = "sample.txt";
        if (!File.Exists(path))
        {
            Console.WriteLine($"File not found: {path}");
            return;
        }

        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            using var stream = File.OpenRead(path);
            var report = await client.SubmitFileAsync(stream, Path.GetFileName(path), CancellationToken.None);
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
