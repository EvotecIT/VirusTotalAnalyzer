using System;
using System.IO;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class SubmitFileExample
{
    public static async Task RunAsync()
    {
        var path = "sample.txt";
        if (!File.Exists(path))
        {
            Console.WriteLine($"File not found: {path}");
            return;
        }

        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
#if NET472
            using var stream = File.OpenRead(path);
#else
            await using var stream = File.OpenRead(path);
#endif
            var report = await client.SubmitFileAsync(stream, Path.GetFileName(path), AnalysisType.File);
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
