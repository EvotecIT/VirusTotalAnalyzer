using System;
using System.IO;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class DownloadYaraRulesetExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
#if NET472
            using var stream = await client.DownloadYaraRulesetAsync("RULESET_ID");
            using var file = File.Create("ruleset.zip");
            await stream.CopyToAsync(file);
#else
            await using var stream = await client.DownloadYaraRulesetAsync("RULESET_ID");
            await using var file = File.Create("ruleset.zip");
            await stream.CopyToAsync(file);
#endif
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
