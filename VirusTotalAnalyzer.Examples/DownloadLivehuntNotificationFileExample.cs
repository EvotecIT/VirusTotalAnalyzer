using System;
using System.IO;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class DownloadLivehuntNotificationFileExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            using var stream = await client.DownloadLivehuntNotificationFileAsync("notification-file-id");
            using var file = File.Create("notification_file.bin");
            await stream.CopyToAsync(file);
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
