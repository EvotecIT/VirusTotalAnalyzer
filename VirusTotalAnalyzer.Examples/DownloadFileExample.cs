using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class DownloadFileExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var url = await client.GetFileDownloadUrlAsync("44d88612fea8a8f36de82e1278abb02f");
            if (url is null)
            {
                Console.WriteLine("Download URL was not provided.");
                return;
            }
            using var httpClient = new HttpClient();
            using var stream = await httpClient.GetStreamAsync(url);
            using var file = File.Create("downloaded_file.bin");
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
