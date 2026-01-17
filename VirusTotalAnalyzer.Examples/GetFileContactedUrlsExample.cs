using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetFileContactedUrlsExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var page = await client.GetFileContactedUrlsAsync("44d88612fea8a8f36de82e1278abb02f", fetchAll: true);
            foreach (var url in page?.Data ?? new List<UrlSummary>())
            {
                var resolvedUrl = url.Data?.Attributes?.Url;
                if (!string.IsNullOrEmpty(resolvedUrl))
                {
                    Console.WriteLine(resolvedUrl);
                }
            }
            var cursor = page?.NextCursor;
            if (!string.IsNullOrEmpty(cursor))
            {
                Console.WriteLine($"More URLs available. Next cursor: {cursor}");
            }
        }
        catch (ApiException ex)
        {
            Console.WriteLine($"API error: {ex.Error?.Message}");
        }
    }
}
