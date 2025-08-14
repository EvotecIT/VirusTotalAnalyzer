using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetFileContactedUrlsExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var page = await client.GetFileContactedUrlsAsync("44d88612fea8a8f36de82e1278abb02f", fetchAll: true);
            foreach (var url in page?.Data ?? new List<UrlSummary>())
            {
                Console.WriteLine(url.Data.Attributes.Url);
            }
            if (!string.IsNullOrEmpty(page?.NextCursor))
            {
                Console.WriteLine($"More URLs available. Next cursor: {page.NextCursor}");
            }
        }
        catch (ApiException ex)
        {
            Console.WriteLine($"API error: {ex.Error?.Message}");
        }
    }
}
