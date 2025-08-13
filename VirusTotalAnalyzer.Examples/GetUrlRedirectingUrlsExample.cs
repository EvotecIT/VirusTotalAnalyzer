using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetUrlRedirectingUrlsExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var urls = await client.GetUrlRedirectingUrlsAsync("url-id");
            foreach (var url in urls ?? Array.Empty<UrlSummary>())
            {
                Console.WriteLine(url.Data.Attributes.Url);
            }
        }
        catch (ApiException ex)
        {
            Console.WriteLine($"API error: {ex.Error?.Message}");
        }
    }
}
