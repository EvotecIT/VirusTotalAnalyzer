using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetUrlRelationshipsExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var downloaded = await client.GetUrlDownloadedFilesAsync("url-id");
            Console.WriteLine(downloaded?.Count);

            var referrers = await client.GetUrlReferrerFilesAsync("url-id");
            Console.WriteLine(referrers?.Count);

            var ips = await client.GetUrlContactedIpsAsync("url-id");
            Console.WriteLine(ips?.Count);
        }
        catch (ApiException ex)
        {
            Console.WriteLine($"API error: {ex.Error?.Message}");
        }
    }
}
