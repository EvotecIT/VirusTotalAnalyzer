using System;
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
            var urls = await client.GetFileContactedUrlsAsync("44d88612fea8a8f36de82e1278abb02f");
            foreach (var url in urls ?? [])
            {
                Console.WriteLine(url.Attributes.Url);
            }
        }
        catch (ApiException ex)
        {
            Console.WriteLine($"API error: {ex.Error?.Message}");
        }
    }
}
