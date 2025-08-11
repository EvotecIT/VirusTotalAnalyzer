using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetFileReferrerFilesExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var files = await client.GetFileReferrerFilesAsync("44d88612fea8a8f36de82e1278abb02f");
            foreach (var file in files ?? [])
            {
                Console.WriteLine(file.Id);
            }
        }
        catch (ApiException ex)
        {
            Console.WriteLine($"API error: {ex.Error?.Message}");
        }
    }
}
