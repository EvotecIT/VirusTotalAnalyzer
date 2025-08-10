using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetFileNamesExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var names = await client.GetFileNamesAsync("44d88612fea8a8f36de82e1278abb02f");
            foreach (var name in names?.Data ?? [])
            {
                Console.WriteLine($"{name.Id} (first seen: {name.Attributes.Date:u})");
            }
        }
        catch (ApiException ex)
        {
            Console.WriteLine($"API error: {ex.Error?.Message}");
        }
    }
}
