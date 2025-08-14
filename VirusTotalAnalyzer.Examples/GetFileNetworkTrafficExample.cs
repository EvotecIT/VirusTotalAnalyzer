using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetFileNetworkTrafficExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var traffic = await client.GetFileNetworkTrafficAsync("44d88612fea8a8f36de82e1278abb02f", sandbox: "default");
            foreach (var entry in traffic?.Data.Tcp ?? [])
            {
                Console.WriteLine($"{entry.Destination}:{entry.Port}");
            }
        }
        catch (ApiException ex)
        {
            Console.WriteLine($"API error: {ex.Error?.Message}");
        }
    }
}
