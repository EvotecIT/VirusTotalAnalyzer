using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetFileContactedIpsExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var ips = await client.GetFileContactedIpsAsync("44d88612fea8a8f36de82e1278abb02f");
            foreach (var ip in ips ?? [])
            {
                Console.WriteLine(ip.Attributes.IpAddress);
            }
        }
        catch (ApiException ex)
        {
            Console.WriteLine($"API error: {ex.Error?.Message}");
        }
    }
}
