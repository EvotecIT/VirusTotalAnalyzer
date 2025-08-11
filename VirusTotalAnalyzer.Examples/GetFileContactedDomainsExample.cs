using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetFileContactedDomainsExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var domains = await client.GetFileContactedDomainsAsync("44d88612fea8a8f36de82e1278abb02f");
            foreach (var domain in domains ?? [])
            {
                Console.WriteLine(domain.Attributes.Domain);
            }
        }
        catch (ApiException ex)
        {
            Console.WriteLine($"API error: {ex.Error?.Message}");
        }
    }
}
