using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetCrowdsourcedResultsExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var yaraResults = await client.GetCrowdsourcedYaraResultsAsync("44d88612fea8a8f36de82e1278abb02f");
            Console.WriteLine(yaraResults?.Count);

            var idsResults = await client.GetCrowdsourcedIdsResultsAsync("44d88612fea8a8f36de82e1278abb02f");
            Console.WriteLine(idsResults?.Count);
        }
        catch (ApiException ex)
        {
            Console.WriteLine($"API error: {ex.Error?.Message}");
        }
    }
}
