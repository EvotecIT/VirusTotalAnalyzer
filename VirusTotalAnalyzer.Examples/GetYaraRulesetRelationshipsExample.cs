using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetYaraRulesetRelationshipsExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var owner = await client.GetYaraRulesetOwnerAsync("ruleset-id");
            Console.WriteLine(owner?.Id);

            var editors = await client.GetYaraRulesetEditorsAsync("ruleset-id", limit: 10);
            Console.WriteLine(editors?.Count);
        }
        catch (ApiException ex)
        {
            Console.WriteLine($"API error: {ex.Error?.Message}");
        }
    }
}
