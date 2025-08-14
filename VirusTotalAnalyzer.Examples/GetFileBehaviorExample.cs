using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetFileBehaviorExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var behavior = await client.GetFileBehaviorAsync("44d88612fea8a8f36de82e1278abb02f", sandbox: "default");
            Console.WriteLine(behavior?.Data.Count);

            var summary = await client.GetFileBehaviorSummaryAsync("44d88612fea8a8f36de82e1278abb02f", sandbox: "default");
            Console.WriteLine(summary?.Data.Tags.Count);
        }
        catch (ApiException ex)
        {
            Console.WriteLine($"API error: {ex.Error?.Message}");
        }
    }
}
