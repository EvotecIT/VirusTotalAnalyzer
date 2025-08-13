using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetUrlAnalysesExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var (analyses, cursor) = await client.GetUrlAnalysesAsync("44d88612fea8a8f36de82e1278abb02f");
            foreach (var analysis in analyses)
            {
                Console.WriteLine($"{analysis.Id} - {analysis.Data.Attributes.Status}");
            }
            if (cursor != null)
            {
                Console.WriteLine($"More analyses available. Next cursor: {cursor}");
            }
        }
        catch (ApiException ex)
        {
            Console.WriteLine($"API error: {ex.Error?.Message}");
        }
    }
}
