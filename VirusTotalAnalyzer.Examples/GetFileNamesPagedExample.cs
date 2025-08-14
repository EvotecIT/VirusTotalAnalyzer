using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetFileNamesPagedExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var page = await client.GetFileNamesPagedAsync("44d88612fea8a8f36de82e1278abb02f", fetchAll: true);
            foreach (var name in page!.Data)
            {
                Console.WriteLine($"{name.Id} (first seen: {name.Attributes.Date:u})");
            }
            Console.WriteLine($"Next cursor: {page.NextCursor}");
        }
        catch (ApiException ex)
        {
            Console.WriteLine($"API error: {ex.Error?.Message}");
        }
    }
}
