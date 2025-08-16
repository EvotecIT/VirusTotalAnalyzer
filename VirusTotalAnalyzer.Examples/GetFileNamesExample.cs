using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetFileNamesExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var (names, cursor) = await client.GetFileNamesAsync("44d88612fea8a8f36de82e1278abb02f");
            foreach (var name in names)
            {
                Console.WriteLine($"{name.Id} (first seen: {name.Attributes.Date:u})");
            }
            if (cursor != null)
            {
                Console.WriteLine($"More names available. Next cursor: {cursor}");
            }
        }
        catch (ApiException ex)
        {
            Console.WriteLine($"API error: {ex.Error?.Message}");
        }
    }
}
