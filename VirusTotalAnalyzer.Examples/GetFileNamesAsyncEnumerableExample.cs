using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetFileNamesAsyncEnumerableExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            await foreach (var name in client.GetFileNamesAsyncEnumerable("44d88612fea8a8f36de82e1278abb02f"))
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
