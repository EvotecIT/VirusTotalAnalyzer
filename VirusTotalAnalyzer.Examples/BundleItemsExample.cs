using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class BundleItemsExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var request = new AddItemsRequest
            {
                Data = { new Relationship { Id = "file-id", Type = ResourceType.File } }
            };
            var added = await client.AddBundleItemsAsync("bundle-id", request);
            Console.WriteLine($"Added {added?.Data.Count ?? 0} items");

            var items = await client.ListBundleItemsAsync("bundle-id", limit: 10, fetchAll: true);
            Console.WriteLine($"Retrieved {items?.Data.Count} items");

            await client.DeleteBundleItemAsync("bundle-id", "file-id");
            Console.WriteLine("Item deleted");
        }
        catch (RateLimitExceededException ex)
        {
            Console.WriteLine($"Rate limit exceeded. Retry after: {ex.RetryAfter}, remaining quota: {ex.RemainingQuota}");
        }
        catch (ApiException ex)
        {
            Console.WriteLine($"API error: {ex.Error?.Message}");
        }
    }
}

