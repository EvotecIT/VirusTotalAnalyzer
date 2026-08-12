using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class CollectionItemsExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var request = new RelationshipDescriptorsRequest
            {
                Data = { new RelationshipDescriptor { Id = "file-id", Type = ResourceType.File } }
            };
            await client.AddCollectionItemsAsync("collection-id", "files", request);
            Console.WriteLine("Item added");

            var items = await client.GetCollectionObjectsAsync("collection-id", "files", limit: 10, fetchAll: true);
            Console.WriteLine($"Retrieved {items?.Data.Count} items");

            await client.DeleteCollectionItemsAsync("collection-id", "files", request);
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
