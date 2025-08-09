using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class CreateCollectionExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var request = new CreateCollectionRequest
            {
                Data = { Attributes = { Name = "My Collection" } }
            };
            var collection = await client.CreateCollectionAsync(request);
            Console.WriteLine(collection?.Id);
            if (collection != null)
            {
                await client.DeleteCollectionAsync(collection.Id);
                Console.WriteLine("Collection deleted");
            }
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
