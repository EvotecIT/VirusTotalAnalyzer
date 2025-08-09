using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class CreateBundleExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var request = new CreateBundleRequest
            {
                Data =
                {
                    Attributes =
                    {
                        Name = "My Bundle",
                        Description = "Demo",
                        Files = { new Relationship { Id = "file-id", Type = ResourceType.File } }
                    }
                }
            };
            var bundle = await client.CreateBundleAsync(request);
            Console.WriteLine(bundle?.Id);
            if (bundle != null)
            {
                await client.DeleteBundleAsync(bundle.Id);
                Console.WriteLine("Bundle deleted");
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
