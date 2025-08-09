using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class CreateGraphExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var request = new CreateGraphRequest
            {
                Data = { Attributes = { Name = "My Graph" } }
            };
            var graph = await client.CreateGraphAsync(request);
            Console.WriteLine(graph?.Id);
            if (graph != null)
            {
                await client.DeleteGraphAsync(graph.Id);
                Console.WriteLine("Graph deleted");
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
