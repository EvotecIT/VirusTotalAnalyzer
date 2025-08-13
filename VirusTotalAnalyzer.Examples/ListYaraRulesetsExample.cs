using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class ListYaraRulesetsExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var page = await client.ListYaraRulesetsAsync(fetchAll: false);
            foreach (var rs in page.Data)
            {
                Console.WriteLine($"{rs.Id}: {rs.Data.Attributes.Name}");
            }
            Console.WriteLine($"Next cursor: {page.NextCursor}");
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

