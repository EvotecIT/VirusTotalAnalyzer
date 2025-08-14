using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class CreateMonitorItemExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var request = new CreateMonitorItemRequest
            {
                Data = { Attributes = { Path = "/path/to/file" } }
            };
            var item = await client.CreateMonitorItemAsync(request);
            Console.WriteLine(item?.Id);

            var items = await client.ListMonitorItemsAsync(fetchAll: true);
            if (items != null)
            {
                foreach (var i in items.Data)
                {
                    Console.WriteLine(i.Id);
                }
            }

            if (item != null)
            {
                await client.DeleteMonitorItemAsync(item.Id);
                Console.WriteLine("Monitor item deleted");
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
