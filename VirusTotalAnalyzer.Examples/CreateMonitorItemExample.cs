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

            var items = await client.ListMonitorItemsAsync();
            foreach (var i in items)
            {
                Console.WriteLine(i.Id);
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
