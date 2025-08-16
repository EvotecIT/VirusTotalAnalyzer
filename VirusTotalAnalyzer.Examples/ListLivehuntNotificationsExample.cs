using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class ListLivehuntNotificationsExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var page = await client.ListLivehuntNotificationsAsync(fetchAll: false);
            foreach (var notification in page.Data)
            {
                Console.WriteLine(notification.Id);
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
