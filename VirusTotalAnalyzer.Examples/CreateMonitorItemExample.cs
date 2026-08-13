using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class CreateMonitorItemExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var options = new MonitorUploadOptions
            {
                Path = "/releases/1.0.0/app.exe",
                Details = "Signed release binary"
            };
            var upload = await client.UploadMonitorFileAsync("app.exe", options);
            Console.WriteLine($"{upload.Item.Id}: {upload.VerificationStatus}");

            var items = await client.ListMonitorItemsAsync("path:/releases/1.0.0/");
            if (items != null)
            {
                foreach (var i in items.Data)
                {
                    Console.WriteLine(i.Id);
                }
            }

            if (!string.IsNullOrEmpty(upload.Item.Id))
            {
                await client.DeleteMonitorItemAsync(upload.Item.Id);
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
