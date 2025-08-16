using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class StartRetrohuntJobExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var request = new RetrohuntJobRequest();
            request.Data.Attributes.Rules = "rule demo";
            var job = await client.CreateRetrohuntJobAsync(request);
            if (job == null)
            {
                return;
            }
            RetrohuntJob? current;
            do
            {
                await Task.Delay(TimeSpan.FromSeconds(30));
                current = await client.GetRetrohuntJobAsync(job.Id);
            }
            while (current != null && current.Data.Attributes.Status != "done");

            var page = await client.ListRetrohuntNotificationsAsync(fetchAll: false);
            foreach (var n in page.Data)
            {
                Console.WriteLine($"Notification {n.Id} from job {n.Data.Attributes.JobId}");
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
