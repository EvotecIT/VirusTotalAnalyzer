using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GetUserQuotaExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var privileges = await client.GetUserPrivilegesAsync("user-id");
            var quota = await client.GetUserQuotaAsync("user-id");
            Console.WriteLine($"Privileges: {privileges?.Data.Count}");
            Console.WriteLine($"Quota items: {quota?.Data.Count}");
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
