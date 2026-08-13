using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GraphPermissionsExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var request = new GraphPermissionRequest
            {
                Data = { new RelationshipDescriptor { Id = "username", Type = ResourceType.User } }
            };
            await client.GrantGraphPermissionAsync("graph-id", GraphPermission.Viewer, request);
            Console.WriteLine("Viewer added");

            var viewers = await client.GetGraphPermissionsAsync("graph-id", GraphPermission.Viewer, limit: 10);
            Console.WriteLine($"Retrieved {viewers?.Data.Count} viewers");

            await client.RevokeGraphPermissionAsync("graph-id", GraphPermission.Viewer, "username");
            Console.WriteLine("Viewer removed");
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
