using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GraphCollaboratorsExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var request = new AddCollaboratorsRequest
            {
                Data = { new Relationship { Id = "username", Type = ResourceType.User } }
            };
            await client.AddGraphCollaboratorsAsync("graph-id", request);
            Console.WriteLine("Collaborator added");

            var collaborators = await client.GetGraphCollaboratorsAsync("graph-id", limit: 10);
            Console.WriteLine($"Retrieved {collaborators?.Data.Count} collaborators");

            await client.DeleteGraphCollaboratorAsync("graph-id", "username");
            Console.WriteLine("Collaborator removed");
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

