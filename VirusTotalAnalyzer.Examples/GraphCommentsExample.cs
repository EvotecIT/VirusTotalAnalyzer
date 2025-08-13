using System;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer.Examples;

public static class GraphCommentsExample
{
    public static async Task RunAsync()
    {
        var client = VirusTotalClient.Create("YOUR_API_KEY");
        try
        {
            var comment = await client.AddGraphCommentAsync("graph-id", "Nice graph");
            Console.WriteLine(comment?.Id);

            var comments = await client.GetGraphCommentsAsync("graph-id", limit: 10);
            Console.WriteLine($"Retrieved {comments?.Data.Count} comments");

            if (comment != null)
            {
                await client.DeleteGraphCommentAsync("graph-id", comment.Id);
                Console.WriteLine("Comment deleted");
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
