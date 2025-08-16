using System.Threading.Tasks;

namespace VirusTotalAnalyzer.Examples;

public static class CreateCommentWithBuilderExample
{
    public static async Task RunAsync()
    {
        IVirusTotalClient client = VirusTotalClient.Create("YOUR-API-KEY");

        var request = new CommentRequestBuilder()
            .WithText("Nice file")
            .Build();

        var comment = await client.CreateCommentAsync(ResourceType.File, "file-id", request);
        _ = comment;
    }
}

