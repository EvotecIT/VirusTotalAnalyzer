using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using VirusTotalAnalyzer.Models;

Console.WriteLine("VirusTotalAnalyzer example running.");

var sampleJson = "{\"id\":\"abc\",\"type\":\"file\",\"data\":{\"attributes\":{\"md5\":\"demo-md5\",\"sha256\":\"demo-sha\"}}}";

using var httpClient = new HttpClient(new StubHandler(sampleJson))
{
    BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
};
var client = new VirusTotalClient(httpClient);

var report = await client.GetFileReportAsync("abc");
Console.WriteLine($"Sample file md5: {report?.Data.Attributes.Md5}");

var analysisJson = "{\"id\":\"analysis\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
using var submitHttpClient = new HttpClient(new StubHandler(analysisJson))
{
    BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
};
var submitClient = new VirusTotalClient(submitHttpClient);
var analysis = await submitClient.SubmitUrlAsync("https://example.com", AnalysisType.Url);
Console.WriteLine($"Submission status: {analysis?.Data.Attributes.Status}");

var completedAnalysisJson = "{\"id\":\"analysis\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"completed\"}}}";
using var waitClientHttp = new HttpClient(new QueueHandler(
    new HttpResponseMessage(HttpStatusCode.OK)
    {
        Content = new StringContent(analysisJson, Encoding.UTF8, "application/json")
    },
    new HttpResponseMessage(HttpStatusCode.OK)
    {
        Content = new StringContent(completedAnalysisJson, Encoding.UTF8, "application/json")
    }))
{
    BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
};
var waitClient = new VirusTotalClient(waitClientHttp);
var completedAnalysis = await waitClient.WaitForAnalysisCompletionAsync("analysis", TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(1));
Console.WriteLine($"Wait completed status: {completedAnalysis?.Data.Attributes.Status}");

var commentsJson = "{\"data\":[{\"id\":\"c1\",\"type\":\"comment\",\"data\":{\"attributes\":{\"date\":1,\"text\":\"example comment\"}}}]}";
using var commentsClient = new HttpClient(new StubHandler(commentsJson))
{
    BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
};
var commentClient = new VirusTotalClient(commentsClient);
var comments = await commentClient.GetCommentsAsync(ResourceType.File, "abc");
Console.WriteLine($"Comments retrieved: {comments?.Count}");

var createCommentJson = @"{""data"":{""id"":""c2"",""type"":""comment"",""data"":{""attributes"":{""date"":2,""text"":""hello""}}}}";
using var createCommentClient = new HttpClient(new StubHandler(createCommentJson))
{
    BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
};
var addCommentClient = new VirusTotalClient(createCommentClient);
var createdComment = await addCommentClient.AddCommentAsync(ResourceType.File, "abc", "hello");
Console.WriteLine($"Created comment id: {createdComment?.Id}");

var voteJson = @"{""data"":{""id"":""v1"",""type"":""vote"",""data"":{""attributes"":{""date"":1,""verdict"":""harmless""}}}}";
using var voteClientHttp = new HttpClient(new StubHandler(voteJson))
{
    BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
};
var voteClientExample = new VirusTotalClient(voteClientHttp);
var vote = await voteClientExample.VoteAsync(ResourceType.File, "abc", VoteValue.Harmless);
Console.WriteLine($"Vote verdict: {vote?.Data.Attributes.Verdict}");

var deleteHandler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.NoContent));
using var deleteHttp = new HttpClient(deleteHandler)
{
    BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
};
var deleteClient = new VirusTotalClient(deleteHttp);
await deleteClient.DeleteAsync(ResourceType.File, "abc");
Console.WriteLine("Deleted item");

var userJson = @"{""id"":""user1"",""type"":""user"",""data"":{""attributes"":{""username"":""jdoe"",""role"":""admin""}}}";
using var userHttp = new HttpClient(new StubHandler(userJson))
{
    BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
};
var userClientExample = new VirusTotalClient(userHttp);
var user = await userClientExample.GetUserAsync("user1");
Console.WriteLine($"Retrieved user: {user?.Data.Attributes.Username}");

var tmp = Path.GetTempFileName();
await File.WriteAllTextAsync(tmp, "demo");
using var scanHttpClient = new HttpClient(new StubHandler(analysisJson))
{
    BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
};
var scanClient = new VirusTotalClient(scanHttpClient);
var scanReport = await scanClient.ScanFileAsync(tmp);
Console.WriteLine($"Scan status via helper: {scanReport?.Data.Attributes.Status}");
File.Delete(tmp);

using var exampleStream = new MemoryStream(Encoding.UTF8.GetBytes("example"));
var builder = new MultipartFormDataBuilder(exampleStream, "example.txt");
using var httpContent = builder.Build();
Console.WriteLine($"Multipart boundary example: {builder.Boundary}");

var rateLimitJson = "{\"error\":{\"code\":\"RateLimitExceeded\",\"message\":\"too many\"}}";
var rateLimitResponse = new HttpResponseMessage(HttpStatusCode.TooManyRequests)
{
    Content = new StringContent(rateLimitJson, Encoding.UTF8, "application/json")
};
rateLimitResponse.Headers.Add("Retry-After", "5");
rateLimitResponse.Headers.Add("X-RateLimit-Remaining", "0");
using var rateLimitHttp = new HttpClient(new SingleResponseHandler(rateLimitResponse))
{
    BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
};
var rateClient = new VirusTotalClient(rateLimitHttp);
try
{
    await rateClient.GetFileReportAsync("abc");
}
catch (RateLimitExceededException ex)
{
    Console.WriteLine($"Rate limit retry after: {ex.RetryAfter?.TotalSeconds}s");
}

class StubHandler : HttpMessageHandler
{
    private readonly string _response;
    public StubHandler(string response) => _response = response;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(_response, Encoding.UTF8, "application/json")
        });
}

class SingleResponseHandler : HttpMessageHandler
{
    private readonly HttpResponseMessage _response;
    public SingleResponseHandler(HttpResponseMessage response) => _response = response;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        => Task.FromResult(_response);
}

class QueueHandler : HttpMessageHandler
{
    private readonly System.Collections.Generic.Queue<HttpResponseMessage> _responses;
    public QueueHandler(params HttpResponseMessage[] responses)
        => _responses = new System.Collections.Generic.Queue<HttpResponseMessage>(responses);

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        => Task.FromResult(_responses.Dequeue());
}
