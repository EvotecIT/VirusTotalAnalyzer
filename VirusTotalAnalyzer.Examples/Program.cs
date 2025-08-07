using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer;

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

var commentsJson = "{\"data\":[{\"id\":\"c1\",\"type\":\"comment\",\"data\":{\"attributes\":{\"date\":1,\"text\":\"example comment\"}}}]}";
using var commentsClient = new HttpClient(new StubHandler(commentsJson))
{
    BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
};
var commentClient = new VirusTotalClient(commentsClient);
var comments = await commentClient.GetCommentsAsync(ResourceType.File, "abc");
Console.WriteLine($"Comments retrieved: {comments?.Count}");

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
