using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public partial class VirusTotalClientTests
{
    [Fact]
    public async Task SubmitFileAsync_NonSeekableLargeStream_UsesUploadUrl()
    {
        var uploadUrl = "https://upload.example.com/";
        var uploadUrlJson = $"{{\"data\":\"{uploadUrl}\"}}";
        var analysisJson = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(uploadUrlJson, Encoding.UTF8, "application/json")
            },
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(analysisJson, Encoding.UTF8, "application/json")
            }
        );
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var data = new byte[33554433];
        using var stream = new NonSeekableStream(data);

        var report = await client.SubmitFileAsync(stream, "large.bin", CancellationToken.None);

        Assert.NotNull(report);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal("/api/v3/files/upload_url", handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal(uploadUrl, handler.Requests[1].RequestUri!.ToString());
    }
}
