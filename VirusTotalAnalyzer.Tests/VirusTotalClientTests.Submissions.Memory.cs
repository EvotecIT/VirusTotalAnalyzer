using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public partial class VirusTotalClientTests
{
    [Fact]
    public async Task SubmitFileAsync_NonSeekableStream_DoesNotAllocateExcessiveMemory()
    {
        var analysisJson = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new NullContentHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(analysisJson, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var data = new byte[20 * 1024 * 1024];
        using var stream = new NonSeekableStream(data);

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        var before = GC.GetTotalMemory(true);

        var report = await client.SubmitFileAsync(stream, "test.bin", CancellationToken.None);

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        var after = GC.GetTotalMemory(true);

        Assert.NotNull(report);
        Assert.True(after - before < data.Length / 2);
    }

    private sealed class NullContentHandler : HttpMessageHandler
    {
        private readonly HttpResponseMessage _response;

        public NullContentHandler(HttpResponseMessage response) => _response = response;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Content != null)
            {
#if NET472
                await request.Content.CopyToAsync(Stream.Null).ConfigureAwait(false);
#else
                await request.Content.CopyToAsync(Stream.Null, cancellationToken).ConfigureAwait(false);
#endif
            }
            return _response;
        }
    }
}

