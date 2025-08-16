using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public partial class VirusTotalClientTests
{
    [Fact]
    public async Task GetFileReportAsync_SendsDefaultUserAgent()
    {
        var json = "{\"data\":{}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await client.GetFileReportAsync("abc");

        Assert.NotNull(handler.Request);
        var expected = $"{typeof(VirusTotalClient).Assembly.GetName().Name}/{typeof(VirusTotalClient).Assembly.GetName().Version}";
        Assert.Equal(expected, handler.Request!.Headers.UserAgent.ToString());
    }

    [Fact]
    public async Task GetFileReportAsync_SendsCustomUserAgent()
    {
        var json = "{\"data\":{}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient, userAgent: "MyApp/1.0");

        await client.GetFileReportAsync("abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("MyApp/1.0", handler.Request!.Headers.UserAgent.ToString());
    }
}

