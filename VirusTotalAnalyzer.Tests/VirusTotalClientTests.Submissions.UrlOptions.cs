using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public partial class VirusTotalClientTests
{
    [Fact]
    public async Task SubmitUrlAsync_WaitForCompletion_AddsQueryParameter()
    {
        var json = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var report = await client.SubmitUrlAsync("https://example.com", waitForCompletion: true);

        Assert.NotNull(report);
        Assert.NotNull(handler.Request);
        Assert.Equal("?wait_for_completion=true", handler.Request!.RequestUri!.Query);
    }

    [Fact]
    public async Task SubmitUrlAsync_AnalyzeFalse_AddsQueryParameter()
    {
        var json = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var report = await client.SubmitUrlAsync("https://example.com", waitForCompletion: false, analyze: false);

        Assert.NotNull(report);
        Assert.NotNull(handler.Request);
        Assert.Equal("?analyze=false", handler.Request!.RequestUri!.Query);
    }

    [Fact]
    public async Task SubmitUrlAsync_WithOptions_BuildsCombinedQuery()
    {
        var json = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);
        var options = new SubmitUrlOptions { WaitForCompletion = true, Analyze = true };

        var report = await client.SubmitUrlAsync("https://example.com", options);

        Assert.NotNull(report);
        Assert.NotNull(handler.Request);
        Assert.Equal("?wait_for_completion=true&analyze=true", handler.Request!.RequestUri!.Query);
    }
}
