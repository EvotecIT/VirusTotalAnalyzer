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
    public async Task GetUrlGraphsAsync_GetsGraphs()
    {
        var relationshipsJson = "{\"data\":[{\"id\":\"g1\",\"type\":\"graph\"},{\"id\":\"g2\",\"type\":\"graph\"}]}";
        var graph1Json = "{\"id\":\"g1\",\"type\":\"graph\",\"data\":{\"attributes\":{\"name\":\"one\"}}}";
        var graph2Json = "{\"id\":\"g2\",\"type\":\"graph\",\"data\":{\"attributes\":{\"name\":\"two\"}}}";

        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(relationshipsJson, Encoding.UTF8, "application/json")
            },
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(graph1Json, Encoding.UTF8, "application/json")
            },
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(graph2Json, Encoding.UTF8, "application/json")
            }
        );

        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var graphs = await client.GetUrlGraphsAsync("url-id");

        Assert.NotNull(graphs);
        Assert.Equal(2, graphs.Count);
        Assert.Equal("g1", graphs[0].Id);
        Assert.Equal("g2", graphs[1].Id);
        Assert.Equal("/api/v3/urls/url-id/relationships/graphs", handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal("/api/v3/graphs/g1", handler.Requests[1].RequestUri!.AbsolutePath);
        Assert.Equal("/api/v3/graphs/g2", handler.Requests[2].RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetUrlGraphsAsync_BuildsQueryWithLimitAndCursor()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"data\":[]}", Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var graphs = await client.GetUrlGraphsAsync("url-id", limit: 10, cursor: "abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("?limit=10&cursor=abc", handler.Request!.RequestUri!.Query);
        Assert.NotNull(graphs);
        Assert.Empty(graphs);
    }
}

