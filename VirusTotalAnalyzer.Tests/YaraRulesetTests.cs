using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class YaraRulesetTests
{
    private const string SingleRulesetJson = "{\"id\":\"rs1\",\"type\":\"intelligence_hunting_ruleset\",\"data\":{\"attributes\":{\"name\":\"demo\",\"rules\":\"rule\",\"watchers\":[{\"id\":\"user1\",\"type\":\"user\"}]}}}";

    [Fact]
    public async Task ListYaraRulesetsAsync_DeserializesResponse()
    {
        var json = $"{{\"data\":[{SingleRulesetJson}]}}";
        var handler = new StubHandler(json);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var page = await client.ListYaraRulesetsAsync();

        var rs = Assert.Single(page.Data);
        Assert.Equal("rs1", rs.Id);
        Assert.Equal("demo", rs.Data.Attributes.Name);
    }

    [Fact]
    public async Task ListYaraRulesetsAsync_PagesThroughResults()
    {
        var first = $"{{\"data\":[{SingleRulesetJson}],\"meta\":{{\"cursor\":\"abc\"}}}}";
        var second = "{\"data\":[{\"id\":\"rs2\",\"type\":\"intelligence_hunting_ruleset\",\"data\":{\"attributes\":{\"name\":\"demo2\",\"rules\":\"rule2\"}}}]}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(first, Encoding.UTF8, "application/json")
            },
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(second, Encoding.UTF8, "application/json")
            });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var page = await client.ListYaraRulesetsAsync(limit: 1);

        Assert.Equal(2, page.Data.Count);
        Assert.Null(page.NextCursor);
        Assert.Equal("rs1", page.Data[0].Id);
        Assert.Equal("rs2", page.Data[1].Id);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Contains("limit=1", handler.Requests[0].RequestUri!.Query);
        Assert.Contains("cursor=abc", handler.Requests[1].RequestUri!.Query);
    }

    [Fact]
    public async Task ListYaraRulesetsAsync_SinglePage()
    {
        var first = $"{{\"data\":[{SingleRulesetJson}],\"meta\":{{\"cursor\":\"abc\"}}}}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(first, Encoding.UTF8, "application/json")
            });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var page = await client.ListYaraRulesetsAsync(limit: 1, fetchAll: false);

        Assert.Single(page.Data);
        Assert.Equal("rs1", page.Data[0].Id);
        Assert.Equal("abc", page.NextCursor);
        Assert.Single(handler.Requests);
        Assert.Contains("limit=1", handler.Requests[0].RequestUri!.Query);
    }

    [Fact]
    public async Task GetYaraRulesetAsync_DeserializesResponse()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(SingleRulesetJson, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var ruleset = await client.GetYaraRulesetAsync("rs1");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/intelligence/hunting_rulesets/rs1", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("demo", ruleset!.Data.Attributes.Name);
    }

    [Fact]
    public async Task CreateYaraRulesetAsync_SerializesRequestAndDeserializesResponse()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($"{{\"data\":{SingleRulesetJson}}}", Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);
        var request = new YaraRulesetRequest();
        request.Data.Attributes.Name = "demo";
        request.Data.Attributes.Rules = "rule";
        request.Data.Attributes.Watchers = new() { new YaraWatcher { Id = "user1", Type = "user" } };

        var ruleset = await client.CreateYaraRulesetAsync(request);

        Assert.NotNull(handler.Request);
        Assert.Equal(HttpMethod.Post, handler.Request!.Method);
        Assert.Equal("/api/v3/intelligence/hunting_rulesets", handler.Request.RequestUri!.AbsolutePath);
        Assert.Contains("\"name\":\"demo\"", handler.Content);
        Assert.Equal("demo", ruleset!.Data.Attributes.Name);
    }

    [Fact]
    public async Task UpdateYaraRulesetAsync_SendsPatch()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($"{{\"data\":{SingleRulesetJson}}}", Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);
        var request = new YaraRulesetRequest();
        request.Data.Attributes.Name = "demo";

        var ruleset = await client.UpdateYaraRulesetAsync("rs1", request);

        Assert.NotNull(handler.Request);
        Assert.Equal("PATCH", handler.Request!.Method.Method);
        Assert.Equal("/api/v3/intelligence/hunting_rulesets/rs1", handler.Request.RequestUri!.AbsolutePath);
        Assert.NotNull(ruleset);
    }

    [Fact]
    public async Task DeleteYaraRulesetAsync_UsesCorrectPath()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK);
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await client.DeleteYaraRulesetAsync("rs1");

        Assert.NotNull(handler.Request);
        Assert.Equal(HttpMethod.Delete, handler.Request!.Method);
        Assert.Equal("/api/v3/intelligence/hunting_rulesets/rs1", handler.Request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetYaraRulesetOwnerAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"u1\",\"type\":\"user\"}]}";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var owner = await client.GetYaraRulesetOwnerAsync("rs1");

        Assert.NotNull(owner);
        Assert.Equal("u1", owner!.Id);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/intelligence/hunting_rulesets/rs1/relationships/owner", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetYaraRulesetEditorsAsync_UsesCorrectPathAndBuildsQuery()
    {
        var json = "{\"data\":[{\"id\":\"u1\",\"type\":\"user\"},{\"id\":\"u2\",\"type\":\"user\"}]}";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var editors = await client.GetYaraRulesetEditorsAsync("rs1", limit: 10, cursor: "abc");

        Assert.NotNull(editors);
        Assert.Equal(2, editors!.Count);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/intelligence/hunting_rulesets/rs1/relationships/editors", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("limit=10&cursor=abc", handler.Request.RequestUri!.Query.TrimStart('?'));
    }

    [Fact]
    public async Task DownloadYaraRulesetAsync_UsesCorrectPathAndReturnsStream()
    {
        var trackingStream = new TrackingStream(new byte[] { 1, 2, 3 });
        var response = new TrackingResponseMessage
        {
            StatusCode = HttpStatusCode.OK,
            Content = new StreamContent(trackingStream)
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

#if NETFRAMEWORK
        using (var stream = await client.DownloadYaraRulesetAsync("rs1"))
        {
            Assert.NotNull(handler.Request);
            Assert.Equal("/api/v3/intelligence/hunting_rulesets/rs1/download", handler.Request!.RequestUri!.AbsolutePath);
            Assert.False(trackingStream.Disposed);
            Assert.False(response.Disposed);
        }
#else
        await using (var stream = await client.DownloadYaraRulesetAsync("rs1"))
        {
            Assert.NotNull(handler.Request);
            Assert.Equal("/api/v3/intelligence/hunting_rulesets/rs1/download", handler.Request!.RequestUri!.AbsolutePath);
            Assert.False(trackingStream.Disposed);
            Assert.False(response.Disposed);
        }
#endif
        Assert.True(trackingStream.Disposed);
        Assert.True(response.Disposed);
    }

    [Fact]
    public async Task DownloadYaraRulesetAsync_ThrowsApiException()
    {
        var errorJson = "{\"error\":{\"code\":\"NotFoundError\",\"message\":\"not found\"}}";
        var response = new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent(errorJson, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var ex = await Assert.ThrowsAsync<ApiException>(async () => await client.DownloadYaraRulesetAsync("rs1"));

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/intelligence/hunting_rulesets/rs1/download", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("NotFoundError", ex.Error?.Code);
        Assert.Equal("not found", ex.Message);
    }
}

