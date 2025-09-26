using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class YaraRulesetWatcherTests
{
    [Fact]
    public async Task GetYaraRulesetWatchersAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"user1\",\"type\":\"user\"},{\"id\":\"user2\",\"type\":\"user\"}]}";
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

        var watchers = await client.GetYaraRulesetWatchersAsync("rs1");

        Assert.NotNull(watchers);
        Assert.Equal(2, watchers!.Count);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/intelligence/hunting_rulesets/rs1/watchers", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task AddYaraRulesetWatchersAsync_SerializesRequestAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"user1\",\"type\":\"user\"}]}";
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

        var request = new YaraWatcherRequest
        {
            Data = { new YaraWatcher { Id = "user1", Type = "user" } }
        };

        var watchers = await client.AddYaraRulesetWatchersAsync("rs1", request);

        Assert.NotNull(watchers);
        Assert.Single(watchers);
        Assert.NotNull(handler.Request);
        Assert.Equal(HttpMethod.Post, handler.Request!.Method);
        Assert.Equal("/api/v3/intelligence/hunting_rulesets/rs1/watchers", handler.Request.RequestUri!.AbsolutePath);
        Assert.Equal(json, handler.Content);
    }

    [Fact]
    public async Task AddYaraRulesetWatchersAsync_NullRequest_Throws()
    {
        var httpClient = new HttpClient(new StubHandler("{}"))
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await Assert.ThrowsAsync<ArgumentNullException>(() => client.AddYaraRulesetWatchersAsync("rs1", null!));
    }

    [Fact]
    public async Task RemoveYaraRulesetWatcherAsync_UsesCorrectPath()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK);
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await client.RemoveYaraRulesetWatcherAsync("rs1", "user1");

        Assert.NotNull(handler.Request);
        Assert.Equal(HttpMethod.Delete, handler.Request!.Method);
        Assert.Equal("/api/v3/intelligence/hunting_rulesets/rs1/watchers/user1", handler.Request.RequestUri!.AbsolutePath);
    }
}

