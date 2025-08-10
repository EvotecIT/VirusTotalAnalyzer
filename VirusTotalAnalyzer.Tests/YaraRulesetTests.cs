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
        var client = new VirusTotalClient(httpClient);

        var rulesets = await client.ListYaraRulesetsAsync();

        var rs = Assert.Single(rulesets!);
        Assert.Equal("rs1", rs.Id);
        Assert.Equal("demo", rs.Data.Attributes.Name);
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
        var client = new VirusTotalClient(httpClient);

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
        var client = new VirusTotalClient(httpClient);
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
        var client = new VirusTotalClient(httpClient);
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
        var client = new VirusTotalClient(httpClient);

        await client.DeleteYaraRulesetAsync("rs1");

        Assert.NotNull(handler.Request);
        Assert.Equal(HttpMethod.Delete, handler.Request!.Method);
        Assert.Equal("/api/v3/intelligence/hunting_rulesets/rs1", handler.Request.RequestUri!.AbsolutePath);
    }
}

