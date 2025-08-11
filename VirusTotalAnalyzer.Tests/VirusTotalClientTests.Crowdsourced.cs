using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public partial class VirusTotalClientTests
{
    [Fact]
    public async Task GetCrowdsourcedYaraResultsAsync_DeserializesResponse()
    {
        var json = "{\"data\":[{\"rule_name\":\"r1\",\"ruleset_id\":\"rs1\"}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var results = await client.GetCrowdsourcedYaraResultsAsync("abc");

        Assert.NotNull(results);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/crowdsourced_yara_results", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("r1", results![0].RuleName);
        Assert.Equal("rs1", results[0].RulesetId);
    }

    [Fact]
    public async Task GetCrowdsourcedYaraResultsAsync_ThrowsApiException()
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
        var client = new VirusTotalClient(httpClient);

        var ex = await Assert.ThrowsAsync<ApiException>(() => client.GetCrowdsourcedYaraResultsAsync("abc"));
        Assert.Equal("NotFoundError", ex.Error?.Code);
        Assert.Equal("not found", ex.Message);
    }

    [Fact]
    public async Task GetCrowdsourcedIdsResultsAsync_DeserializesResponse()
    {
        var json = "{\"data\":[{\"rule_name\":\"r1\",\"rule_id\":\"1\",\"alert_severity\":2}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var results = await client.GetCrowdsourcedIdsResultsAsync("abc");

        Assert.NotNull(results);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/crowdsourced_ids_results", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("r1", results![0].RuleName);
        Assert.Equal("1", results[0].RuleId);
        Assert.Equal(2, results[0].AlertSeverity);
    }

    [Fact]
    public async Task GetCrowdsourcedIdsResultsAsync_ThrowsApiException()
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
        var client = new VirusTotalClient(httpClient);

        var ex = await Assert.ThrowsAsync<ApiException>(() => client.GetCrowdsourcedIdsResultsAsync("abc"));
        Assert.Equal("NotFoundError", ex.Error?.Code);
        Assert.Equal("not found", ex.Message);
    }
}
