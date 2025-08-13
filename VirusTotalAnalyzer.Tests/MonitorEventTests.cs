using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class MonitorEventTests
{
    [Fact]
    public async Task ListMonitorEventsAsync_GetsEvents()
    {
        var json = "{\"data\":[{\"id\":\"e1\",\"type\":\"monitor_event\",\"data\":{\"attributes\":{\"path\":\"/foo\",\"event_type\":\"created\"}}}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var response = await client.ListMonitorEventsAsync();

        Assert.NotNull(response);
        Assert.Single(response.Data);
        Assert.Equal(HttpMethod.Get, handler.Request!.Method);
        Assert.Equal("/api/v3/monitor/events", handler.Request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task ListMonitorEventsAsync_WithParameters_AppendsToUrlAndReturnsCursor()
    {
        var json = "{\"data\":[],\"meta\":{\"cursor\":\"next_cursor\"}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var response = await client.ListMonitorEventsAsync(filter: "type:foo", limit: 10, cursor: "abc");

        Assert.NotNull(response);
        Assert.Equal("next_cursor", response.NextCursor);
        Assert.Equal(HttpMethod.Get, handler.Request!.Method);
        Assert.Equal("/api/v3/monitor/events", handler.Request.RequestUri!.AbsolutePath);
        Assert.Equal("?filter=type%3Afoo&limit=10&cursor=abc", handler.Request.RequestUri.Query);
    }

    [Fact]
    public async Task GetCommentsAsync_OnMonitorEvent_UsesMonitorEventsPath()
    {
        var json = "{\"data\":[]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var comments = await client.GetCommentsAsync(ResourceType.MonitorEvent, "e1");

        Assert.NotNull(comments);
        Assert.Equal("/api/v3/monitor/events/e1/comments", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task CreateCommentAsync_OnMonitorEvent_UsesMonitorEventsPath()
    {
        var json = @"{""data"":{""id"":""c1"",""type"":""comment"",""data"":{""attributes"":{""date"":1,""text"":""hi""}}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var comment = await client.CreateCommentAsync(ResourceType.MonitorEvent, "e1", "hi");

        Assert.NotNull(comment);
        Assert.Equal("/api/v3/monitor/events/e1/comments", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Contains("\"text\":\"hi\"", handler.Content);
    }

    [Fact]
    public async Task GetVotesAsync_OnMonitorEvent_UsesMonitorEventsPath()
    {
        var json = "{\"data\":[]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var votes = await client.GetVotesAsync(ResourceType.MonitorEvent, "e1");

        Assert.NotNull(votes);
        Assert.Equal("/api/v3/monitor/events/e1/votes", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task CreateVoteAsync_OnMonitorEvent_UsesMonitorEventsPath()
    {
        var json = @"{""data"":{""id"":""v1"",""type"":""vote"",""data"":{""attributes"":{""date"":1,""verdict"":""malicious""}}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var vote = await client.CreateVoteAsync(ResourceType.MonitorEvent, "e1", VoteVerdict.Malicious);

        Assert.NotNull(vote);
        Assert.Equal("/api/v3/monitor/events/e1/votes", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Contains("\"verdict\":\"malicious\"", handler.Content);
    }
}

