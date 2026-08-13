using System;
using System.Collections.Generic;
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
    public async Task ListMonitorEventsAsync_DeserializesPlainEventDictionaries()
    {
        const string json = """
            {
              "data": [{
                "action": "DETECTED",
                "creator_id": "publisher",
                "details": [{ "v": "engine" }],
                "level": "1",
                "monitor_key": "key",
                "owner_id": "owner",
                "plaintext_description": "Detected by engine",
                "source": "ANALYSIS",
                "subject": "sample.exe",
                "timestamp": "2024-07-01T12:34:56Z"
              }],
              "meta": { "cursor": "next", "job_id": "job-1" }
            }
            """;
        var handler = new SingleResponseHandler(JsonResponse(json));
        using var httpClient = CreateHttpClient(handler);
        using var client = new VirusTotalClient(httpClient);

        var response = await client.ListMonitorEventsAsync("action:DETECTED", "start", "job-0");

        var monitorEvent = Assert.Single(response!.Data);
        Assert.Equal(MonitorEventAction.Detected, monitorEvent.Action);
        Assert.Equal(MonitorEventSource.Analysis, monitorEvent.Source);
        Assert.Equal(1, monitorEvent.Level);
        Assert.Equal("engine", Assert.Single(monitorEvent.Details).V);
        Assert.Equal(DateTimeOffset.Parse("2024-07-01T12:34:56Z"), monitorEvent.Timestamp);
        Assert.Equal("?filter=action%3ADETECTED&cursor=start&job_id=job-0", handler.Request!.RequestUri!.Query);
    }

    [Fact]
    public async Task EnumerateMonitorEventsAsync_PropagatesCursorAndJobId()
    {
        var handler = new QueueHandler(
            JsonResponse("{\"data\":[{\"action\":\"UPLOAD\",\"source\":\"FILE\"}],\"meta\":{\"cursor\":\"next\",\"job_id\":\"job-1\"}}"),
            JsonResponse("{\"data\":[{\"action\":\"CLEAN\",\"source\":\"ANALYSIS\"}]}"));
        using var httpClient = CreateHttpClient(handler);
        using var client = new VirusTotalClient(httpClient);
        var actions = new List<MonitorEventAction>();

        await foreach (var monitorEvent in client.EnumerateMonitorEventsAsync())
        {
            actions.Add(monitorEvent.Action);
        }

        Assert.Equal(new[] { MonitorEventAction.Upload, MonitorEventAction.Clean }, actions);
        Assert.Equal(string.Empty, handler.Requests[0].RequestUri!.Query);
        Assert.Equal("?cursor=next&job_id=job-1", handler.Requests[1].RequestUri!.Query);
    }

    private static HttpClient CreateHttpClient(HttpMessageHandler handler) => new(handler)
    {
        BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
    };

    private static HttpResponseMessage JsonResponse(string json) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json")
    };
}
