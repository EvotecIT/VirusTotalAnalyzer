using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class MonitorItemTests
{
    [Fact]
    public async Task ListMonitorItemsAsync_GetsItems()
    {
        var json = "{\"data\":[{\"id\":\"m1\",\"type\":\"monitorItem\",\"data\":{\"attributes\":{\"path\":\"/foo\"}}}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var items = await client.ListMonitorItemsAsync();

        Assert.NotNull(items);
        Assert.Equal(HttpMethod.Get, handler.Request!.Method);
        Assert.Equal("/api/v3/monitor/items", handler.Request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task CreateMonitorItemAsync_PostsItem()
    {
        var json = "{\"id\":\"m1\",\"type\":\"monitorItem\",\"data\":{\"attributes\":{\"path\":\"/foo\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var request = new CreateMonitorItemRequest { Data = { Attributes = { Path = "/foo" } } };
        var item = await client.CreateMonitorItemAsync(request);

        Assert.NotNull(item);
        Assert.Equal(HttpMethod.Post, handler.Request!.Method);
        Assert.Equal("/api/v3/monitor/items", handler.Request.RequestUri!.AbsolutePath);
        Assert.Contains("\"path\":\"/foo\"", handler.Content);
    }

    [Fact]
    public async Task UpdateMonitorItemAsync_PatchesItem()
    {
        var json = "{\"id\":\"m1\",\"type\":\"monitorItem\",\"data\":{\"attributes\":{\"path\":\"/bar\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var request = new UpdateMonitorItemRequest { Data = { Attributes = { Path = "/bar" } } };
        var item = await client.UpdateMonitorItemAsync("m1", request);

        Assert.NotNull(item);
        Assert.Equal("PATCH", handler.Request!.Method.Method);
        Assert.Equal("/api/v3/monitor/items/m1", handler.Request.RequestUri!.AbsolutePath);
        Assert.Contains("\"path\":\"/bar\"", handler.Content);
    }

    [Fact]
    public async Task DeleteMonitorItemAsync_UsesDelete()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.NoContent));
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.DeleteMonitorItemAsync("m1");

        Assert.Equal(HttpMethod.Delete, handler.Request!.Method);
        Assert.Equal("/api/v3/monitor/items/m1", handler.Request.RequestUri!.AbsolutePath);
    }
}
