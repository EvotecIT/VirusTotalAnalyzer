using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class MonitorItemTests
{
    [Fact]
    public async Task ListMonitorItemsAsync_DeserializesOfficialResourceShapeAndQuery()
    {
        const string json = """
            {
              "data": [{
                "id": "m1",
                "type": "monitor_item",
                "attributes": {
                  "path": "/publisher/app.exe",
                  "sha256": "abc",
                  "size": 42,
                  "tags": ["release"]
                }
              }],
              "meta": { "cursor": "next_cursor" },
              "links": { "next": "https://www.virustotal.com/api/v3/monitor/items?cursor=next_cursor" }
            }
            """;
        var handler = new SingleResponseHandler(JsonResponse(json));
        using var httpClient = CreateHttpClient(handler);
        using var client = new VirusTotalClient(httpClient);

        var response = await client.ListMonitorItemsAsync("path:/publisher/*", 10, "abc");

        var item = Assert.Single(response!.Data);
        Assert.Equal("m1", item.Id);
        Assert.Equal("/publisher/app.exe", item.Attributes.Path);
        Assert.Equal("abc", item.Attributes.Sha256);
        Assert.Equal(42, item.Attributes.Size);
        Assert.Equal("next_cursor", response.NextCursor);
        Assert.Equal("?filter=path%3A%2Fpublisher%2F%2A&limit=10&cursor=abc", handler.Request!.RequestUri!.Query);
    }

    [Fact]
    public async Task EnumerateMonitorItemsAsync_FollowsCursor()
    {
        var handler = new QueueHandler(
            JsonResponse("{\"data\":[{\"id\":\"m1\",\"type\":\"monitor_item\",\"attributes\":{}}],\"meta\":{\"cursor\":\"next\"}}"),
            JsonResponse("{\"data\":[{\"id\":\"m2\",\"type\":\"monitor_item\",\"attributes\":{}}]}"));
        using var httpClient = CreateHttpClient(handler);
        using var client = new VirusTotalClient(httpClient);
        var items = new List<string>();

        await foreach (var item in client.EnumerateMonitorItemsAsync())
        {
            items.Add(item.Id);
        }

        Assert.Equal(new[] { "m1", "m2" }, items);
        Assert.Equal(string.Empty, handler.Requests[0].RequestUri!.Query);
        Assert.Equal("?cursor=next", handler.Requests[1].RequestUri!.Query);
    }

    [Fact]
    public async Task CreateMonitorFolderAsync_PostsFormPath()
    {
        var handler = new SingleResponseHandler(JsonResponse(
            "{\"data\":{\"id\":\"folder1\",\"type\":\"monitor_item\",\"attributes\":{\"path\":\"/publisher/\",\"item_type\":\"folder\"}}}"));
        using var httpClient = CreateHttpClient(handler);
        using var client = new VirusTotalClient(httpClient);

        var item = await client.CreateMonitorFolderAsync("/publisher/");

        Assert.Equal("folder1", item!.Id);
        Assert.Equal("folder", item.Attributes.ItemType);
        Assert.Equal(HttpMethod.Post, handler.Request!.Method);
        Assert.Equal("/api/v3/monitor/items", handler.Request.RequestUri!.AbsolutePath);
        Assert.Equal("path=%2Fpublisher%2F", handler.Content);
    }

    [Fact]
    public async Task ConfigureMonitorItemAsync_UsesConfigEndpointAndResourceEnvelope()
    {
        var handler = new SingleResponseHandler(JsonResponse(
            "{\"data\":{\"id\":\"m1\",\"type\":\"monitor_item\",\"attributes\":{\"details\":\"release 1\"}}}"));
        using var httpClient = CreateHttpClient(handler);
        using var client = new VirusTotalClient(httpClient);

        var item = await client.ConfigureMonitorItemAsync("m1", "release 1");

        Assert.Equal("release 1", item!.Attributes.Details);
        Assert.Equal("PATCH", handler.Request!.Method.Method);
        Assert.Equal("/api/v3/monitor/items/m1/config", handler.Request.RequestUri!.AbsolutePath);
        Assert.Contains("\"type\":\"monitoritem\"", handler.Content);
        Assert.Contains("\"details\":\"release 1\"", handler.Content);
    }

    [Fact]
    public async Task DeleteMonitorItemAsync_UsesDelete()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.NoContent));
        using var httpClient = CreateHttpClient(handler);
        using var client = new VirusTotalClient(httpClient);

        await client.DeleteMonitorItemAsync("m1");

        Assert.Equal(HttpMethod.Delete, handler.Request!.Method);
        Assert.Equal("/api/v3/monitor/items/m1", handler.Request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public void MonitorItemFilter_BuildsDocumentedPathItemAndTagExpressions()
    {
        Assert.Equal("path:/Product/", VirusTotalAnalyzer.Models.MonitorItemFilter.ByPath("/Product/").Expression);
        Assert.Equal("item:folder-id", VirusTotalAnalyzer.Models.MonitorItemFilter.ByItem("folder-id").Expression);
        Assert.Equal(
            "tag:detected new-detections",
            VirusTotalAnalyzer.Models.MonitorItemFilter.ByTags("detected", "new-detections").Expression);
    }

    [Theory]
    [InlineData("publisher/")]
    [InlineData("/publisher")]
    public async Task CreateMonitorFolderAsync_RejectsInvalidFolderPath(string path)
    {
        using var httpClient = CreateHttpClient(new StubHandler("{}"));
        using var client = new VirusTotalClient(httpClient);

        await Assert.ThrowsAsync<ArgumentException>(() => client.CreateMonitorFolderAsync(path));
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
