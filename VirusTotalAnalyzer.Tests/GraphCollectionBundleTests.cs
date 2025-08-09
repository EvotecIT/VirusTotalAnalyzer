using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class GraphCollectionBundleTests
{
    [Fact]
    public async Task CreateGraphAsync_PostsGraph()
    {
        var json = "{\"id\":\"g1\",\"type\":\"graph\",\"data\":{\"attributes\":{\"name\":\"demo\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var request = new CreateGraphRequest { Data = { Attributes = { Name = "demo" } } };
        var graph = await client.CreateGraphAsync(request);

        Assert.NotNull(graph);
        Assert.Equal(HttpMethod.Post, handler.Request!.Method);
        Assert.Equal("/api/v3/graphs", handler.Request.RequestUri!.AbsolutePath);
        Assert.Contains("\"name\":\"demo\"", handler.Content);
    }

    [Fact]
    public async Task UpdateGraphAsync_PatchesGraph()
    {
        var json = "{\"id\":\"g1\",\"type\":\"graph\",\"data\":{\"attributes\":{\"name\":\"updated\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var request = new UpdateGraphRequest { Data = { Attributes = { Name = "updated" } } };
        var graph = await client.UpdateGraphAsync("g1", request);

        Assert.NotNull(graph);
        Assert.Equal("PATCH", handler.Request!.Method.Method);
        Assert.Equal("/api/v3/graphs/g1", handler.Request.RequestUri!.AbsolutePath);
        Assert.Contains("\"name\":\"updated\"", handler.Content);
    }

    [Fact]
    public async Task DeleteGraphAsync_UsesDelete()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.NoContent));
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.DeleteGraphAsync("g1");

        Assert.Equal(HttpMethod.Delete, handler.Request!.Method);
        Assert.Equal("/api/v3/graphs/g1", handler.Request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task CreateGraphAsync_ThrowsOnError()
    {
        var error = "{\"error\":{\"message\":\"bad\"}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent(error, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var request = new CreateGraphRequest { Data = { Attributes = { Name = "demo" } } };
        await Assert.ThrowsAsync<ApiException>(() => client.CreateGraphAsync(request));
    }

    [Fact]
    public async Task CreateCollectionAsync_PostsCollection()
    {
        var json = "{\"id\":\"c1\",\"type\":\"collection\",\"data\":{\"attributes\":{\"name\":\"demo\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var request = new CreateCollectionRequest { Data = { Attributes = { Name = "demo" } } };
        var collection = await client.CreateCollectionAsync(request);

        Assert.NotNull(collection);
        Assert.Equal(HttpMethod.Post, handler.Request!.Method);
        Assert.Equal("/api/v3/collections", handler.Request.RequestUri!.AbsolutePath);
        Assert.Contains("\"name\":\"demo\"", handler.Content);
    }

    [Fact]
    public async Task UpdateCollectionAsync_PatchesCollection()
    {
        var json = "{\"id\":\"c1\",\"type\":\"collection\",\"data\":{\"attributes\":{\"name\":\"updated\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var request = new UpdateCollectionRequest { Data = { Attributes = { Name = "updated" } } };
        var collection = await client.UpdateCollectionAsync("c1", request);

        Assert.NotNull(collection);
        Assert.Equal("PATCH", handler.Request!.Method.Method);
        Assert.Equal("/api/v3/collections/c1", handler.Request.RequestUri!.AbsolutePath);
        Assert.Contains("\"name\":\"updated\"", handler.Content);
    }

    [Fact]
    public async Task DeleteCollectionAsync_UsesDelete()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.NoContent));
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.DeleteCollectionAsync("c1");

        Assert.Equal(HttpMethod.Delete, handler.Request!.Method);
        Assert.Equal("/api/v3/collections/c1", handler.Request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task CreateBundleAsync_PostsBundle()
    {
        var json = "{\"id\":\"b1\",\"type\":\"bundle\",\"data\":{\"attributes\":{\"name\":\"demo\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var request = new CreateBundleRequest
        {
            Data = { Attributes = { Name = "demo", Files = { new Relationship { Id = "f1", Type = ResourceType.File } } } }
        };
        var bundle = await client.CreateBundleAsync(request);

        Assert.NotNull(bundle);
        Assert.Equal(HttpMethod.Post, handler.Request!.Method);
        Assert.Equal("/api/v3/bundles", handler.Request.RequestUri!.AbsolutePath);
        Assert.Contains("\"name\":\"demo\"", handler.Content);
    }

    [Fact]
    public async Task UpdateBundleAsync_PatchesBundle()
    {
        var json = "{\"id\":\"b1\",\"type\":\"bundle\",\"data\":{\"attributes\":{\"name\":\"updated\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var request = new UpdateBundleRequest { Data = { Attributes = { Name = "updated" } } };
        var bundle = await client.UpdateBundleAsync("b1", request);

        Assert.NotNull(bundle);
        Assert.Equal("PATCH", handler.Request!.Method.Method);
        Assert.Equal("/api/v3/bundles/b1", handler.Request.RequestUri!.AbsolutePath);
        Assert.Contains("\"name\":\"updated\"", handler.Content);
    }

    [Fact]
    public async Task DeleteBundleAsync_UsesDelete()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.NoContent));
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.DeleteBundleAsync("b1");

        Assert.Equal(HttpMethod.Delete, handler.Request!.Method);
        Assert.Equal("/api/v3/bundles/b1", handler.Request.RequestUri!.AbsolutePath);
    }
}
