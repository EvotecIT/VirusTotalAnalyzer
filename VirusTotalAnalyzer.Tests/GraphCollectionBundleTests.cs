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
    public async Task ListGraphsAsync_GetsGraphs()
    {
        var json = "{\"data\":[{\"id\":\"g1\",\"type\":\"graph\",\"data\":{\"attributes\":{\"name\":\"demo\"}}}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var response = await client.ListGraphsAsync();

        Assert.NotNull(response);
        Assert.Single(response.Data);
        Assert.Equal(HttpMethod.Get, handler.Request!.Method);
        Assert.Equal("/api/v3/graphs", handler.Request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task ListGraphsAsync_WithPaginationParameters_AppendsToUrlAndReturnsCursor()
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

        var response = await client.ListGraphsAsync(limit: 10, cursor: "abc");

        Assert.NotNull(response);
        Assert.Equal("next_cursor", response.NextCursor);
        Assert.Equal(HttpMethod.Get, handler.Request!.Method);
        Assert.Equal("/api/v3/graphs", handler.Request.RequestUri!.AbsolutePath);
        Assert.Equal("?limit=10&cursor=abc", handler.Request.RequestUri.Query);
    }

    [Fact]
    public async Task ListGraphsAsync_FetchAll_RetrievesAllPages()
    {
        var first = "{\"data\":[{\"id\":\"g1\",\"type\":\"graph\"}],\"meta\":{\"cursor\":\"next\"}}";
        var second = "{\"data\":[{\"id\":\"g2\",\"type\":\"graph\"}]}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(first, Encoding.UTF8, "application/json") },
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(second, Encoding.UTF8, "application/json") }
        );
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var response = await client.ListGraphsAsync(fetchAll: true);

        Assert.NotNull(response);
        Assert.Equal(2, response.Data.Count);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal(string.Empty, handler.Requests[0].RequestUri!.Query);
        Assert.Equal("?cursor=next", handler.Requests[1].RequestUri!.Query);
    }

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
    public async Task GetGraphCommentsAsync_GetsComments()
    {
        var json = @"{""data"":[{""id"":""c1"",""type"":""comment"",""data"":{""attributes"":{""text"":""hi""}}}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var response = await client.GetGraphCommentsAsync("g1");

        Assert.NotNull(response);
        Assert.Single(response.Data);
        Assert.Equal(HttpMethod.Get, handler.Request!.Method);
        Assert.Equal("/api/v3/graphs/g1/comments", handler.Request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task AddGraphCommentAsync_PostsComment()
    {
        var json = @"{""data"":{""id"":""c1"",""type"":""comment"",""data"":{""attributes"":{""text"":""hi""}}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var comment = await client.AddGraphCommentAsync("g1", "hi");

        Assert.NotNull(comment);
        Assert.Equal(HttpMethod.Post, handler.Request!.Method);
        Assert.Equal("/api/v3/graphs/g1/comments", handler.Request.RequestUri!.AbsolutePath);
        Assert.Contains("\"text\":\"hi\"", handler.Content);
    }

    [Fact]
    public async Task DeleteGraphCommentAsync_UsesDelete()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.NoContent));
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.DeleteGraphCommentAsync("g1", "c1");

        Assert.Equal(HttpMethod.Delete, handler.Request!.Method);
        Assert.Equal("/api/v3/graphs/g1/comments/c1", handler.Request.RequestUri!.AbsolutePath);
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
    public async Task ListCollectionsAsync_GetsCollections()
    {
        var json = "{\"data\":[{\"id\":\"c1\",\"type\":\"collection\",\"data\":{\"attributes\":{\"name\":\"demo\"}}}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var response = await client.ListCollectionsAsync();

        Assert.NotNull(response);
        Assert.Single(response.Data);
        Assert.Equal(HttpMethod.Get, handler.Request!.Method);
        Assert.Equal("/api/v3/collections", handler.Request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task ListCollectionsAsync_WithPaginationParameters_AppendsToUrlAndReturnsCursor()
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

        var response = await client.ListCollectionsAsync(limit: 10, cursor: "abc");

        Assert.NotNull(response);
        Assert.Equal("next_cursor", response.NextCursor);
        Assert.Equal(HttpMethod.Get, handler.Request!.Method);
        Assert.Equal("/api/v3/collections", handler.Request.RequestUri!.AbsolutePath);
        Assert.Equal("?limit=10&cursor=abc", handler.Request.RequestUri.Query);
    }

    [Fact]
    public async Task ListCollectionsAsync_FetchAll_RetrievesAllPages()
    {
        var first = "{\"data\":[{\"id\":\"c1\",\"type\":\"collection\"}],\"meta\":{\"cursor\":\"next\"}}";
        var second = "{\"data\":[{\"id\":\"c2\",\"type\":\"collection\"}]}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(first, Encoding.UTF8, "application/json") },
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(second, Encoding.UTF8, "application/json") }
        );
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var response = await client.ListCollectionsAsync(fetchAll: true);

        Assert.NotNull(response);
        Assert.Equal(2, response.Data.Count);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal(string.Empty, handler.Requests[0].RequestUri!.Query);
        Assert.Equal("?cursor=next", handler.Requests[1].RequestUri!.Query);
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
    public async Task ListCollectionItemsAsync_GetsItems()
    {
        var json = "{\"data\":[{\"id\":\"f1\",\"type\":\"file\"}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var response = await client.ListCollectionItemsAsync("c1");

        Assert.NotNull(response);
        Assert.Single(response.Data);
        Assert.Equal(HttpMethod.Get, handler.Request!.Method);
        Assert.Equal("/api/v3/collections/c1/items", handler.Request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task ListCollectionItemsAsync_FetchAll_RetrievesAllPages()
    {
        var first = "{\"data\":[{\"id\":\"f1\",\"type\":\"file\"}],\"meta\":{\"cursor\":\"next\"}}";
        var second = "{\"data\":[{\"id\":\"f2\",\"type\":\"file\"}]}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(first, Encoding.UTF8, "application/json") },
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(second, Encoding.UTF8, "application/json") }
        );
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var response = await client.ListCollectionItemsAsync("c1", fetchAll: true);

        Assert.NotNull(response);
        Assert.Equal(2, response.Data.Count);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal(string.Empty, handler.Requests[0].RequestUri!.Query);
        Assert.Equal("?cursor=next", handler.Requests[1].RequestUri!.Query);
    }

    [Fact]
    public async Task AddCollectionItemsAsync_PostsItems()
    {
        var json = "{\"data\":[{\"id\":\"f1\",\"type\":\"file\"}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var request = new AddItemsRequest
        {
            Data = { new Relationship { Id = "f1", Type = ResourceType.File } }
        };
        var response = await client.AddCollectionItemsAsync("c1", request);

        Assert.NotNull(response);
        Assert.Equal(HttpMethod.Post, handler.Request!.Method);
        Assert.Equal("/api/v3/collections/c1/items", handler.Request.RequestUri!.AbsolutePath);
        Assert.Contains("\"id\":\"f1\"", handler.Content);
    }

    [Fact]
    public async Task DeleteCollectionItemAsync_UsesDelete()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.NoContent));
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.DeleteCollectionItemAsync("c1", "f1");

        Assert.Equal(HttpMethod.Delete, handler.Request!.Method);
        Assert.Equal("/api/v3/collections/c1/items/f1", handler.Request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task ListBundlesAsync_GetsBundles()
    {
        var json = "{\"data\":[{\"id\":\"b1\",\"type\":\"bundle\",\"data\":{\"attributes\":{\"name\":\"demo\"}}}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var response = await client.ListBundlesAsync();

        Assert.NotNull(response);
        Assert.Single(response.Data);
        Assert.Equal(HttpMethod.Get, handler.Request!.Method);
        Assert.Equal("/api/v3/bundles", handler.Request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task ListBundlesAsync_WithPaginationParameters_AppendsToUrlAndReturnsCursor()
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

        var response = await client.ListBundlesAsync(limit: 10, cursor: "abc");

        Assert.NotNull(response);
        Assert.Equal("next_cursor", response.NextCursor);
        Assert.Equal(HttpMethod.Get, handler.Request!.Method);
        Assert.Equal("/api/v3/bundles", handler.Request.RequestUri!.AbsolutePath);
        Assert.Equal("?limit=10&cursor=abc", handler.Request.RequestUri.Query);
    }

    [Fact]
    public async Task ListBundlesAsync_FetchAll_RetrievesAllPages()
    {
        var first = "{\"data\":[{\"id\":\"b1\",\"type\":\"bundle\"}],\"meta\":{\"cursor\":\"next\"}}";
        var second = "{\"data\":[{\"id\":\"b2\",\"type\":\"bundle\"}]}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(first, Encoding.UTF8, "application/json") },
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(second, Encoding.UTF8, "application/json") }
        );
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var response = await client.ListBundlesAsync(fetchAll: true);

        Assert.NotNull(response);
        Assert.Equal(2, response.Data.Count);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal(string.Empty, handler.Requests[0].RequestUri!.Query);
        Assert.Equal("?cursor=next", handler.Requests[1].RequestUri!.Query);
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

    [Fact]
    public async Task ListBundleItemsAsync_GetsItems()
    {
        var json = "{\"data\":[{\"id\":\"f1\",\"type\":\"file\"}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var response = await client.ListBundleItemsAsync("b1");

        Assert.NotNull(response);
        Assert.Single(response.Data);
        Assert.Equal(HttpMethod.Get, handler.Request!.Method);
        Assert.Equal("/api/v3/bundles/b1/items", handler.Request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task ListBundleItemsAsync_FetchAll_RetrievesAllPages()
    {
        var first = "{\"data\":[{\"id\":\"f1\",\"type\":\"file\"}],\"meta\":{\"cursor\":\"next\"}}";
        var second = "{\"data\":[{\"id\":\"f2\",\"type\":\"file\"}]}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(first, Encoding.UTF8, "application/json") },
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(second, Encoding.UTF8, "application/json") }
        );
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var response = await client.ListBundleItemsAsync("b1", fetchAll: true);

        Assert.NotNull(response);
        Assert.Equal(2, response.Data.Count);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal(string.Empty, handler.Requests[0].RequestUri!.Query);
        Assert.Equal("?cursor=next", handler.Requests[1].RequestUri!.Query);
    }

    [Fact]
    public async Task AddBundleItemsAsync_PostsItems()
    {
        var json = "{\"data\":[{\"id\":\"f1\",\"type\":\"file\"}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var request = new AddItemsRequest
        {
            Data = { new Relationship { Id = "f1", Type = ResourceType.File } }
        };
        var response = await client.AddBundleItemsAsync("b1", request);

        Assert.NotNull(response);
        Assert.Equal(HttpMethod.Post, handler.Request!.Method);
        Assert.Equal("/api/v3/bundles/b1/items", handler.Request.RequestUri!.AbsolutePath);
        Assert.Contains("\"id\":\"f1\"", handler.Content);
    }

    [Fact]
    public async Task DeleteBundleItemAsync_UsesDelete()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.NoContent));
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.DeleteBundleItemAsync("b1", "f1");

        Assert.Equal(HttpMethod.Delete, handler.Request!.Method);
        Assert.Equal("/api/v3/bundles/b1/items/f1", handler.Request.RequestUri!.AbsolutePath);
    }
}
