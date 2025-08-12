using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Reflection;
using VirusTotalAnalyzer;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public partial class VirusTotalClientTests
{
    [Fact]
    public async Task GetUserAsync_DeserializesResponse()
    {
        var json = @"{""id"":""user1"",""type"":""user"",""data"":{""attributes"":{""username"":""demo"",""role"":""admin""}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var user = await client.GetUserAsync("user1");

        Assert.NotNull(user);
        Assert.Equal("demo", user!.Data.Attributes.Username);
        Assert.Equal(UserRole.Admin, user.Data.Attributes.Role);
        Assert.Equal("/api/v3/users/user1", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetUserPrivilegesAsync_DeserializesResponse()
    {
        var json = @"{""data"":{""can_download_file"":{""allowed"":true},""can_view_graph"":{""allowed"":false}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var privileges = await client.GetUserPrivilegesAsync("user1");

        Assert.NotNull(privileges);
        Assert.True(privileges!.Data["can_download_file"].Allowed);
        Assert.False(privileges.Data["can_view_graph"].Allowed);
        Assert.Equal("/api/v3/users/user1/privileges", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetUserQuotaAsync_DeserializesResponse()
    {
        var json = @"{""data"":{""api_requests_daily"":{""allowed"":100,""used"":10}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var quota = await client.GetUserQuotaAsync("user1");

        Assert.NotNull(quota);
        Assert.Equal(100, quota!.Data["api_requests_daily"].Allowed);
        Assert.Equal(10, quota.Data["api_requests_daily"].Used);
        Assert.Equal("/api/v3/users/user1/quotas", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetUploadUrlAsync_ReturnsUri()
    {
        var json = "{\"data\":\"https://upload.example/upload\"}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var uri = await client.GetUploadUrlAsync();

        Assert.NotNull(uri);
        Assert.Equal("https://upload.example/upload", uri!.ToString());
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/upload_url", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetFileDownloadUrlAsync_ReturnsUri()
    {
        var json = "{\"data\":\"https://download.example/file\"}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var uri = await client.GetFileDownloadUrlAsync("abc");

        Assert.NotNull(uri);
        Assert.Equal("https://download.example/file", uri!.ToString());
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/download_url", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task SubmitFileAsync_PostsDirectlyToFiles_ForSmallFiles()
    {
        var analysisJson = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(analysisJson, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var path = System.IO.Path.GetTempFileName();
#if NETFRAMEWORK
        System.IO.File.WriteAllText(path, "demo");
        var stream = System.IO.File.OpenRead(path);
#else
        await System.IO.File.WriteAllTextAsync(path, "demo");
        var stream = System.IO.File.OpenRead(path);
#endif
        try
        {
            var report = await client.SubmitFileAsync(stream, "demo.bin", AnalysisType.File, "pass");

            Assert.NotNull(report);
            Assert.NotNull(handler.Request);
            Assert.Equal("/api/v3/files", handler.Request!.RequestUri!.AbsolutePath);
            Assert.True(handler.Request.Headers.Contains("password"));
        }
        finally
        {
#if NETFRAMEWORK
            stream.Dispose();
#else
            await stream.DisposeAsync();
#endif
            System.IO.File.Delete(path);
        }
    }

    [Fact]
    public async Task SubmitFileAsync_UsesUploadUrlForLargeFiles()
    {
        var uploadJson = "{\"data\":\"https://upload.example/upload\"}";
        var analysisJson = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(uploadJson, Encoding.UTF8, "application/json")
            },
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(analysisJson, Encoding.UTF8, "application/json")
            });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        using var ms = new System.IO.MemoryStream(new byte[33554433]);
        var report = await client.SubmitFileAsync(ms, "demo.bin", AnalysisType.File, "pass");

        Assert.NotNull(report);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal("/api/v3/files/upload_url", handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal("https://upload.example/upload", handler.Requests[1].RequestUri!.ToString());
        Assert.True(handler.Requests[1].Headers.Contains("password"));
    }

    [Fact]
    public async Task ReanalyzeHashAsync_UsesCorrectPath()
    {
        var json = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var report = await client.ReanalyzeHashAsync("abc", AnalysisType.File);

        Assert.NotNull(report);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/analyse", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task SubmitUrlAsync_PostsFormEncodedContent()
    {
        var json = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var report = await client.SubmitUrlAsync("https://example.com", AnalysisType.Url);

        Assert.NotNull(report);
        Assert.NotNull(handler.Request);
        var request = handler.Request!;
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("/api/v3/urls", request.RequestUri!.AbsolutePath);
        Assert.Equal("application/x-www-form-urlencoded", request.Content!.Headers.ContentType!.MediaType);
        Assert.Equal("url=https%3A%2F%2Fexample.com", handler.Content);
    }

    [Fact]
    public async Task ScanUrlAsync_PostsToUrlsAndReturnsReport()
    {
        var json = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}"; 
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var report = await client.ScanUrlAsync("https://example.com");

        Assert.NotNull(report);
        Assert.Equal("an", report!.Id);
        Assert.NotNull(handler.Request);
        Assert.Equal(HttpMethod.Post, handler.Request!.Method);
        Assert.Equal("/api/v3/urls", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("url=https%3A%2F%2Fexample.com", handler.Content);
    }

    [Fact]
    public async Task WaitForAnalysisCompletionAsync_PollsUntilCompleted()
    {
        var queued = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
        var completed = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"completed\"}}}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(queued, Encoding.UTF8, "application/json")
            },
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(completed, Encoding.UTF8, "application/json")
            });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var report = await client.WaitForAnalysisCompletionAsync("an", TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(1));

        Assert.NotNull(report);
        Assert.Equal(AnalysisStatus.Completed, report!.Data.Attributes.Status);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task WaitForAnalysisCompletionAsync_ThrowsTimeout()
    {
        var queued = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new StubHandler(queued);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await Assert.ThrowsAsync<TimeoutException>(() =>
            client.WaitForAnalysisCompletionAsync("an", TimeSpan.FromMilliseconds(50), TimeSpan.FromMilliseconds(10)));
    }

    [Fact]
    public async Task WaitForAnalysisCompletionAsync_ReturnsImmediately_WhenCompleted()
    {
        var completed = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"completed\"}}}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(completed, Encoding.UTF8, "application/json")
            });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var report = await client.WaitForAnalysisCompletionAsync("an", TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(1));

        Assert.NotNull(report);
        Assert.Equal(AnalysisStatus.Completed, report!.Data.Attributes.Status);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task WaitForAnalysisCompletionAsync_ThrowsOnCancellation()
    {
        var queued = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(queued, Encoding.UTF8, "application/json")
            });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        using var cts = new CancellationTokenSource(100);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            client.WaitForAnalysisCompletionAsync("an", TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(1), cts.Token));

        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task WaitForAnalysisCompletionAsync_ThrowsApiException_OnError()
    {
        var error = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"error\",\"error\":\"bad\"}}}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(error, Encoding.UTF8, "application/json")
            });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var ex = await Assert.ThrowsAsync<ApiException>(() =>
            client.WaitForAnalysisCompletionAsync("an", TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(1)));

        Assert.Equal("bad", ex.Message);
        Assert.Equal("bad", ex.Error?.Message);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task WaitForAnalysisCompletionAsync_ThrowsApiException_OnCancelled()
    {
        var cancelled = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"cancelled\",\"error\":\"user cancelled\"}}}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(cancelled, Encoding.UTF8, "application/json")
            });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var ex = await Assert.ThrowsAsync<ApiException>(() =>
            client.WaitForAnalysisCompletionAsync("an", TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(1)));

        Assert.Equal("user cancelled", ex.Message);
        Assert.Equal("user cancelled", ex.Error?.Message);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task WaitForAnalysisCompletionAsync_ThrowsTimeout_OnStatusTimeout()
    {
        var timeout = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"timeout\"}}}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(timeout, Encoding.UTF8, "application/json")
            });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await Assert.ThrowsAsync<TimeoutException>(() =>
            client.WaitForAnalysisCompletionAsync("an", TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(1)));

        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task GetCommentsAsync_DeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"c1\",\"type\":\"comment\",\"data\":{\"attributes\":{\"date\":1,\"text\":\"hi\"}}}],\"meta\":{}}";
        var handler = new StubHandler(json);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var page = await client.GetCommentsAsync(ResourceType.File, "abc");

        Assert.NotNull(page);
        Assert.Single(page!.Data);
        Assert.Equal("c1", page.Data[0].Id);
        Assert.Equal("hi", page.Data[0].Data.Attributes.Text);
    }

    [Fact]
    public async Task GetCommentsAsync_PaginatesThroughResults()
    {
        var first = "{\"data\":[{\"id\":\"c1\",\"type\":\"comment\",\"data\":{\"attributes\":{\"date\":1,\"text\":\"hi\"}}}],\"meta\":{\"cursor\":\"abc\"}}";
        var second = "{\"data\":[{\"id\":\"c2\",\"type\":\"comment\",\"data\":{\"attributes\":{\"date\":2,\"text\":\"bye\"}}}]}";
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
        var client = new VirusTotalClient(httpClient);

        var page1 = await client.GetCommentsAsync(ResourceType.File, "abc", limit: 1);
        var page2 = await client.GetCommentsAsync(ResourceType.File, "abc", cursor: page1!.Meta!.Cursor);

        Assert.Equal("c1", page1!.Data[0].Id);
        Assert.Equal("c2", page2!.Data[0].Id);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Contains("limit=1", handler.Requests[0].RequestUri!.Query);
        Assert.Contains("cursor=abc", handler.Requests[1].RequestUri!.Query);
    }

    [Fact]
    public async Task GetCommentAsync_DeserializesResponseAndUsesCorrectPath()
    {
        var json = @"{""data"":{""id"":""c1"",""type"":""comment"",""data"":{""attributes"":{""date"":1,""text"":""hello""}}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var comment = await client.GetCommentAsync("c1");

        Assert.NotNull(comment);
        Assert.Equal("c1", comment!.Id);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/comments/c1", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetCommentAsync_ThrowsApiException()
    {
        var errorJson = @"{""error"":{""code"":""NotFoundError"",""message"":""not found""}}";
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

        var ex = await Assert.ThrowsAsync<ApiException>(() => client.GetCommentAsync("c1"));
        Assert.Equal("not found", ex.Message);
        Assert.Equal("NotFoundError", ex.Error?.Code);
    }

    [Fact]
    public async Task SearchAsync_UsesCorrectPath()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"data\":[]}", Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.SearchAsync("demo query");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/intelligence/search", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("query=demo%20query", handler.Request!.RequestUri!.Query.TrimStart('?'));
    }

    [Fact]
    public async Task SearchAsync_BuildsQueryWithLimitAndCursor()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"data\":[]}", Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.SearchAsync("demo query", limit: 10, cursor: "abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/intelligence/search", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("query=demo%20query&limit=10&cursor=abc", handler.Request!.RequestUri!.Query.TrimStart('?'));
    }

    [Fact]
    public async Task SearchAsync_BuildsQueryWithOrderAndDescriptor()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"data\":[]}", Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.SearchAsync("demo query", order: "last_analysis_date", descriptor: "asc");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/intelligence/search", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("query=demo%20query&order=last_analysis_date&descriptor=asc", handler.Request!.RequestUri!.Query.TrimStart('?'));
    }

    [Fact]
    public async Task SearchAsync_DeserializesCursor()
    {
        var json = "{\"data\":[],\"meta\":{\"cursor\":\"next\"}}";
        var handler = new StubHandler(json);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var response = await client.SearchAsync("demo query");

        Assert.Equal("next", response?.Meta?.Cursor);
    }

    [Fact]
    public async Task GetFeedAsync_BuildsQueryWithLimitAndCursor()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"data\":[]}", Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.GetFeedAsync(ResourceType.File, limit: 20, cursor: "xyz");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/feeds/files", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("limit=20&cursor=xyz", handler.Request!.RequestUri!.Query.TrimStart('?'));
    }

    [Fact]
    public async Task GetFeedAsync_DeserializesCursor()
    {
        var json = "{\"data\":[],\"meta\":{\"cursor\":\"next\"}}";
        var handler = new StubHandler(json);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var feed = await client.GetFeedAsync(ResourceType.File);

        Assert.Equal("next", feed?.Meta?.Cursor);
    }

    [Fact]
    public async Task GetFeedAsync_ThrowsForUnsupportedResourceType()
    {
        var handler = new StubHandler("{\"data\":[]}");
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => client.GetFeedAsync(ResourceType.Analysis));
    }

}
