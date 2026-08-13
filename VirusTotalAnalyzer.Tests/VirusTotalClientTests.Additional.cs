using System;
using System.Diagnostics;
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
        var json = @"{""data"":{""id"":""user1"",""type"":""user"",""links"":{""self"":""https://www.virustotal.com/api/v3/users/user1""},""attributes"":{""first_name"":""Demo"",""last_name"":""User"",""has_2fa"":true,""user_since"":42,""privileges"":{""allinfo"":{""granted"":false}},""quotas"":{""api_requests_daily"":{""allowed"":500,""used"":10}}}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var user = await client.GetUserAsync("user1");

        Assert.NotNull(user);
        Assert.Equal("Demo", user!.Attributes.FirstName);
        Assert.Equal("User", user.Attributes.LastName);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(42), user.Attributes.UserSince);
        Assert.True(user.Attributes.Has2Fa);
        Assert.False(user.Attributes.Privileges["allinfo"].Granted);
        Assert.Equal(500, user.Attributes.Quotas["api_requests_daily"].Allowed);
        Assert.Equal(10, user.Attributes.Quotas["api_requests_daily"].Used);
        Assert.Equal("https://www.virustotal.com/api/v3/users/user1", user.Links.Self);
        Assert.Equal("/api/v3/users/user1", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetUploadUrlAsync_ReturnsUri()
    {
        var json = "{\"data\":\"http://www.virustotal.com/_ah/upload/token\"}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var uri = await client.GetUploadUrlAsync();

        Assert.NotNull(uri);
        Assert.Equal("https://www.virustotal.com/_ah/upload/token", uri!.ToString());
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/upload_url", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetUploadUrlAsync_ReturnsNullForInvalidUri()
    {
        var json = "{\"data\":\"not a uri\"}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var uri = await client.GetUploadUrlAsync();

        Assert.Null(uri);
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
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var uri = await client.GetFileDownloadUrlAsync("abc");

        Assert.NotNull(uri);
        Assert.Equal("https://download.example/file", uri!.ToString());
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/download_url", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetFileDownloadUrlAsync_ReturnsNullForInvalidUri()
    {
        var json = "{\"data\":\"not a uri\"}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var uri = await client.GetFileDownloadUrlAsync("abc");

        Assert.Null(uri);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/download_url", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task SubmitFileAsync_PostsDirectlyToFiles_ForSmallFiles()
    {
        var analysisJson = "{\"data\":{\"id\":\"an\",\"type\":\"analysis\",\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(analysisJson, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

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
            var report = await client.SubmitFileAsync(stream, "demo.bin", "pass");

            Assert.NotNull(report);
            Assert.NotNull(handler.Request);
            Assert.Equal("/api/v3/files", handler.Request!.RequestUri!.AbsolutePath);
            Assert.True(handler.Request.Headers.Contains("x-virustotal-password"));
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
        var uploadJson = "{\"data\":\"https://uploads.virustotal.com/upload\"}";
        var analysisJson = "{\"data\":{\"id\":\"an\",\"type\":\"analysis\",\"attributes\":{\"status\":\"queued\"}}}";
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
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        using var ms = new System.IO.MemoryStream(new byte[33554433]);
        var report = await client.SubmitFileAsync(ms, "demo.bin", "pass");

        Assert.NotNull(report);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal("/api/v3/files/upload_url", handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal("https://uploads.virustotal.com/upload", handler.Requests[1].RequestUri!.ToString());
        Assert.True(handler.Requests[1].Headers.Contains("x-virustotal-password"));
    }

    [Fact]
    public async Task ReanalyzeHashAsync_UsesCorrectPath()
    {
        var json = "{\"data\":{\"id\":\"an\",\"type\":\"analysis\",\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var report = await client.ReanalyzeHashAsync("abc", AnalysisType.File);

        Assert.NotNull(report);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/analyse", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task SubmitUrlAsync_PostsFormEncodedContent()
    {
        var json = "{\"data\":{\"id\":\"an\",\"type\":\"analysis\",\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var report = await client.SubmitUrlAsync("https://example.com");

        Assert.NotNull(report);
        Assert.NotNull(handler.Request);
        var request = handler.Request!;
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("/api/v3/urls", request.RequestUri!.AbsolutePath);
        Assert.Equal(string.Empty, request.RequestUri!.Query);
        Assert.Equal("application/x-www-form-urlencoded", request.Content!.Headers.ContentType!.MediaType);
        Assert.Equal("url=https%3A%2F%2Fexample.com", handler.Content);
    }

    [Fact]
    public async Task ScanUrlAsync_PostsToUrlsAndReturnsReport()
    {
        var json = "{\"data\":{\"id\":\"an\",\"type\":\"analysis\",\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

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
        var queued = "{\"data\":{\"id\":\"an\",\"type\":\"analysis\",\"attributes\":{\"status\":\"queued\"}}}";
        var completed = "{\"data\":{\"id\":\"an\",\"type\":\"analysis\",\"attributes\":{\"status\":\"completed\"}}}";
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
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var report = await client.WaitForAnalysisCompletionAsync("an", TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(1));

        Assert.NotNull(report);
        Assert.Equal(AnalysisStatus.Completed, report!.Attributes.Status);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task WaitForAnalysisCompletionAsync_ThrowsTimeout()
    {
        var queued = "{\"data\":{\"id\":\"an\",\"type\":\"analysis\",\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new StubHandler(queued);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await Assert.ThrowsAsync<TimeoutException>(() =>
            client.WaitForAnalysisCompletionAsync("an", TimeSpan.FromMilliseconds(50), TimeSpan.FromMilliseconds(10)));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task WaitForAnalysisCompletionAsync_RejectsNonPositiveDurations(bool invalidTimeout)
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK));
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var exception = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            client.WaitForAnalysisCompletionAsync(
                "an",
                invalidTimeout ? TimeSpan.Zero : TimeSpan.FromSeconds(1),
                invalidTimeout ? TimeSpan.FromSeconds(1) : TimeSpan.Zero));

        Assert.Equal(invalidTimeout ? "timeout" : "pollingInterval", exception.ParamName);
        Assert.Null(handler.Request);
    }

    [Fact]
    public async Task WaitForAnalysisCompletionAsync_ReturnsImmediately_WhenCompleted()
    {
        var completed = "{\"data\":{\"id\":\"an\",\"type\":\"analysis\",\"attributes\":{\"status\":\"completed\"}}}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(completed, Encoding.UTF8, "application/json")
            });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var report = await client.WaitForAnalysisCompletionAsync("an", TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(1));

        Assert.NotNull(report);
        Assert.Equal(AnalysisStatus.Completed, report!.Attributes.Status);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task WaitForAnalysisCompletionAsync_AcceptsTimeoutBeyondCancellationTimerRange()
    {
        var completed = "{\"data\":{\"id\":\"an\",\"type\":\"analysis\",\"attributes\":{\"status\":\"completed\"}}}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(completed, Encoding.UTF8, "application/json")
            });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var report = await client.WaitForAnalysisCompletionAsync(
            "an",
            TimeSpan.FromSeconds(int.MaxValue),
            TimeSpan.FromSeconds(20));

        Assert.NotNull(report);
        Assert.Equal(AnalysisStatus.Completed, report!.Attributes.Status);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task WaitForAnalysisCompletionAsync_RetriesRateLimitWithinTimeout()
    {
        var error = new HttpResponseMessage((HttpStatusCode)429)
        {
            Content = new StringContent("{\"error\":{\"code\":\"RateLimitExceeded\",\"message\":\"slow down\"}}", Encoding.UTF8, "application/json")
        };
        error.Headers.Add("Retry-After", "0");
        var completed = "{\"data\":{\"id\":\"an\",\"type\":\"analysis\",\"attributes\":{\"status\":\"completed\"}}}";
        var handler = new QueueHandler(
            error,
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(completed, Encoding.UTF8, "application/json")
            });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var report = await client.WaitForAnalysisCompletionAsync(
            "an",
            TimeSpan.FromSeconds(1),
            TimeSpan.FromMilliseconds(1));

        Assert.NotNull(report);
        Assert.Equal(AnalysisStatus.Completed, report!.Attributes.Status);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task WaitForAnalysisCompletionAsync_CancelsPollAtDeadline()
    {
        var handler = new StubHandler(async (_, cancellationToken) =>
        {
            await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"data\":{\"id\":\"an\",\"type\":\"analysis\",\"attributes\":{\"status\":\"completed\"}}}")
            };
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);
        var stopwatch = Stopwatch.StartNew();

        await Assert.ThrowsAsync<TimeoutException>(() => client.WaitForAnalysisCompletionAsync(
            "an",
            TimeSpan.FromMilliseconds(100),
            TimeSpan.FromMilliseconds(10)));

        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task WaitForAnalysisCompletionAsync_ThrowsOnCancellation()
    {
        var queued = "{\"data\":{\"id\":\"an\",\"type\":\"analysis\",\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(queued, Encoding.UTF8, "application/json")
            });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        using var cts = new CancellationTokenSource(100);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            client.WaitForAnalysisCompletionAsync("an", TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(1), cts.Token));

        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task WaitForAnalysisCompletionAsync_ThrowsApiException_OnError()
    {
        var error = "{\"data\":{\"id\":\"an\",\"type\":\"analysis\",\"attributes\":{\"status\":\"error\",\"error\":\"bad\"}}}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(error, Encoding.UTF8, "application/json")
            });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var ex = await Assert.ThrowsAsync<ApiException>(() =>
            client.WaitForAnalysisCompletionAsync("an", TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(1)));

        Assert.Equal("bad", ex.Message);
        Assert.Equal("bad", ex.Error?.Message);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task WaitForAnalysisCompletionAsync_ThrowsApiException_OnCancelled()
    {
        var cancelled = "{\"data\":{\"id\":\"an\",\"type\":\"analysis\",\"attributes\":{\"status\":\"cancelled\",\"error\":\"user cancelled\"}}}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(cancelled, Encoding.UTF8, "application/json")
            });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var ex = await Assert.ThrowsAsync<ApiException>(() =>
            client.WaitForAnalysisCompletionAsync("an", TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(1)));

        Assert.Equal("user cancelled", ex.Message);
        Assert.Equal("user cancelled", ex.Error?.Message);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task WaitForAnalysisCompletionAsync_ThrowsTimeout_OnStatusTimeout()
    {
        var timeout = "{\"data\":{\"id\":\"an\",\"type\":\"analysis\",\"attributes\":{\"status\":\"timeout\"}}}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(timeout, Encoding.UTF8, "application/json")
            });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await Assert.ThrowsAsync<TimeoutException>(() =>
            client.WaitForAnalysisCompletionAsync("an", TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(1)));

        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task GetCommentsAsync_DeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"c1\",\"type\":\"comment\",\"attributes\":{\"date\":1,\"text\":\"hi\"}}],\"meta\":{}}";
        var handler = new StubHandler(json);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var page = await client.GetCommentsAsync(ResourceType.File, "abc");

        Assert.NotNull(page);
        Assert.Single(page!.Data);
        Assert.Equal("c1", page.Data[0].Id);
        Assert.Equal("hi", page.Data[0].Attributes.Text);
    }

    [Fact]
    public async Task GetCommentsAsync_PaginatesThroughResults()
    {
        var first = "{\"data\":[{\"id\":\"c1\",\"type\":\"comment\",\"attributes\":{\"date\":1,\"text\":\"hi\"}}],\"meta\":{\"cursor\":\"abc\"}}";
        var second = "{\"data\":[{\"id\":\"c2\",\"type\":\"comment\",\"attributes\":{\"date\":2,\"text\":\"bye\"}}]}";
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
        IVirusTotalClient client = new VirusTotalClient(httpClient);

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
        var json = @"{""data"":{""id"":""c1"",""type"":""comment"",""attributes"":{""date"":1,""text"":""hello""}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

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
        IVirusTotalClient client = new VirusTotalClient(httpClient);

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
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await client.SearchAsync("demo query");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/search", handler.Request!.RequestUri!.AbsolutePath);
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
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await client.SearchAsync("demo query", limit: 10, cursor: "abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/search", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("query=demo%20query&limit=10&cursor=abc", handler.Request!.RequestUri!.Query.TrimStart('?'));
    }

    [Fact]
    public async Task SearchIntelligenceAsync_BuildsQueryWithOrderAndDescriptor()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"data\":[]}", Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await client.SearchIntelligenceAsync("demo query", order: "last_analysis_date", descriptor: "asc");

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
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var response = await client.SearchAsync("demo query");

        Assert.Equal("next", response?.Meta?.Cursor);
    }

    [Fact]
    public async Task GetIocStreamAsync_BuildsQuery()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"data\":[]}", Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await client.GetIocStreamAsync("type:file", limit: 40, descriptorsOnly: true, cursor: "abc", order: "date+");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/ioc_stream", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("filter=type%3Afile&limit=40&descriptors_only=true&cursor=abc&order=date%2B", handler.Request!.RequestUri!.Query.TrimStart('?'));
    }

    [Fact]
    public async Task GetIocStreamAsync_AllowsUnfilteredStream()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"data\":[]}", Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await client.GetIocStreamAsync(limit: 1);

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/ioc_stream", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("?limit=1", handler.Request.RequestUri.Query);
    }

    [Fact]
    public async Task GetIocStreamAsync_DeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"abc\",\"type\":\"file\",\"attributes\":{\"md5\":\"demo\"}}],\"meta\":{\"cursor\":\"next\"}}";
        var handler = new StubHandler(json);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var stream = await client.GetIocStreamAsync("type:file");

        var item = Assert.Single(stream!.Data);
        Assert.Equal("abc", item.Id);
        Assert.Equal("file", item.Type);
        Assert.Equal("demo", item.Attributes!["md5"].GetString());
        Assert.Equal("next", stream.Meta?.Cursor);
    }

    [Fact]
    public async Task GetPopularThreatCategoriesAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[\"adware\",\"ransomware\",\"virus\"]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var categories = await client.GetPopularThreatCategoriesAsync();

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/popular_threat_categories", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal(new[] { "adware", "ransomware", "virus" }, categories);
    }

}
