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
    public void Create_SetsBaseAddressAndHeader()
    {
        var client = VirusTotalClient.Create("demo-key");

        var httpField = typeof(VirusTotalClient).GetField("_httpClient", BindingFlags.NonPublic | BindingFlags.Instance);
        var httpClient = Assert.IsType<HttpClient>(httpField!.GetValue(client)!);
        var disposeField = typeof(VirusTotalClient).GetField("_disposeClient", BindingFlags.NonPublic | BindingFlags.Instance);
        var disposeClient = Assert.IsType<bool>(disposeField!.GetValue(client)!);

        Assert.Equal(new Uri("https://www.virustotal.com/api/v3/"), httpClient.BaseAddress);
        Assert.True(httpClient.DefaultRequestHeaders.TryGetValues("x-apikey", out var values));
        Assert.Equal("demo-key", Assert.Single(values));
        Assert.True(disposeClient);
    }

    [Fact]
    public async Task GetFileReportAsync_DeserializesResponse()
    {
        var json = "{\"id\":\"abc\",\"type\":\"file\",\"data\":{\"attributes\":{\"md5\":\"demo\"}}}";
        var handler = new StubHandler(json);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var report = await client.GetFileReportAsync("abc");

        Assert.NotNull(report);
        Assert.Equal("abc", report!.Id);
        Assert.Equal(ResourceType.File, report.Type);
        Assert.Equal("demo", report.Data.Attributes.Md5);
    }

    [Fact]
    public async Task DownloadFileAsync_UsesCorrectPathAndReturnsStream()
    {
        var trackingStream = new TrackingStream(new byte[] { 1, 2, 3 });
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(trackingStream)
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var stream = await client.DownloadFileAsync("abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/download", handler.Request!.RequestUri!.AbsolutePath);
        Assert.False(trackingStream.Disposed);
#if NETFRAMEWORK
        stream.Dispose();
#else
        await stream.DisposeAsync();
#endif
        Assert.True(trackingStream.Disposed);
    }

    [Fact]
    public async Task DownloadFileAsync_ThrowsApiException()
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

        var ex = await Assert.ThrowsAsync<ApiException>(async () => await client.DownloadFileAsync("abc"));

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/download", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("NotFoundError", ex.Error?.Code);
        Assert.Equal("not found", ex.Message);
    }

    [Fact]
    public async Task DownloadLivehuntNotificationFileAsync_UsesCorrectPathAndReturnsStream()
    {
        var trackingStream = new TrackingStream(new byte[] { 1, 2, 3 });
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(trackingStream)
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var stream = await client.DownloadLivehuntNotificationFileAsync("abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/intelligence/hunting_notification_files/abc", handler.Request!.RequestUri!.AbsolutePath);
        Assert.False(trackingStream.Disposed);
#if NETFRAMEWORK
        stream.Dispose();
#else
        await stream.DisposeAsync();
#endif
        Assert.True(trackingStream.Disposed);
    }

    [Fact]
    public async Task DownloadLivehuntNotificationFileAsync_ThrowsApiException()
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

        var ex = await Assert.ThrowsAsync<ApiException>(async () => await client.DownloadLivehuntNotificationFileAsync("abc"));

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/intelligence/hunting_notification_files/abc", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("NotFoundError", ex.Error?.Code);
        Assert.Equal("not found", ex.Message);
    }

    [Fact]
    public async Task GetUrlReportAsync_DeserializesResponse()
    {
        var json = "{\"id\":\"def\",\"type\":\"url\",\"data\":{\"attributes\":{\"url\":\"https://example.com\"}}}";
        var handler = new StubHandler(json);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var report = await client.GetUrlReportAsync("def");

        Assert.NotNull(report);
        Assert.Equal("def", report!.Id);
        Assert.Equal(ResourceType.Url, report.Type);
        Assert.Equal("https://example.com", report.Data.Attributes.Url);
    }

    [Fact]
    public async Task GetUrlReportAsync_ThrowsApiException()
    {
        var errorJson = @"{""error"":{""code"":""NotFoundError"",""message"":""not found""}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent(errorJson, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var ex = await Assert.ThrowsAsync<ApiException>(() => client.GetUrlReportAsync("def"));

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/urls/def", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("NotFoundError", ex.Error?.Code);
        Assert.Equal("not found", ex.Message);
    }

    [Fact]
    public async Task CreateCommentAsync_PostsComment()
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

        var comment = await client.CreateCommentAsync(ResourceType.File, "abc", "hello");

        Assert.NotNull(comment);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/comments", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Contains("\"text\":\"hello\"", handler.Content);
    }

    [Fact]
    public async Task AddCommentAsync_TextForwardsToCreateCommentAsync()
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

        var comment = await client.AddCommentAsync(ResourceType.File, "abc", "hello");

        Assert.NotNull(comment);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/comments", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Contains("\"text\":\"hello\"", handler.Content);
    }

    [Fact]
    public async Task AddCommentAsync_RequestForwardsToCreateCommentAsync()
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
        var request = new CreateCommentRequest
        {
            Data = new CreateCommentData
            {
                Attributes = new CreateCommentAttributes { Text = "hello" }
            }
        };

        var comment = await client.AddCommentAsync(ResourceType.File, "abc", request);

        Assert.NotNull(comment);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/comments", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Contains("\"text\":\"hello\"", handler.Content);
    }

    [Fact]
    public async Task CreateVoteAsync_PostsVerdict()
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

        var vote = await client.CreateVoteAsync(ResourceType.File, "abc", VoteVerdict.Malicious);

        Assert.NotNull(vote);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/votes", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Contains("\"verdict\":\"malicious\"", handler.Content);
    }

    [Fact]
    public async Task VoteAsync_VerdictForwardsToCreateVoteAsync()
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

        var vote = await client.VoteAsync(ResourceType.File, "abc", VoteVerdict.Malicious);

        Assert.NotNull(vote);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/votes", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Contains("\"verdict\":\"malicious\"", handler.Content);
    }

    [Fact]
    public async Task VoteAsync_RequestForwardsToCreateVoteAsync()
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
        var request = new CreateVoteRequest
        {
            Data = new CreateVoteData
            {
                Attributes = new CreateVoteAttributes { Verdict = VoteVerdict.Malicious }
            }
        };

        var vote = await client.VoteAsync(ResourceType.File, "abc", request);

        Assert.NotNull(vote);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/votes", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Contains("\"verdict\":\"malicious\"", handler.Content);
    }

    [Fact]
    public async Task DeleteItemAsync_UsesDelete()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.NoContent));
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.DeleteItemAsync(ResourceType.File, "abc");

        Assert.NotNull(handler.Request);
        Assert.Equal(HttpMethod.Delete, handler.Request!.Method);
        Assert.Equal("/api/v3/files/abc", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task DeleteAsync_ForwardsToDeleteItemAsync()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.NoContent));
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.DeleteAsync(ResourceType.File, "abc");

        Assert.NotNull(handler.Request);
        Assert.Equal(HttpMethod.Delete, handler.Request!.Method);
        Assert.Equal("/api/v3/files/abc", handler.Request!.RequestUri!.AbsolutePath);
    }

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
        var json = "{\"data\":[{\"id\":\"c1\",\"type\":\"comment\",\"data\":{\"attributes\":{\"date\":1,\"text\":\"hi\"}}}]}";
        var handler = new StubHandler(json);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var comments = await client.GetCommentsAsync(ResourceType.File, "abc");

        Assert.NotNull(comments);
        Assert.Single(comments);
        Assert.Equal("c1", comments![0].Id);
        Assert.Equal("hi", comments[0].Data.Attributes.Text);
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

}
