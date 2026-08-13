using System;
using System.IO;
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
        IVirusTotalClient client = VirusTotalClient.Create("demo-key");

        var httpField = typeof(VirusTotalClient).GetField("_httpClient", BindingFlags.NonPublic | BindingFlags.Instance);
        var httpClient = Assert.IsType<HttpClient>(httpField!.GetValue(client)!);
        var disposeField = typeof(VirusTotalClient).GetField("_disposeClient", BindingFlags.NonPublic | BindingFlags.Instance);
        var disposeClient = Assert.IsType<bool>(disposeField!.GetValue(client)!);

        Assert.Equal(new Uri("https://www.virustotal.com/api/v3/"), httpClient.BaseAddress);
        Assert.True(httpClient.DefaultRequestHeaders.TryGetValues("x-apikey", out var values));
        Assert.Equal("demo-key", Assert.Single(values));
        var expectedAgent = $"{typeof(VirusTotalClient).Assembly.GetName().Name}/{typeof(VirusTotalClient).Assembly.GetName().Version}";
        Assert.Equal(expectedAgent, httpClient.DefaultRequestHeaders.UserAgent.ToString());
        Assert.True(disposeClient);
    }

    [Fact]
    public async Task GetFileReportAsync_DeserializesResponse()
    {
        var json = "{\"data\":{\"id\":\"abc\",\"type\":\"file\",\"links\":{\"self\":\"https://www.virustotal.com/api/v3/files/abc\"},\"attributes\":{\"md5\":\"demo\"}}}";
        var handler = new StubHandler(json);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var report = await client.GetFileReportAsync("abc");

        Assert.NotNull(report);
        Assert.Equal("abc", report!.Id);
        Assert.Equal(ResourceType.File, report.Type);
        Assert.Equal("demo", report.Attributes.Md5);
        Assert.Equal("https://www.virustotal.com/api/v3/files/abc", report.Links.Self);
    }

    [Fact]
    public async Task GetFileReportAsync_AppendsFieldsAndRelationships()
    {
        var json = "{\"data\":{\"id\":\"abc\",\"type\":\"file\"}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await client.GetFileReportAsync(
            "abc",
            fields: new[] { "reputation", "size" },
            relationships: new[] { "analyses" });

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal(
            "fields=reputation,size&relationships=analyses",
            handler.Request!.RequestUri!.Query.TrimStart('?'));
    }

    [Fact]
    public async Task DownloadFileAsync_UsesCorrectPathAndReturnsStream()
    {
        var trackingStream = new TrackingStream(new byte[] { 1, 2, 3 });
        var downloadResponse = new TrackingResponseMessage
        {
            StatusCode = HttpStatusCode.OK,
            Content = new StreamContent(trackingStream)
        };
        var apiHandler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                "{\"data\":\"https://storage.example/files/abc\"}",
                Encoding.UTF8,
                "application/json")
        });
        var httpClient = new HttpClient(apiHandler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        httpClient.DefaultRequestHeaders.Add("x-apikey", "secret");

        var redirectResponse = new HttpResponseMessage(HttpStatusCode.Redirect);
        redirectResponse.Headers.Location = new Uri("https://cdn.example/files/abc");
        var downloadHandler = new QueueHandler(redirectResponse, downloadResponse);
        var downloadClient = new HttpClient(downloadHandler);
        IVirusTotalClient client = new VirusTotalClient(httpClient, downloadClient);

#if NETFRAMEWORK
        using (var stream = await client.DownloadFileAsync("abc"))
        {
            Assert.NotNull(apiHandler.Request);
            Assert.Equal("/api/v3/files/abc/download_url", apiHandler.Request!.RequestUri!.AbsolutePath);
            Assert.False(trackingStream.Disposed);
            Assert.False(downloadResponse.Disposed);
        }
#else
        await using (var stream = await client.DownloadFileAsync("abc"))
        {
            Assert.NotNull(apiHandler.Request);
            Assert.Equal("/api/v3/files/abc/download_url", apiHandler.Request!.RequestUri!.AbsolutePath);
            Assert.False(trackingStream.Disposed);
            Assert.False(downloadResponse.Disposed);
        }
#endif
        Assert.True(trackingStream.Disposed);
        Assert.True(downloadResponse.Disposed);
        Assert.Equal(2, downloadHandler.Requests.Count);
        Assert.Equal("storage.example", downloadHandler.Requests[0].RequestUri!.Host);
        Assert.Equal("cdn.example", downloadHandler.Requests[1].RequestUri!.Host);
        Assert.All(downloadHandler.Requests, request =>
        {
            Assert.False(request.Headers.Contains("x-apikey"));
            Assert.Null(request.Headers.Authorization);
        });
    }

    [Fact]
    public async Task DownloadFileAsync_ThrowsApiException()
    {
        var errorJson = @"{""error"":{""code"":""NotFoundError"",""message"":""not found""}}";
        var response = new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent(errorJson, Encoding.UTF8, "application/json")
        };
        var apiHandler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(apiHandler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var downloadClient = new HttpClient(new QueueHandler());
        IVirusTotalClient client = new VirusTotalClient(httpClient, downloadClient);

        var ex = await Assert.ThrowsAsync<ApiException>(async () => await client.DownloadFileAsync("abc"));

        Assert.NotNull(apiHandler.Request);
        Assert.Equal("/api/v3/files/abc/download_url", apiHandler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("NotFoundError", ex.Error?.Code);
        Assert.Equal("not found", ex.Message);
    }

    [Fact]
    public async Task DownloadFileAsync_RejectsHttpsToHttpRedirectWithoutSendingApiKey()
    {
        var apiHandler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                "{\"data\":\"https://storage.example/files/abc\"}",
                Encoding.UTF8,
                "application/json")
        });
        var httpClient = new HttpClient(apiHandler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        httpClient.DefaultRequestHeaders.Add("x-apikey", "secret");

        var redirectResponse = new HttpResponseMessage(HttpStatusCode.Redirect);
        redirectResponse.Headers.Location = new Uri("http://storage.example/insecure");
        var downloadHandler = new QueueHandler(redirectResponse);
        var downloadClient = new HttpClient(downloadHandler);
        using var client = new VirusTotalClient(httpClient, downloadClient);

        await Assert.ThrowsAsync<InvalidDataException>(() => client.DownloadFileAsync("abc"));

        var request = Assert.Single(downloadHandler.Requests);
        Assert.False(request.Headers.Contains("x-apikey"));
        Assert.Null(request.Headers.Authorization);
    }

    [Theory]
    [InlineData("pcap", "/api/v3/file_behaviours/abc/pcap")]
    [InlineData("livehunt", "/api/v3/intelligence/hunting_notification_files/abc")]
    public async Task RedirectingAuthenticatedDownloads_FollowSignedUrlWithoutApiKey(
        string downloadKind,
        string expectedApiPath)
    {
        var apiRedirect = new HttpResponseMessage(HttpStatusCode.Redirect);
        apiRedirect.Headers.Location = new Uri("https://storage.example/downloads/abc");
        var apiHandler = new QueueHandler(apiRedirect);
        var apiClient = new HttpClient(apiHandler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        apiClient.DefaultRequestHeaders.Add("x-apikey", "secret");

        var downloadHandler = new QueueHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(new byte[] { 1, 2, 3 })
        });
        var downloadClient = new HttpClient(downloadHandler);
        using var client = new VirusTotalClient(apiClient, downloadClient);

        var downloadTask = downloadKind switch
        {
            "pcap" => client.DownloadFileBehaviorArtifactAsync("abc", BehaviorArtifact.Pcap),
            "livehunt" => client.DownloadLivehuntNotificationFileAsync("abc"),
            _ => throw new InvalidOperationException($"Unknown download kind: {downloadKind}")
        };

        using var stream = await downloadTask;
        Assert.Equal(1, stream.ReadByte());

        var apiRequest = Assert.Single(apiHandler.Requests);
        Assert.Equal(expectedApiPath, apiRequest.RequestUri!.AbsolutePath);
        Assert.True(apiRequest.Headers.Contains("x-apikey"));

        var downloadRequest = Assert.Single(downloadHandler.Requests);
        Assert.Equal("storage.example", downloadRequest.RequestUri!.Host);
        Assert.False(downloadRequest.Headers.Contains("x-apikey"));
        Assert.Null(downloadRequest.Headers.Authorization);
    }

    [Fact]
    public async Task DownloadFileBehaviorArtifactAsync_RejectsInsecureRedirectBeforeUnauthenticatedRequest()
    {
        var apiRedirect = new HttpResponseMessage(HttpStatusCode.Redirect);
        apiRedirect.Headers.Location = new Uri("http://storage.example/downloads/abc");
        var apiHandler = new QueueHandler(apiRedirect);
        var apiClient = new HttpClient(apiHandler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        apiClient.DefaultRequestHeaders.Add("x-apikey", "secret");
        var downloadHandler = new QueueHandler();
        using var client = new VirusTotalClient(apiClient, new HttpClient(downloadHandler));

        await Assert.ThrowsAsync<InvalidDataException>(() => client.DownloadFileBehaviorArtifactAsync("abc", BehaviorArtifact.Pcap));

        Assert.Single(apiHandler.Requests);
        Assert.Empty(downloadHandler.Requests);
    }

    [Fact]
    public async Task DownloadFileBehaviorArtifactAsync_UsesCorrectPathAndReturnsStream()
    {
        var trackingStream = new TrackingStream(new byte[] { 1, 2, 3 });
        var response = new TrackingResponseMessage
        {
            StatusCode = HttpStatusCode.OK,
            Content = new StreamContent(trackingStream)
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

#if NETFRAMEWORK
        using (var stream = await client.DownloadFileBehaviorArtifactAsync("abc", BehaviorArtifact.Pcap))
        {
            Assert.NotNull(handler.Request);
            Assert.Equal("/api/v3/file_behaviours/abc/pcap", handler.Request!.RequestUri!.AbsolutePath);
            Assert.False(trackingStream.Disposed);
            Assert.False(response.Disposed);
        }
#else
        await using (var stream = await client.DownloadFileBehaviorArtifactAsync("abc", BehaviorArtifact.Pcap))
        {
            Assert.NotNull(handler.Request);
            Assert.Equal("/api/v3/file_behaviours/abc/pcap", handler.Request!.RequestUri!.AbsolutePath);
            Assert.False(trackingStream.Disposed);
            Assert.False(response.Disposed);
        }
#endif
        Assert.True(trackingStream.Disposed);
        Assert.True(response.Disposed);
    }

    [Fact]
    public async Task DownloadFileBehaviorArtifactAsync_ThrowsApiException()
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

        var ex = await Assert.ThrowsAsync<ApiException>(async () => await client.DownloadFileBehaviorArtifactAsync("abc", BehaviorArtifact.Pcap));

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/file_behaviours/abc/pcap", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("NotFoundError", ex.Error?.Code);
        Assert.Equal("not found", ex.Message);
    }

    [Fact]
    public async Task DownloadLivehuntNotificationFileAsync_UsesCorrectPathAndReturnsStream()
    {
        var trackingStream = new TrackingStream(new byte[] { 1, 2, 3 });
        var response = new TrackingResponseMessage
        {
            StatusCode = HttpStatusCode.OK,
            Content = new StreamContent(trackingStream)
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

#if NETFRAMEWORK
        using (var stream = await client.DownloadLivehuntNotificationFileAsync("abc"))
        {
            Assert.NotNull(handler.Request);
            Assert.Equal("/api/v3/intelligence/hunting_notification_files/abc", handler.Request!.RequestUri!.AbsolutePath);
            Assert.False(trackingStream.Disposed);
            Assert.False(response.Disposed);
        }
#else
        await using (var stream = await client.DownloadLivehuntNotificationFileAsync("abc"))
        {
            Assert.NotNull(handler.Request);
            Assert.Equal("/api/v3/intelligence/hunting_notification_files/abc", handler.Request!.RequestUri!.AbsolutePath);
            Assert.False(trackingStream.Disposed);
            Assert.False(response.Disposed);
        }
#endif
        Assert.True(trackingStream.Disposed);
        Assert.True(response.Disposed);
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
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var ex = await Assert.ThrowsAsync<ApiException>(async () => await client.DownloadLivehuntNotificationFileAsync("abc"));

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/intelligence/hunting_notification_files/abc", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("NotFoundError", ex.Error?.Code);
        Assert.Equal("not found", ex.Message);
    }

    [Fact]
    public async Task GetUrlReportAsync_DeserializesResponse()
    {
        var json = "{\"data\":{\"id\":\"def\",\"type\":\"url\",\"attributes\":{\"url\":\"https://example.com\"}}}";
        var handler = new StubHandler(json);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var report = await client.GetUrlReportAsync("def");

        Assert.NotNull(report);
        Assert.Equal("def", report!.Id);
        Assert.Equal(ResourceType.Url, report.Type);
        Assert.Equal("https://example.com", report.Attributes.Url);
    }

    [Fact]
    public async Task GetUrlReportAsync_AppendsFieldsAndRelationships()
    {
        var json = "{\"data\":{\"id\":\"def\",\"type\":\"url\"}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await client.GetUrlReportAsync(
            "def",
            fields: new[] { "last_analysis_date" },
            relationships: new[] { "last_serving_ip_address" });

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/urls/def", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal(
            "fields=last_analysis_date&relationships=last_serving_ip_address",
            handler.Request!.RequestUri!.Query.TrimStart('?'));
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
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var ex = await Assert.ThrowsAsync<ApiException>(() => client.GetUrlReportAsync("def"));

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/urls/def", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("NotFoundError", ex.Error?.Code);
        Assert.Equal("not found", ex.Message);
    }

    [Fact]
    public async Task GetUrlReportAsync_WithUrl_ComputesIdentifier()
    {
        var url = new Uri("https://example.com");
        var id = VirusTotalClientExtensions.GetUrlId(url.ToString());
        var json = $"{{\"data\":{{\"id\":\"{id}\",\"type\":\"url\"}}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var report = await client.GetUrlReportAsync(url);

        Assert.NotNull(report);
        Assert.Equal(id, report!.Id);
        Assert.NotNull(handler.Request);
        Assert.Equal($"/api/v3/urls/{id}", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task CreateCommentAsync_PostsComment()
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

        var comment = await client.CreateCommentAsync(ResourceType.File, "abc", "hello");

        Assert.NotNull(comment);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/comments", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Contains("\"text\":\"hello\"", handler.Content);
    }

    [Fact]
    public async Task AddCommentAsync_TextForwardsToCreateCommentAsync()
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

        var comment = await client.AddCommentAsync(ResourceType.File, "abc", "hello");

        Assert.NotNull(comment);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/comments", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Contains("\"text\":\"hello\"", handler.Content);
    }

    [Fact]
    public async Task AddCommentAsync_RequestForwardsToCreateCommentAsync()
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
    public async Task CreateCommentAsync_NullRequest_Throws()
    {
        var httpClient = new HttpClient(new StubHandler("{}"))
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await Assert.ThrowsAsync<ArgumentNullException>(() => client.CreateCommentAsync(ResourceType.File, "abc", (CreateCommentRequest)null!));
    }

    [Fact]
    public async Task CreateVoteAsync_PostsVerdict()
    {
        var json = @"{""data"":{""id"":""v1"",""type"":""vote"",""attributes"":{""date"":1,""verdict"":""malicious""}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var vote = await client.CreateVoteAsync(ResourceType.File, "abc", VoteVerdict.Malicious);

        Assert.NotNull(vote);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/votes", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Contains("\"verdict\":\"malicious\"", handler.Content);
    }

    [Fact]
    public async Task VoteAsync_VerdictForwardsToCreateVoteAsync()
    {
        var json = @"{""data"":{""id"":""v1"",""type"":""vote"",""attributes"":{""date"":1,""verdict"":""malicious""}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var vote = await client.VoteAsync(ResourceType.File, "abc", VoteVerdict.Malicious);

        Assert.NotNull(vote);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/votes", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Contains("\"verdict\":\"malicious\"", handler.Content);
    }

    [Fact]
    public async Task VoteAsync_RequestForwardsToCreateVoteAsync()
    {
        var json = @"{""data"":{""id"":""v1"",""type"":""vote"",""attributes"":{""date"":1,""verdict"":""malicious""}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);
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
    public async Task CreateVoteAsync_NullRequest_Throws()
    {
        var httpClient = new HttpClient(new StubHandler("{}"))
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await Assert.ThrowsAsync<ArgumentNullException>(() => client.CreateVoteAsync(ResourceType.File, "abc", null!));
    }

    [Fact]
    public async Task DeleteItemAsync_UsesDelete()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.NoContent));
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

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
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await client.DeleteAsync(ResourceType.File, "abc");

        Assert.NotNull(handler.Request);
        Assert.Equal(HttpMethod.Delete, handler.Request!.Method);
        Assert.Equal("/api/v3/files/abc", handler.Request!.RequestUri!.AbsolutePath);
    }

}
