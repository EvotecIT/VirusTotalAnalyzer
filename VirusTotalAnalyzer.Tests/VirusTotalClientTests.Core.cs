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
        var json = "{\"data\":{\"id\":\"abc\",\"type\":\"file\",\"attributes\":{\"md5\":\"demo\"}}}";
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
        Assert.Equal("demo", report.Attributes.Md5);
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
        var client = new VirusTotalClient(httpClient);

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
        var client = new VirusTotalClient(httpClient);

#if NETFRAMEWORK
        using (var stream = await client.DownloadFileAsync("abc"))
        {
            Assert.NotNull(handler.Request);
            Assert.Equal("/api/v3/files/abc/download", handler.Request!.RequestUri!.AbsolutePath);
            Assert.False(trackingStream.Disposed);
            Assert.False(response.Disposed);
        }
#else
        await using (var stream = await client.DownloadFileAsync("abc"))
        {
            Assert.NotNull(handler.Request);
            Assert.Equal("/api/v3/files/abc/download", handler.Request!.RequestUri!.AbsolutePath);
            Assert.False(trackingStream.Disposed);
            Assert.False(response.Disposed);
        }
#endif
        Assert.True(trackingStream.Disposed);
        Assert.True(response.Disposed);
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
    public async Task DownloadPcapAsync_UsesCorrectPathAndReturnsStream()
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
        var client = new VirusTotalClient(httpClient);

#if NETFRAMEWORK
        using (var stream = await client.DownloadPcapAsync("abc"))
        {
            Assert.NotNull(handler.Request);
            Assert.Equal("/api/v3/analyses/abc/pcap", handler.Request!.RequestUri!.AbsolutePath);
            Assert.False(trackingStream.Disposed);
            Assert.False(response.Disposed);
        }
#else
        await using (var stream = await client.DownloadPcapAsync("abc"))
        {
            Assert.NotNull(handler.Request);
            Assert.Equal("/api/v3/analyses/abc/pcap", handler.Request!.RequestUri!.AbsolutePath);
            Assert.False(trackingStream.Disposed);
            Assert.False(response.Disposed);
        }
#endif
        Assert.True(trackingStream.Disposed);
        Assert.True(response.Disposed);
    }

    [Fact]
    public async Task DownloadPcapAsync_ThrowsApiException()
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

        var ex = await Assert.ThrowsAsync<ApiException>(async () => await client.DownloadPcapAsync("abc"));

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/analyses/abc/pcap", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("NotFoundError", ex.Error?.Code);
        Assert.Equal("not found", ex.Message);
    }

    [Fact]
    public async Task DownloadRetrohuntNotificationFileAsync_UsesCorrectPathAndReturnsStream()
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
        var client = new VirusTotalClient(httpClient);

#if NETFRAMEWORK
        using (var stream = await client.DownloadRetrohuntNotificationFileAsync("abc"))
        {
            Assert.NotNull(handler.Request);
            Assert.Equal("/api/v3/intelligence/retrohunt_notification_files/abc", handler.Request!.RequestUri!.AbsolutePath);
            Assert.False(trackingStream.Disposed);
            Assert.False(response.Disposed);
        }
#else
        await using (var stream = await client.DownloadRetrohuntNotificationFileAsync("abc"))
        {
            Assert.NotNull(handler.Request);
            Assert.Equal("/api/v3/intelligence/retrohunt_notification_files/abc", handler.Request!.RequestUri!.AbsolutePath);
            Assert.False(trackingStream.Disposed);
            Assert.False(response.Disposed);
        }
#endif
        Assert.True(trackingStream.Disposed);
        Assert.True(response.Disposed);
    }

    [Fact]
    public async Task DownloadRetrohuntNotificationFileAsync_ThrowsApiException()
    {
        var errorJson = "{\"error\":{\"code\":\"NotFoundError\",\"message\":\"not found\"}}";
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

        var ex = await Assert.ThrowsAsync<ApiException>(async () => await client.DownloadRetrohuntNotificationFileAsync("abc"));

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/intelligence/retrohunt_notification_files/abc", handler.Request!.RequestUri!.AbsolutePath);
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
        var json = "{\"data\":{\"id\":\"def\",\"type\":\"url\",\"attributes\":{\"url\":\"https://example.com\"}}}";
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
        var client = new VirusTotalClient(httpClient);

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
        var client = new VirusTotalClient(httpClient);

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
        var client = new VirusTotalClient(httpClient);

        var report = await client.GetUrlReportAsync(url);

        Assert.NotNull(report);
        Assert.Equal(id, report!.Id);
        Assert.NotNull(handler.Request);
        Assert.Equal($"/api/v3/urls/{id}", handler.Request!.RequestUri!.AbsolutePath);
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

}
