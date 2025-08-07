using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class VirusTotalClientTests
{
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
    public async Task GetUploadUrlAsync_ReturnsUri()
    {
        var json = "{\"data\":\"https://upload.example/upload\"}";
        var handler = new RecordingHandler(new HttpResponseMessage(HttpStatusCode.OK)
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
        Assert.Single(handler.Requests);
        Assert.Equal("/api/v3/files/upload_url", handler.Requests[0].RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task SubmitFileAsync_UsesUploadUrlForLargeFiles()
    {
        var uploadJson = "{\"data\":\"https://upload.example/upload\"}";
        var analysisJson = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new RecordingHandler(
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
        var handler = new RecordingHandler(new HttpResponseMessage(HttpStatusCode.OK)
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
        Assert.Single(handler.Requests);
        Assert.Equal("/api/v3/files/abc/analyse", handler.Requests[0].RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task SubmitUrlAsync_PostsFormEncodedContent()
    {
        var json = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new RecordingHandler(new HttpResponseMessage(HttpStatusCode.OK)
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
        Assert.Single(handler.Requests);
        var request = handler.Requests[0];
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("/api/v3/urls", request.RequestUri!.AbsolutePath);
        Assert.Equal("application/x-www-form-urlencoded", request.Content!.Headers.ContentType!.MediaType);
        Assert.Equal("url=https%3A%2F%2Fexample.com", handler.Contents[0]);
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
        var handler = new RecordingHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"data\":[]}", Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.SearchAsync("demo query");

        Assert.Single(handler.Requests);
        Assert.Equal("/api/v3/intelligence/search", handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal("query=demo%20query", handler.Requests[0].RequestUri!.Query.TrimStart('?'));
    }

    [Fact]
    public async Task ScanFileAsync_UsesExtensionHelper()
    {
        var analysisJson = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new RecordingHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(analysisJson, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var path = System.IO.Path.GetTempFileName();
        await System.IO.File.WriteAllTextAsync(path, "demo");
        try
        {
            var report = await client.ScanFileAsync(path);
            Assert.NotNull(report);
            Assert.Single(handler.Requests);
        }
        finally
        {
            System.IO.File.Delete(path);
        }
    }

    [Fact]
    public async Task GetFileReportAsync_ThrowsApiException()
    {
        var errorJson = @"{""error"":{""code"":""NotFoundError"",""message"":""not found""}}";
        var response = new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent(errorJson, Encoding.UTF8, "application/json")
        };
        var handler = new RecordingHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var ex = await Assert.ThrowsAsync<ApiException>(() => client.GetFileReportAsync("abc"));
        Assert.Equal("not found", ex.Message);
        Assert.Equal("NotFoundError", ex.Error?.Code);
    }

    [Fact]
    public async Task Client_ThrowsRateLimitExceededException()
    {
        var errorJson = @"{""error"":{""code"":""RateLimitExceeded"",""message"":""too many""}}";
        var response = new HttpResponseMessage((HttpStatusCode)429)
        {
            Content = new StringContent(errorJson, Encoding.UTF8, "application/json")
        };
        response.Headers.Add("Retry-After", "10");
        response.Headers.Add("X-RateLimit-Remaining", "123");
        var handler = new RecordingHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var ex = await Assert.ThrowsAsync<RateLimitExceededException>(() => client.GetFileReportAsync("abc"));
        Assert.Equal(TimeSpan.FromSeconds(10), ex.RetryAfter);
        Assert.Equal(123, ex.RemainingQuota);
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly string _response;
        public StubHandler(string response) => _response = response;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_response, Encoding.UTF8, "application/json")
            });
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly System.Collections.Generic.Queue<HttpResponseMessage> _responses;
        public System.Collections.Generic.List<HttpRequestMessage> Requests { get; } = new();
        public System.Collections.Generic.List<string?> Contents { get; } = new();

        public RecordingHandler(params HttpResponseMessage[] responses)
            => _responses = new System.Collections.Generic.Queue<HttpResponseMessage>(responses);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            if (request.Content != null)
            {
                var text = await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                Contents.Add(text);
            }
            else
            {
                Contents.Add(null);
            }
            return _responses.Dequeue();
        }
    }
}
