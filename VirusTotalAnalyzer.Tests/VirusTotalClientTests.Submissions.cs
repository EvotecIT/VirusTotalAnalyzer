using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using VirusTotalAnalyzer;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public partial class VirusTotalClientTests
{
    [Fact]
    public async Task ScanFileAsync_UsesExtensionHelper()
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
#else
        await System.IO.File.WriteAllTextAsync(path, "demo");
#endif
        try
        {
            var report = await client.ScanFileAsync(path);
            Assert.NotNull(report);
            Assert.NotNull(handler.Request);
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
        var handler = new SingleResponseHandler(response);
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
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var ex = await Assert.ThrowsAsync<RateLimitExceededException>(() => client.GetFileReportAsync("abc"));
        Assert.Equal(TimeSpan.FromSeconds(10), ex.RetryAfter);
        Assert.Equal(123, ex.RemainingQuota);
    }

    [Fact]
    public async Task GetLivehuntNotificationAsync_DeserializesResponse()
    {
        var json = "{\"data\":{\"id\":\"ln1\",\"type\":\"livehunt_notification\",\"attributes\":{\"rule_name\":\"r1\"}}}";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var notification = await client.GetLivehuntNotificationAsync("ln1");

        Assert.NotNull(notification);
        Assert.Equal("ln1", notification!.Id);
        Assert.Equal("r1", notification.Attributes.RuleName);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/livehunt_notifications/ln1", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetLivehuntNotificationAsync_ThrowsApiException()
    {
        var errorJson = @"{""error"":{""code"":""NotFoundError"",""message"":""not found""}}";
        var response = new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent(errorJson, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/" )
        };
        var client = new VirusTotalClient(httpClient);

        await Assert.ThrowsAsync<ApiException>(() => client.GetLivehuntNotificationAsync("ln1"));
    }

    [Fact]
    public async Task GetRetrohuntJobAsync_DeserializesResponse()
    {
        var json = "{\"id\":\"rj1\",\"type\":\"retrohunt_job\",\"data\":{\"attributes\":{\"status\":\"done\"}}}";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var job = await client.GetRetrohuntJobAsync("rj1");

        Assert.NotNull(job);
        Assert.Equal("rj1", job!.Id);
        Assert.Equal("done", job.Data.Attributes.Status);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/retrohunt_jobs/rj1", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetRetrohuntJobAsync_ThrowsApiException()
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

        await Assert.ThrowsAsync<ApiException>(() => client.GetRetrohuntJobAsync("rj1"));
    }

    [Fact]
    public async Task GetRetrohuntNotificationAsync_DeserializesResponse()
    {
        var json = "{\"id\":\"rn1\",\"type\":\"retrohunt_notification\",\"data\":{\"attributes\":{\"job_id\":\"j1\"}}}";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var notification = await client.GetRetrohuntNotificationAsync("rn1");

        Assert.NotNull(notification);
        Assert.Equal("rn1", notification!.Id);
        Assert.Equal("j1", notification.Data.Attributes.JobId);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/retrohunt_notifications/rn1", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetRetrohuntNotificationAsync_ThrowsApiException()
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

        await Assert.ThrowsAsync<ApiException>(() => client.GetRetrohuntNotificationAsync("rn1"));
    }

    [Fact]
    public async Task GetMonitorItemAsync_DeserializesResponse()
    {
        var json = "{\"id\":\"mi1\",\"type\":\"monitor_item\",\"data\":{\"attributes\":{\"path\":\"/tmp\"}}}";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var item = await client.GetMonitorItemAsync("mi1");

        Assert.NotNull(item);
        Assert.Equal("mi1", item!.Id);
        Assert.Equal("/tmp", item.Data.Attributes.Path);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/monitor/items/mi1", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetMonitorItemAsync_ThrowsApiException()
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

        await Assert.ThrowsAsync<ApiException>(() => client.GetMonitorItemAsync("mi1"));
    }

    [Fact]
    public async Task GetBundleAsync_DeserializesResponseAndUsesCorrectPath()
    {
        var json = "{\"id\":\"b1\",\"type\":\"bundle\",\"data\":{\"attributes\":{\"name\":\"Demo\",\"files\":[{\"id\":\"f1\",\"type\":\"file\"}]}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var bundle = await client.GetBundleAsync("b1");

        Assert.NotNull(bundle);
        Assert.Equal("b1", bundle!.Id);
        Assert.Equal(ResourceType.Bundle, bundle.Type);
        Assert.Equal("Demo", bundle.Data.Attributes.Name);
        Assert.Single(bundle.Data.Attributes.Files);
        Assert.Equal("/api/v3/bundles/b1", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task SubmitFileAsync_IncludesPasswordHeader()
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

        using var ms = new System.IO.MemoryStream(new byte[1]);
        var report = await client.SubmitFileAsync(ms, "demo.bin", "pass");

        Assert.NotNull(report);
        Assert.NotNull(handler.Request);
        Assert.True(handler.Request!.Headers.Contains("x-virustotal-password"));
    }

    [Fact]
    public async Task SubmitPrivateFileAsync_PostsToPrivateAnalyses()
    {
        var json = "{\"id\":\"pa\",\"type\":\"private_analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        using var ms = new System.IO.MemoryStream(new byte[1]);
        var report = await client.SubmitPrivateFileAsync(ms, "demo.bin", "pass");

        Assert.NotNull(report);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/private/analyses", handler.Request!.RequestUri!.AbsolutePath);
        Assert.True(handler.Request.Headers.Contains("x-virustotal-password"));
    }

    [Fact]
    public async Task GetPrivateAnalysisAsync_DeserializesResponse()
    {
        var json = "{\"id\":\"pa\",\"type\":\"private_analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new StubHandler(json);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var analysis = await client.GetPrivateAnalysisAsync("pa");

        Assert.NotNull(analysis);
        Assert.Equal("pa", analysis!.Id);
        Assert.Equal(ResourceType.PrivateAnalysis, analysis.Type);
        Assert.Equal(AnalysisStatus.Queued, analysis.Data.Attributes.Status);
    }

    [Fact]
    public async Task ReanalyzeHashAsync_UsesPrivateFilePath()
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

        var report = await client.ReanalyzeHashAsync("abc", AnalysisType.PrivateFile);

        Assert.NotNull(report);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/private/files/abc/analyse", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task ListLivehuntNotificationsAsync_PagesThroughResults()
    {
        var first = "{\"data\":[{\"id\":\"n1\",\"type\":\"livehunt_notification\",\"attributes\":{\"rule_name\":\"r1\"}}],\"meta\":{\"cursor\":\"abc\"}}";
        var second = "{\"data\":[{\"id\":\"n2\",\"type\":\"livehunt_notification\",\"attributes\":{\"rule_name\":\"r2\"}}]}";
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

        var notifications = await client.ListLivehuntNotificationsAsync(limit: 1);

        Assert.Equal(2, notifications.Data.Count);
        Assert.Null(notifications.NextCursor);
        Assert.Equal("n1", notifications.Data[0].Id);
        Assert.Equal("n2", notifications.Data[1].Id);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Contains("limit=1", handler.Requests[0].RequestUri!.Query);
        Assert.Contains("cursor=abc", handler.Requests[1].RequestUri!.Query);
    }

    [Fact]
    public async Task ListLivehuntNotificationsAsync_SinglePage()
    {
        var first = "{\"data\":[{\"id\":\"n1\",\"type\":\"livehunt_notification\",\"attributes\":{\"rule_name\":\"r1\"}}],\"meta\":{\"cursor\":\"abc\"}}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(first, Encoding.UTF8, "application/json")
            });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var page = await client.ListLivehuntNotificationsAsync(limit: 1, fetchAll: false);

        Assert.Single(page.Data);
        Assert.Equal("n1", page.Data[0].Id);
        Assert.Equal("abc", page.NextCursor);
        Assert.Single(handler.Requests);
        Assert.Contains("limit=1", handler.Requests[0].RequestUri!.Query);
    }

    [Fact]
    public async Task CreateRetrohuntJobAsync_SerializesRequestAndDeserializesResponse()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"data\":{\"id\":\"rj1\",\"type\":\"retrohunt_job\",\"attributes\":{\"status\":\"queued\"}}}", Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);
        var request = new RetrohuntJobRequest();
        request.Data.Attributes.Rules = "rule";

        var job = await client.CreateRetrohuntJobAsync(request);

        Assert.NotNull(handler.Request);
        Assert.Equal(HttpMethod.Post, handler.Request!.Method);
        Assert.Equal("/api/v3/intelligence/retrohunt_jobs", handler.Request.RequestUri!.AbsolutePath);
        Assert.Contains("\"rules\":\"rule\"", handler.Content);
        Assert.Equal("rj1", job!.Id);
    }

    [Fact]
    public async Task DeleteRetrohuntJobAsync_UsesDelete()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.NoContent));
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.DeleteRetrohuntJobAsync("rj1");

        Assert.NotNull(handler.Request);
        Assert.Equal(HttpMethod.Delete, handler.Request!.Method);
        Assert.Equal("/api/v3/intelligence/retrohunt_jobs/rj1", handler.Request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task DeleteLivehuntNotificationAsync_UsesDelete()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.NoContent));
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.DeleteLivehuntNotificationAsync("ln1");

        Assert.NotNull(handler.Request);
        Assert.Equal(HttpMethod.Delete, handler.Request!.Method);
        Assert.Equal("/api/v3/intelligence/hunting_notifications/ln1", handler.Request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task DeleteRetrohuntNotificationAsync_UsesDelete()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.NoContent));
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.DeleteRetrohuntNotificationAsync("rn1");

        Assert.NotNull(handler.Request);
        Assert.Equal(HttpMethod.Delete, handler.Request!.Method);
        Assert.Equal("/api/v3/intelligence/retrohunt_notifications/rn1", handler.Request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task AcknowledgeLivehuntNotificationAsync_UsesPost()
    {
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.NoContent));
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.AcknowledgeLivehuntNotificationAsync("ln1");

        Assert.NotNull(handler.Request);
        Assert.Equal(HttpMethod.Post, handler.Request!.Method);
        Assert.Equal("/api/v3/intelligence/hunting_notifications/ln1/acknowledge", handler.Request.RequestUri!.AbsolutePath);
    }

}
