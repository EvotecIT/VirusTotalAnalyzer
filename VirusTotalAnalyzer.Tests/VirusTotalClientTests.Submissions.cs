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
        var json = "{\"id\":\"ln1\",\"type\":\"livehuntNotification\",\"data\":{\"attributes\":{\"rule_name\":\"r1\"}}}";
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
        Assert.Equal("r1", notification.Data.Attributes.RuleName);
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
        var json = "{\"id\":\"rj1\",\"type\":\"retrohuntJob\",\"data\":{\"attributes\":{\"status\":\"done\"}}}";
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
        var json = "{\"id\":\"rn1\",\"type\":\"retrohuntNotification\",\"data\":{\"attributes\":{\"job_id\":\"j1\"}}}";
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
        var json = "{\"id\":\"mi1\",\"type\":\"monitorItem\",\"data\":{\"attributes\":{\"path\":\"/tmp\"}}}";
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
    public async Task SubmitPrivateFileAsync_PostsToPrivateAnalyses()
    {
        var json = "{\"id\":\"pa\",\"type\":\"privateAnalysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
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
        Assert.True(handler.Request.Headers.Contains("password"));
    }

    [Fact]
    public async Task GetPrivateAnalysisAsync_DeserializesResponse()
    {
        var json = "{\"id\":\"pa\",\"type\":\"privateAnalysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
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
        var first = "{\"data\":[{\"id\":\"n1\",\"type\":\"livehuntNotification\",\"data\":{\"attributes\":{\"rule_name\":\"r1\"}}}],\"meta\":{\"cursor\":\"abc\"}}";
        var second = "{\"data\":[{\"id\":\"n2\",\"type\":\"livehuntNotification\",\"data\":{\"attributes\":{\"rule_name\":\"r2\"}}}]}";
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

        Assert.Equal(2, notifications.Count);
        Assert.Equal("n1", notifications[0].Id);
        Assert.Equal("n2", notifications[1].Id);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Contains("limit=1", handler.Requests[0].RequestUri!.Query);
        Assert.Contains("cursor=abc", handler.Requests[1].RequestUri!.Query);
    }

    [Fact]
    public async Task GetIpAddressReportAsync_DeserializesResponseAndUsesCorrectPath()
    {
        var json = "{\"id\":\"1.1.1.1\",\"type\":\"ipAddress\",\"data\":{\"attributes\":{\"ip_address\":\"1.1.1.1\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var report = await client.GetIpAddressReportAsync("1.1.1.1");

        Assert.NotNull(report);
        Assert.Equal("1.1.1.1", report!.Id);
        Assert.Equal(ResourceType.IpAddress, report.Type);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/ip_addresses/1.1.1.1", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetDomainReportAsync_DeserializesResponseAndUsesCorrectPath()
    {
        var json = "{\"id\":\"example.com\",\"type\":\"domain\",\"data\":{\"attributes\":{\"domain\":\"example.com\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var report = await client.GetDomainReportAsync("example.com");

        Assert.NotNull(report);
        Assert.Equal("example.com", report!.Id);
        Assert.Equal(ResourceType.Domain, report.Type);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/domains/example.com", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetAnalysisAsync_DeserializesResponseAndUsesCorrectPath()
    {
        var json = "{\"id\":\"an1\",\"type\":\"analysis\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var report = await client.GetAnalysisAsync("an1");

        Assert.NotNull(report);
        Assert.Equal("an1", report!.Id);
        Assert.Equal(ResourceType.Analysis, report.Type);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/analyses/an1", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetAnalysisAsync_ThrowsApiException()
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

        var ex = await Assert.ThrowsAsync<ApiException>(() => client.GetAnalysisAsync("an1"));

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/analyses/an1", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("NotFoundError", ex.Error?.Code);
        Assert.Equal("not found", ex.Message);
    }

    [Fact]
    public async Task GetGraphAsync_DeserializesResponseAndUsesCorrectPath()
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

        var graph = await client.GetGraphAsync("g1");

        Assert.NotNull(graph);
        Assert.Equal("g1", graph!.Id);
        Assert.Equal(ResourceType.Graph, graph.Type);
        Assert.Equal("demo", graph.Data.Attributes.Name);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/graphs/g1", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetCollectionAsync_DeserializesResponseAndUsesCorrectPath()
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

        var collection = await client.GetCollectionAsync("c1");

        Assert.NotNull(collection);
        Assert.Equal("c1", collection!.Id);
        Assert.Equal(ResourceType.Collection, collection.Type);
        Assert.Equal("demo", collection.Data.Attributes.Name);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/collections/c1", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetVotesAsync_DeserializesResponseAndUsesCorrectPath()
    {
        var json = "{\"data\":[{\"id\":\"v1\",\"type\":\"vote\",\"data\":{\"attributes\":{\"date\":1,\"verdict\":\"malicious\"}}}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var votes = await client.GetVotesAsync(ResourceType.File, "abc");

        Assert.NotNull(votes);
        Assert.Single(votes!);
        Assert.Equal("v1", votes[0].Id);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/votes", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetFeedAsync_DeserializesResponseAndUsesCorrectPath()
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

        var feed = await client.GetFeedAsync(ResourceType.File);

        Assert.NotNull(feed);
        Assert.Single(feed!.Data);
        Assert.Equal("f1", feed.Data[0].Id);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/feeds/files", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetRelationshipsAsync_DeserializesResponseAndUsesCorrectPath()
    {
        var json = "{\"data\":[{\"id\":\"r1\",\"type\":\"file\"}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var relationships = await client.GetRelationshipsAsync(ResourceType.File, "abc", "comments");

        Assert.NotNull(relationships);
        Assert.Single(relationships!.Data);
        Assert.Equal("r1", relationships.Data[0].Id);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/relationships/comments", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task ReanalyzeFileAsync_UsesFilePath()
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

        var report = await client.ReanalyzeFileAsync("abc");

        Assert.NotNull(report);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/analyse", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task ReanalyzeUrlAsync_UsesUrlPath()
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

        var report = await client.ReanalyzeUrlAsync("def");

        Assert.NotNull(report);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/urls/def/analyse", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task ListRetrohuntJobsAsync_PagesThroughResults()
    {
        var first = "{\"data\":[{\"id\":\"j1\",\"type\":\"retrohuntJob\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}],\"meta\":{\"cursor\":\"abc\"}}";
        var second = "{\"data\":[{\"id\":\"j2\",\"type\":\"retrohuntJob\",\"data\":{\"attributes\":{\"status\":\"done\"}}}]}";
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

        var jobs = await client.ListRetrohuntJobsAsync(limit: 1);

        Assert.Equal(2, jobs.Count);
        Assert.Equal("j1", jobs[0].Id);
        Assert.Equal("j2", jobs[1].Id);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Contains("limit=1", handler.Requests[0].RequestUri!.Query);
        Assert.Contains("cursor=abc", handler.Requests[1].RequestUri!.Query);
    }

    [Fact]
    public async Task GetFileBehaviorAsync_DeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"b1\",\"type\":\"analysis\",\"attributes\":{\"processes\":[{\"name\":\"proc1\"}]}}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var behavior = await client.GetFileBehaviorAsync("abc");

        Assert.NotNull(behavior);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/behavior", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("b1", behavior!.Data[0].Id);
        Assert.Equal("proc1", behavior.Data[0].Attributes.Processes[0].Name);
    }

    [Fact]
    public async Task GetFileBehaviorAsync_ThrowsApiException()
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

        var ex = await Assert.ThrowsAsync<ApiException>(() => client.GetFileBehaviorAsync("abc"));
        Assert.Equal("not found", ex.Message);
        Assert.Equal("NotFoundError", ex.Error?.Code);
    }

    [Fact]
    public async Task GetFileBehaviorSummaryAsync_DeserializesResponse()
    {
        var json = "{\"data\":{\"tags\":[\"network\"]}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var summary = await client.GetFileBehaviorSummaryAsync("abc");

        Assert.NotNull(summary);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/behavior_summary", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Contains("network", summary!.Data.Tags);
    }

    [Fact]
    public async Task GetFileBehaviorSummaryAsync_ThrowsApiException()
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

        await Assert.ThrowsAsync<ApiException>(() => client.GetFileBehaviorSummaryAsync("abc"));
    }

    [Fact]
    public async Task GetFileNetworkTrafficAsync_DeserializesResponse()
    {
        var json = "{\"data\":{\"tcp\":[{\"dst\":\"1.2.3.4\",\"port\":80}]}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var traffic = await client.GetFileNetworkTrafficAsync("abc");

        Assert.NotNull(traffic);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/network-traffic", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("1.2.3.4", traffic!.Data.Tcp[0].Destination);
        Assert.Equal(80, traffic.Data.Tcp[0].Port);
    }

    [Fact]
    public async Task GetFileNetworkTrafficAsync_ThrowsApiException()
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

        await Assert.ThrowsAsync<ApiException>(() => client.GetFileNetworkTrafficAsync("abc"));
    }
}
