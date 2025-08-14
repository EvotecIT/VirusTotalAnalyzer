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
    public async Task ListRetrohuntNotificationsAsync_PagesThroughResults()
    {
        var first = "{\"data\":[{\"id\":\"n1\",\"type\":\"retrohunt_notification\",\"data\":{\"attributes\":{\"job_id\":\"j1\"}}}],\"meta\":{\"cursor\":\"abc\"}}";
        var second = "{\"data\":[{\"id\":\"n2\",\"type\":\"retrohunt_notification\",\"data\":{\"attributes\":{\"job_id\":\"j2\"}}}]}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(first, Encoding.UTF8, "application/json") },
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(second, Encoding.UTF8, "application/json") });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var notifications = await client.ListRetrohuntNotificationsAsync(limit: 1);

        Assert.Equal(2, notifications.Data.Count);
        Assert.Null(notifications.NextCursor);
        Assert.Equal("n1", notifications.Data[0].Id);
        Assert.Equal("n2", notifications.Data[1].Id);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Contains("limit=1", handler.Requests[0].RequestUri!.Query);
        Assert.Contains("cursor=abc", handler.Requests[1].RequestUri!.Query);
    }

    [Fact]
    public async Task ListRetrohuntNotificationsAsync_SinglePage()
    {
        var first = "{\"data\":[{\"id\":\"n1\",\"type\":\"retrohunt_notification\",\"data\":{\"attributes\":{\"job_id\":\"j1\"}}}],\"meta\":{\"cursor\":\"abc\"}}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(first, Encoding.UTF8, "application/json") });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var page = await client.ListRetrohuntNotificationsAsync(limit: 1, fetchAll: false);

        Assert.Single(page.Data);
        Assert.Equal("n1", page.Data[0].Id);
        Assert.Equal("abc", page.NextCursor);
        Assert.Single(handler.Requests);
        Assert.Contains("limit=1", handler.Requests[0].RequestUri!.Query);
    }

    [Fact]
    public async Task GetIpAddressReportAsync_DeserializesResponseAndUsesCorrectPath()
    {
        var json = "{\"data\":{\"id\":\"1.1.1.1\",\"type\":\"ip_address\",\"attributes\":{\"ip_address\":\"1.1.1.1\"}}}";
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
    public async Task GetIpAddressReportAsync_AppendsFieldsAndRelationships()
    {
        var json = "{\"data\":{\"id\":\"1.1.1.1\",\"type\":\"ip_address\"}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.GetIpAddressReportAsync(
            "1.1.1.1",
            fields: new[] { "last_analysis_stats" },
            relationships: new[] { "resolutions" });

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/ip_addresses/1.1.1.1", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal(
            "fields=last_analysis_stats&relationships=resolutions",
            handler.Request!.RequestUri!.Query.TrimStart('?'));
    }

    [Fact]
    public async Task GetDomainReportAsync_DeserializesResponseAndUsesCorrectPath()
    {
        var json = "{\"data\":{\"id\":\"example.com\",\"type\":\"domain\",\"attributes\":{\"domain\":\"example.com\"}}}";
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
    public async Task GetDomainReportAsync_AppendsFieldsAndRelationships()
    {
        var json = "{\"data\":{\"id\":\"example.com\",\"type\":\"domain\"}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.GetDomainReportAsync(
            "example.com",
            fields: new[] { "last_analysis_stats" },
            relationships: new[] { "siblings" });

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/domains/example.com", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal(
            "fields=last_analysis_stats&relationships=siblings",
            handler.Request!.RequestUri!.Query.TrimStart('?'));
    }

    [Fact]
    public async Task GetDomainWhoisAsync_DeserializesResponseAndUsesCorrectPath()
    {
        var json = "{\"id\":\"example.com\",\"type\":\"domain\",\"data\":{\"attributes\":{\"whois\":\"domain whois\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var whois = await client.GetDomainWhoisAsync("example.com");

        Assert.NotNull(whois);
        Assert.Equal("example.com", whois!.Id);
        Assert.Equal(ResourceType.Domain, whois.Type);
        Assert.Equal("domain whois", whois.Data.Attributes.Whois);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/domains/example.com/whois", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetIpAddressWhoisAsync_DeserializesResponseAndUsesCorrectPath()
    {
        var json = "{\"id\":\"1.1.1.1\",\"type\":\"ip_address\",\"data\":{\"attributes\":{\"whois\":\"ip whois\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var whois = await client.GetIpAddressWhoisAsync("1.1.1.1");

        Assert.NotNull(whois);
        Assert.Equal("1.1.1.1", whois!.Id);
        Assert.Equal(ResourceType.IpAddress, whois.Type);
        Assert.Equal("ip whois", whois.Data.Attributes.Whois);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/ip_addresses/1.1.1.1/whois", handler.Request!.RequestUri!.AbsolutePath);
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
        var json = "{\"data\":[{\"id\":\"v1\",\"type\":\"vote\",\"data\":{\"attributes\":{\"date\":1,\"verdict\":\"malicious\"}}}],\"meta\":{}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var page = await client.GetVotesAsync(ResourceType.File, "abc");

        Assert.NotNull(page);
        Assert.Single(page!.Data);
        Assert.Equal("v1", page.Data[0].Id);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/votes", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetVotesAsync_PaginatesThroughResults()
    {
        var first = "{\"data\":[{\"id\":\"v1\",\"type\":\"vote\",\"data\":{\"attributes\":{\"date\":1,\"verdict\":\"malicious\"}}}],\"meta\":{\"cursor\":\"abc\"}}";
        var second = "{\"data\":[{\"id\":\"v2\",\"type\":\"vote\",\"data\":{\"attributes\":{\"date\":2,\"verdict\":\"harmless\"}}}]}";
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

        var page1 = await client.GetVotesAsync(ResourceType.File, "abc", limit: 1);
        var page2 = await client.GetVotesAsync(ResourceType.File, "abc", cursor: page1!.Meta!.Cursor);

        Assert.Equal("v1", page1!.Data[0].Id);
        Assert.Equal("v2", page2!.Data[0].Id);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Contains("limit=1", handler.Requests[0].RequestUri!.Query);
        Assert.Contains("cursor=abc", handler.Requests[1].RequestUri!.Query);
    }

    [Fact]
    public async Task GetVoteAsync_DeserializesResponseAndUsesCorrectPath()
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

        var vote = await client.GetVoteAsync("v1");

        Assert.NotNull(vote);
        Assert.Equal("v1", vote!.Id);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/votes/v1", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetVoteAsync_ThrowsApiException()
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

        var ex = await Assert.ThrowsAsync<ApiException>(() => client.GetVoteAsync("v1"));
        Assert.Equal("not found", ex.Message);
        Assert.Equal("NotFoundError", ex.Error?.Code);
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
    public async Task GetFeedAsync_FileBehaviour_DeserializesResponseAndUsesCorrectPath()
    {
        var json = "{\"data\":[{\"id\":\"b1\",\"type\":\"file\"}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var feed = await client.GetFeedAsync(ResourceType.FileBehaviour);

        Assert.NotNull(feed);
        Assert.Single(feed!.Data);
        Assert.Equal("b1", feed.Data[0].Id);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/feeds/file-behaviour", handler.Request!.RequestUri!.AbsolutePath);
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
        Assert.Equal(string.Empty, handler.Request!.RequestUri!.Query);
    }

    [Fact]
    public async Task GetRelationshipsAsync_BuildsQueryWithLimitAndCursor()
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

        await client.GetRelationshipsAsync(ResourceType.File, "abc", "comments", limit: 10, cursor: "abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/relationships/comments", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("limit=10&cursor=abc", handler.Request!.RequestUri!.Query.TrimStart('?'));
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
        var first = "{\"data\":[{\"id\":\"j1\",\"type\":\"retrohunt_job\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}],\"meta\":{\"cursor\":\"abc\"}}";
        var second = "{\"data\":[{\"id\":\"j2\",\"type\":\"retrohunt_job\",\"data\":{\"attributes\":{\"status\":\"done\"}}}]}";
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

        Assert.Equal(2, jobs.Data.Count);
        Assert.Null(jobs.NextCursor);
        Assert.Equal("j1", jobs.Data[0].Id);
        Assert.Equal("j2", jobs.Data[1].Id);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Contains("limit=1", handler.Requests[0].RequestUri!.Query);
        Assert.Contains("cursor=abc", handler.Requests[1].RequestUri!.Query);
    }

    [Fact]
    public async Task ListRetrohuntJobsAsync_SinglePage()
    {
        var first = "{\"data\":[{\"id\":\"j1\",\"type\":\"retrohunt_job\",\"data\":{\"attributes\":{\"status\":\"queued\"}}}],\"meta\":{\"cursor\":\"abc\"}}";
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

        var page = await client.ListRetrohuntJobsAsync(limit: 1, fetchAll: false);

        Assert.Single(page.Data);
        Assert.Equal("j1", page.Data[0].Id);
        Assert.Equal("abc", page.NextCursor);
        Assert.Single(handler.Requests);
        Assert.Contains("limit=1", handler.Requests[0].RequestUri!.Query);
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

    [Fact]
    public async Task GetFilePeInfoAsync_DeserializesResponseAndUsesCorrectPath()
    {
        var json = "{\"data\":{\"attributes\":{\"imphash\":\"abcd\",\"machine_type\":\"x86\",\"sections\":[{\"name\":\".text\"}]}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var info = await client.GetFilePeInfoAsync("abc");

        Assert.NotNull(info);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/pe_info", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("abcd", info!.Data.Attributes.Imphash);
        Assert.Equal("x86", info.Data.Attributes.MachineType);
        Assert.Single(info.Data.Attributes.Sections);
        Assert.Equal(".text", info.Data.Attributes.Sections[0].Name);
    }

    [Fact]
    public async Task GetFilePeInfoAsync_ThrowsApiException()
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

        await Assert.ThrowsAsync<ApiException>(() => client.GetFilePeInfoAsync("abc"));
    }

    [Fact]
    public async Task GetFileClassificationAsync_DeserializesResponseAndUsesCorrectPath()
    {
        var json = "{\"data\":{\"id\":\"f1\",\"type\":\"file\",\"attributes\":{\"popular_threat_name\":\"Trojan\",\"popular_threat_category\":\"malware\",\"suggested_threat_label\":\"malicious\"}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var classification = await client.GetFileClassificationAsync("abc");

        Assert.NotNull(classification);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/classification", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("Trojan", classification!.Data.Attributes.PopularThreatName);
        Assert.Equal("malware", classification.Data.Attributes.PopularThreatCategory);
        Assert.Equal("malicious", classification.Data.Attributes.SuggestedThreatLabel);
    }

    [Fact]
    public async Task GetFileStringsAsync_DeserializesResponseAndUsesCorrectPath()
    {
        var json = "{\"data\":[\"s1\",\"s2\"]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var strings = await client.GetFileStringsAsync("abc");

        Assert.NotNull(strings);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/strings", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal(new[] { "s1", "s2" }, strings);
    }

    [Fact]
    public async Task GetFileStringsAsync_ThrowsApiException()
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

        await Assert.ThrowsAsync<ApiException>(() => client.GetFileStringsAsync("abc"));
    }

    [Fact]
    public async Task GetFileNamesAsync_DeserializesResponseAndUsesCorrectPath()
    {
        var json = "{\"data\":[{\"id\":\"a.exe\",\"type\":\"file_name\",\"attributes\":{\"date\":1672444800}}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var (names, cursor) = await client.GetFileNamesAsync("abc");

        Assert.NotNull(names);
        Assert.Null(cursor);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/names", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("a.exe", names[0].Id);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1672444800), names[0].Attributes.Date);
    }

    [Fact]
    public async Task GetFileNamesAsync_ThrowsApiException()
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

        var ex = await Assert.ThrowsAsync<ApiException>(() => client.GetFileNamesAsync("abc"));
        Assert.Equal("NotFoundError", ex.Error?.Code);
        Assert.Equal("not found", ex.Message);
    }

    [Fact]
    public async Task GetFileNamesAsync_PagesThroughResults()
    {
        var first = "{\"data\":[{\"id\":\"a.exe\",\"type\":\"file_name\",\"attributes\":{\"date\":1}}],\"meta\":{\"cursor\":\"c1\"}}";
        var second = "{\"data\":[{\"id\":\"b.exe\",\"type\":\"file_name\",\"attributes\":{\"date\":2}}]}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(first, Encoding.UTF8, "application/json") },
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(second, Encoding.UTF8, "application/json") });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var (names, cursor) = await client.GetFileNamesAsync("abc");

        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal("/api/v3/files/abc/names", handler.Requests[0].RequestUri!.PathAndQuery);
        Assert.Equal("/api/v3/files/abc/names?cursor=c1", handler.Requests[1].RequestUri!.PathAndQuery);
        Assert.Collection(names,
            n => Assert.Equal("a.exe", n.Id),
            n => Assert.Equal("b.exe", n.Id));
        Assert.Null(cursor);
    }

    [Fact]
    public async Task GetFileNamesAsync_RespectsLimit()
    {
        var first = "{\"data\":[{\"id\":\"a.exe\",\"type\":\"file_name\",\"attributes\":{\"date\":1}}],\"meta\":{\"cursor\":\"c1\"}}";
        var second = "{\"data\":[{\"id\":\"b.exe\",\"type\":\"file_name\",\"attributes\":{\"date\":2}}]}";
        var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(first, Encoding.UTF8, "application/json") },
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(second, Encoding.UTF8, "application/json") });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var (names, cursor) = await client.GetFileNamesAsync("abc", limit: 1);

        Assert.Single(names);
        Assert.Equal("a.exe", names[0].Id);
        Assert.Equal("c1", cursor);
        Assert.Single(handler.Requests);
        Assert.Equal("/api/v3/files/abc/names?limit=1", handler.Requests[0].RequestUri!.PathAndQuery);
    }
}
