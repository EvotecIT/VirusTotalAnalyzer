using System;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public sealed class VirusTotalClientBatchTests
{
    [Fact]
    public async Task Batch_DeduplicatesRequestsButPreservesDuplicateOutput()
    {
        var handler = new QueueHandler(FileResponse("ABC"));
        using var client = CreateClient(handler);
        var options = ImmediateOptions();

        var reports = await client.GetFileReportsBatchAsync(new[] { "ABC", "abc" }, options);

        Assert.Equal(2, reports.Count);
        Assert.Same(reports[0], reports[1]);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task Batch_ReusesSuccessfulResponseAcrossCalls()
    {
        var handler = new QueueHandler(FileResponse("abc"));
        using var client = CreateClient(handler);
        var options = ImmediateOptions();

        var first = await client.GetFileReportsBatchAsync(new[] { "abc" }, options);
        var second = await client.GetFileReportsBatchAsync(new[] { "abc" }, options);

        Assert.Single(first);
        Assert.Single(second);
        Assert.Same(first[0], second[0]);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task Batch_RetriesRateLimitUsingServerDelay()
    {
        var rateLimit = new HttpResponseMessage((HttpStatusCode)429)
        {
            Content = new StringContent("{\"error\":{\"code\":\"RateLimitExceeded\",\"message\":\"slow down\"}}", Encoding.UTF8, "application/json")
        };
        rateLimit.Headers.Add("Retry-After", "0");
        var handler = new QueueHandler(rateLimit, FileResponse("abc"));
        using var client = CreateClient(handler);

        var reports = await client.GetFileReportsBatchAsync(new[] { "abc" }, ImmediateOptions());

        Assert.Single(reports);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task Batch_SpacesRequestStarts()
    {
        var handler = new QueueHandler(FileResponse("a"), FileResponse("b"));
        using var client = CreateClient(handler);
        var options = ImmediateOptions();
        options.MinimumInterval = TimeSpan.FromMilliseconds(40);

        var stopwatch = Stopwatch.StartNew();
        var reports = await client.GetFileReportsBatchAsync(new[] { "a", "b" }, options);
        stopwatch.Stop();

        Assert.Equal(2, reports.Count);
        Assert.True(stopwatch.Elapsed >= TimeSpan.FromMilliseconds(25), $"Elapsed: {stopwatch.Elapsed}");
    }

    [Fact]
    public void Verdict_PreservesReportAndSummarizesStats()
    {
        var report = new FileReport
        {
            Id = "abc",
            Attributes = new FileAttributes
            {
                Reputation = -5,
                LastAnalysisDate = DateTimeOffset.FromUnixTimeSeconds(100),
                LastAnalysisStats = new AnalysisStats { Malicious = 2, Suspicious = 1, Harmless = 4 }
            }
        };

        var verdict = report.ToVerdict();

        Assert.Equal(VirusTotalVerdictKind.Malicious, verdict.Verdict);
        Assert.Equal(7, verdict.Total);
        Assert.Equal(-5, verdict.Reputation);
        Assert.Equal("https://www.virustotal.com/gui/file/abc", verdict.Permalink!.AbsoluteUri.TrimEnd('/'));
        Assert.Same(report, verdict.Report);
    }

    [Fact]
    public void Verdict_DistinguishesUndetectedFromMissingStats()
    {
        var report = new DomainReport
        {
            Id = "example.com",
            Attributes = new DomainAttributes
            {
                LastAnalysisStats = new AnalysisStats { Undetected = 70 }
            }
        };

        Assert.Equal(VirusTotalVerdictKind.Undetected, report.ToVerdict().Verdict);
    }

    [Fact]
    public async Task Verdict_IncludesConfirmedTimeoutFromJson()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                "{\"data\":{\"id\":\"abc\",\"type\":\"file\",\"attributes\":{\"last_analysis_stats\":{\"harmless\":4,\"confirmed-timeout\":2}}}}",
                Encoding.UTF8,
                "application/json")
        };
        var handler = new QueueHandler(response);
        using var client = CreateClient(handler);

        var reports = await client.GetFileReportsBatchAsync(new[] { "abc" }, ImmediateOptions());
        var verdict = reports[0].ToVerdict();

        Assert.Equal(2, verdict.ConfirmedTimeout);
        Assert.Equal(6, verdict.Total);
    }

    private static VirusTotalBatchOptions ImmediateOptions()
        => new() { MinimumInterval = TimeSpan.Zero, CacheDuration = TimeSpan.FromMinutes(1), MaxRetries = 1 };

    private static VirusTotalClient CreateClient(QueueHandler handler)
        => new(new HttpClient(handler) { BaseAddress = new Uri("https://www.virustotal.com/api/v3/") });

    private static HttpResponseMessage FileResponse(string id)
        => new(HttpStatusCode.OK)
        {
            Content = new StringContent($"{{\"data\":{{\"id\":\"{id}\",\"type\":\"file\",\"attributes\":{{}}}}}}", Encoding.UTF8, "application/json")
        };
}
