using System;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
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
    public async Task Batch_FailedInFlightFetchDoesNotPoisonLaterCall()
    {
        var notFound = new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent(
                "{\"error\":{\"code\":\"NotFoundError\",\"message\":\"missing\"}}",
                Encoding.UTF8,
                "application/json")
        };
        var handler = new QueueHandler(notFound, FileResponse("abc"));
        using var client = CreateClient(handler);
        var options = ImmediateOptions();
        options.CacheDuration = TimeSpan.Zero;
        options.MaxRetries = 0;

        await Assert.ThrowsAsync<ApiException>(
            () => client.GetFileReportsBatchAsync(new[] { "abc" }, options));
        var reports = await client.GetFileReportsBatchAsync(new[] { "abc" }, options);

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
    public async Task Batch_CoalescesConcurrentCacheMissesEvenWhenCachingIsDisabled()
    {
        var handler = new BlockingFileHandler();
        using var client = CreateClient(handler);
        var options = ImmediateOptions();
        options.CacheDuration = TimeSpan.Zero;

        var first = client.GetFileReportsBatchAsync(new[] { "abc" }, options);
        await handler.Started.Task;
        var second = client.GetFileReportsBatchAsync(new[] { "abc" }, options);
        await Task.Delay(25);
        handler.Release.TrySetResult(true);

        var results = await Task.WhenAll(first, second);

        Assert.Equal(1, handler.RequestCount);
        Assert.Equal("abc", results[0][0].Id);
        Assert.Same(results[0][0], results[1][0]);
    }

    [Fact]
    public async Task Batch_CancelledFollowerDoesNotCancelSharedFetch()
    {
        var handler = new BlockingFileHandler();
        using var client = CreateClient(handler);
        var options = ImmediateOptions();
        options.CacheDuration = TimeSpan.Zero;

        var leader = client.GetFileReportsBatchAsync(new[] { "abc" }, options);
        await handler.Started.Task;
        using var cancellation = new CancellationTokenSource();
        var follower = client.GetFileReportsBatchAsync(new[] { "abc" }, options, cancellationToken: cancellation.Token);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => follower);
        handler.Release.TrySetResult(true);
        var result = await leader;

        Assert.Single(result);
        Assert.Equal(1, handler.RequestCount);
    }

    [Fact]
    public async Task Batch_RetryAfterPausesOtherConcurrentCallers()
    {
        var handler = new SharedRetryHandler();
        using var client = CreateClient(handler);
        var options = ImmediateOptions();
        options.CacheDuration = TimeSpan.Zero;

        var first = client.GetFileReportsBatchAsync(new[] { "first" }, options);
        await handler.RateLimitReturned.Task;
        await Task.Delay(100);
        var second = client.GetFileReportsBatchAsync(new[] { "second" }, options);

        await Task.WhenAll(first, second);

        Assert.Equal(3, handler.RequestCount);
        Assert.True(
            handler.EarliestSuccessfulRequest - handler.FirstRequest >= TimeSpan.FromMilliseconds(700),
            $"First success started after {handler.EarliestSuccessfulRequest - handler.FirstRequest}.");
    }

    [Fact]
    public async Task Batch_ExhaustedRateLimitStillPausesOtherCallers()
    {
        var handler = new SharedRetryHandler();
        using var client = CreateClient(handler);
        var options = ImmediateOptions();
        options.CacheDuration = TimeSpan.Zero;
        options.MaxRetries = 0;

        var rateLimited = client.GetFileReportsBatchAsync(new[] { "first" }, options);
        await handler.RateLimitReturned.Task;
        await Task.Delay(100);
        var other = client.GetFileReportsBatchAsync(new[] { "second" }, options);

        await Assert.ThrowsAsync<RateLimitExceededException>(() => rateLimited);
        var reports = await other;

        Assert.Single(reports);
        Assert.Equal(2, handler.RequestCount);
        Assert.True(
            handler.EarliestSuccessfulRequest - handler.FirstRequest >= TimeSpan.FromMilliseconds(700),
            $"Other caller started after {handler.EarliestSuccessfulRequest - handler.FirstRequest}.");
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

    private static VirusTotalClient CreateClient(HttpMessageHandler handler)
        => new(new HttpClient(handler) { BaseAddress = new Uri("https://www.virustotal.com/api/v3/") });

    private static HttpResponseMessage FileResponse(string id)
        => new(HttpStatusCode.OK)
        {
            Content = new StringContent($"{{\"data\":{{\"id\":\"{id}\",\"type\":\"file\",\"attributes\":{{}}}}}}", Encoding.UTF8, "application/json")
        };

    private sealed class BlockingFileHandler : HttpMessageHandler
    {
        private int _requestCount;

        internal TaskCompletionSource<bool> Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<bool> Release { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int RequestCount => Volatile.Read(ref _requestCount);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _requestCount);
            Started.TrySetResult(true);
            await Release.Task.ConfigureAwait(false);
            return FileResponse("abc");
        }
    }

    private sealed class SharedRetryHandler : HttpMessageHandler
    {
        private readonly object _sync = new();
        private int _requestCount;
        private long _firstRequest;
        private long _earliestSuccessfulRequest = long.MaxValue;

        internal TaskCompletionSource<bool> RateLimitReturned { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int RequestCount => Volatile.Read(ref _requestCount);
        internal TimeSpan FirstRequest => ToElapsed(_firstRequest);
        internal TimeSpan EarliestSuccessfulRequest => ToElapsed(_earliestSuccessfulRequest);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var requestNumber = Interlocked.Increment(ref _requestCount);
            var timestamp = Stopwatch.GetTimestamp();
            if (requestNumber == 1)
            {
                _firstRequest = timestamp;
                var response = new HttpResponseMessage((HttpStatusCode)429)
                {
                    Content = new StringContent(
                        "{\"error\":{\"code\":\"RateLimitExceeded\",\"message\":\"slow down\"}}",
                        Encoding.UTF8,
                        "application/json")
                };
                response.Headers.Add("Retry-After", "1");
                RateLimitReturned.TrySetResult(true);
                return Task.FromResult(response);
            }

            lock (_sync)
            {
                if (timestamp < _earliestSuccessfulRequest)
                    _earliestSuccessfulRequest = timestamp;
            }
            return Task.FromResult(FileResponse(requestNumber.ToString()));
        }

        private static TimeSpan ToElapsed(long timestamp)
            => TimeSpan.FromSeconds((double)timestamp / Stopwatch.Frequency);
    }
}
