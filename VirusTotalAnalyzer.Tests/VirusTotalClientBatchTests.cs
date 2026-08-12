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
    public async Task Batch_FinalCancelledWaiterCancelsFetchAndAllowsLaterRetry()
    {
        var handler = new CancellationThenSuccessHandler();
        using var client = CreateClient(handler);
        var options = ImmediateOptions();
        options.CacheDuration = TimeSpan.Zero;
        using var cancellation = new CancellationTokenSource();

        var cancelled = client.GetFileReportsBatchAsync(
            new[] { "abc" },
            options,
            cancellationToken: cancellation.Token);
        await handler.Started.Task;
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        await handler.Cancelled.Task;
        var reports = await client.GetFileReportsBatchAsync(new[] { "abc" }, options);

        Assert.Single(reports);
        Assert.Equal(2, handler.RequestCount);
    }

    [Fact]
    public async Task Batch_DifferentRetryPoliciesDoNotShareAnInFlightOperation()
    {
        var handler = new PolicyHandler();
        using var client = CreateClient(handler);
        var noRetry = ImmediateOptions();
        noRetry.CacheDuration = TimeSpan.Zero;
        noRetry.MaxRetries = 0;
        var retry = ImmediateOptions();
        retry.CacheDuration = TimeSpan.Zero;

        var first = client.GetFileReportsBatchAsync(new[] { "abc" }, noRetry);
        await handler.FirstStarted.Task;
        var second = client.GetFileReportsBatchAsync(new[] { "abc" }, retry);
        await Task.Delay(25);
        handler.ReleaseFirst.TrySetResult(true);

        await Assert.ThrowsAsync<RateLimitExceededException>(() => first);
        var reports = await second;

        Assert.Single(reports);
        Assert.Equal(2, handler.RequestCount);
    }

    [Fact]
    public async Task Batch_CoalescedCallersApplyTheirOwnCacheDuration()
    {
        var handler = new BlockingFileHandler();
        using var client = CreateClient(handler);
        var noCache = ImmediateOptions();
        noCache.CacheDuration = TimeSpan.Zero;
        var cached = ImmediateOptions();
        cached.CacheDuration = TimeSpan.FromMinutes(1);

        var first = client.GetFileReportsBatchAsync(new[] { "abc" }, noCache);
        await handler.Started.Task;
        var second = client.GetFileReportsBatchAsync(new[] { "abc" }, cached);
        await Task.Delay(25);
        handler.Release.TrySetResult(true);
        await Task.WhenAll(first, second);
        var third = await client.GetFileReportsBatchAsync(new[] { "abc" }, cached);

        Assert.Single(third);
        Assert.Equal(1, handler.RequestCount);
    }

    [Fact]
    public async Task Batch_CallerCacheDurationLimitsOlderSharedEntries()
    {
        var handler = new QueueHandler(FileResponse("old"), FileResponse("new"));
        using var client = CreateClient(handler);
        var longCache = ImmediateOptions();
        longCache.CacheDuration = TimeSpan.FromMinutes(5);
        var shortCache = ImmediateOptions();
        shortCache.CacheDuration = TimeSpan.FromMilliseconds(10);

        await client.GetFileReportsBatchAsync(new[] { "abc" }, longCache);
        await Task.Delay(30);
        var refreshed = await client.GetFileReportsBatchAsync(new[] { "abc" }, shortCache);

        Assert.Equal("new", refreshed[0].Id);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task Batch_OlderPolicyFetchCannotOverwriteNewerCacheValue()
    {
        var handler = new OutOfOrderHandler();
        using var client = CreateClient(handler);
        var olderPolicy = ImmediateOptions();
        olderPolicy.MaxRetries = 0;
        var newerPolicy = ImmediateOptions();
        newerPolicy.MaxRetries = 1;

        var older = client.GetFileReportsBatchAsync(new[] { "abc" }, olderPolicy);
        await handler.FirstStarted.Task;
        var newer = await client.GetFileReportsBatchAsync(new[] { "abc" }, newerPolicy);
        handler.ReleaseFirst.TrySetResult(true);
        var olderResult = await older;
        var cached = await client.GetFileReportsBatchAsync(new[] { "abc" }, newerPolicy);

        Assert.Equal("new", newer[0].Id);
        Assert.Equal("old", olderResult[0].Id);
        Assert.Equal("new", cached[0].Id);
        Assert.Equal(2, handler.RequestCount);
    }

    [Fact]
    public async Task Batch_RefreshedNullResultUsesNewFetchGeneration()
    {
        var nullResponse = "{\"data\":null}";
        var handler = new QueueHandler(
            JsonResponse(nullResponse),
            JsonResponse(nullResponse),
            JsonResponse(nullResponse));
        using var client = CreateClient(handler);
        var longCache = ImmediateOptions();
        longCache.CacheDuration = TimeSpan.FromMinutes(5);
        var shortCache = ImmediateOptions();
        shortCache.CacheDuration = TimeSpan.FromMilliseconds(20);

        Assert.Empty(await client.GetFileReportsBatchAsync(new[] { "abc" }, longCache));
        await Task.Delay(40);
        Assert.Empty(await client.GetFileReportsBatchAsync(new[] { "abc" }, shortCache));
        Assert.Empty(await client.GetFileReportsBatchAsync(new[] { "abc" }, shortCache));

        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task Batch_CancelledLastWaiterStillPublishesObservedRetryAfter()
    {
        var handler = new DelayedRateLimitHandler();
        using var client = CreateClient(handler);
        var options = ImmediateOptions();
        options.CacheDuration = TimeSpan.Zero;
        using var cancellation = new CancellationTokenSource();

        var cancelled = client.GetFileReportsBatchAsync(
            new[] { "first" },
            options,
            cancellationToken: cancellation.Token);
        await handler.FirstStarted.Task;
        cancellation.Cancel();
        handler.ReleaseRateLimit.TrySetResult(true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        await Task.Delay(100);
        var other = await client.GetFileReportsBatchAsync(new[] { "second" }, options);

        Assert.Single(other);
        Assert.True(
            handler.SuccessfulRequest - handler.FirstRequest >= TimeSpan.FromMilliseconds(800),
            $"Later caller started after {handler.SuccessfulRequest - handler.FirstRequest}.");
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
    public async Task Batch_RetryAfterCanAdvanceScheduleWhileAnotherCallerWaits()
    {
        var handler = new DelayedRateLimitHandler();
        using var client = CreateClient(handler);
        var options = ImmediateOptions();
        options.MinimumInterval = TimeSpan.FromMilliseconds(300);
        options.CacheDuration = TimeSpan.Zero;
        options.MaxRetries = 0;

        var rateLimited = client.GetFileReportsBatchAsync(new[] { "first" }, options);
        await handler.FirstStarted.Task;
        var other = client.GetFileReportsBatchAsync(new[] { "second" }, options);
        await Task.Delay(50);
        handler.ReleaseRateLimit.TrySetResult(true);

        await Assert.ThrowsAsync<RateLimitExceededException>(() => rateLimited);
        var reports = await other;

        Assert.Single(reports);
        Assert.True(
            handler.SuccessfulRequest - handler.FirstRequest >= TimeSpan.FromMilliseconds(800),
            $"Waiting caller started after {handler.SuccessfulRequest - handler.FirstRequest}.");
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

    private static HttpResponseMessage JsonResponse(string json)
        => new(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
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

    private sealed class CancellationThenSuccessHandler : HttpMessageHandler
    {
        private int _requestCount;

        internal TaskCompletionSource<bool> Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<bool> Cancelled { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int RequestCount => Volatile.Read(ref _requestCount);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var requestNumber = Interlocked.Increment(ref _requestCount);
            if (requestNumber == 1)
            {
                Started.TrySetResult(true);
                try
                {
                    await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    Cancelled.TrySetResult(true);
                    throw;
                }
            }

            return FileResponse("abc");
        }
    }

    private sealed class PolicyHandler : HttpMessageHandler
    {
        private int _requestCount;

        internal TaskCompletionSource<bool> FirstStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<bool> ReleaseFirst { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int RequestCount => Volatile.Read(ref _requestCount);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var requestNumber = Interlocked.Increment(ref _requestCount);
            if (requestNumber == 1)
            {
                FirstStarted.TrySetResult(true);
                await ReleaseFirst.Task.ConfigureAwait(false);
                var response = new HttpResponseMessage((HttpStatusCode)429)
                {
                    Content = new StringContent(
                        "{\"error\":{\"code\":\"RateLimitExceeded\",\"message\":\"slow down\"}}",
                        Encoding.UTF8,
                        "application/json")
                };
                response.Headers.Add("Retry-After", "0");
                return response;
            }

            return FileResponse("abc");
        }
    }

    private sealed class DelayedRateLimitHandler : HttpMessageHandler
    {
        private int _requestCount;
        private long _firstRequest;
        private long _successfulRequest;

        internal TaskCompletionSource<bool> FirstStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<bool> ReleaseRateLimit { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TimeSpan FirstRequest => ToElapsed(_firstRequest);
        internal TimeSpan SuccessfulRequest => ToElapsed(_successfulRequest);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var requestNumber = Interlocked.Increment(ref _requestCount);
            if (requestNumber == 1)
            {
                _firstRequest = Stopwatch.GetTimestamp();
                FirstStarted.TrySetResult(true);
                await ReleaseRateLimit.Task.ConfigureAwait(false);
                var response = new HttpResponseMessage((HttpStatusCode)429)
                {
                    Content = new StringContent(
                        "{\"error\":{\"code\":\"RateLimitExceeded\",\"message\":\"slow down\"}}",
                        Encoding.UTF8,
                        "application/json")
                };
                response.Headers.Add("Retry-After", "1");
                return response;
            }

            _successfulRequest = Stopwatch.GetTimestamp();
            return FileResponse("second");
        }

        private static TimeSpan ToElapsed(long timestamp)
            => TimeSpan.FromSeconds((double)timestamp / Stopwatch.Frequency);
    }

    private sealed class OutOfOrderHandler : HttpMessageHandler
    {
        private int _requestCount;

        internal TaskCompletionSource<bool> FirstStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<bool> ReleaseFirst { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int RequestCount => Volatile.Read(ref _requestCount);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var requestNumber = Interlocked.Increment(ref _requestCount);
            if (requestNumber == 1)
            {
                FirstStarted.TrySetResult(true);
                await ReleaseFirst.Task.ConfigureAwait(false);
                return FileResponse("old");
            }

            return FileResponse("new");
        }
    }
}
