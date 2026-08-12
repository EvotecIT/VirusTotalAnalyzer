using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

public sealed partial class VirusTotalClient
{
    private readonly Dictionary<string, BatchCacheEntry> _batchCache = new(StringComparer.Ordinal);
    private readonly object _batchCacheSync = new();
    private readonly Dictionary<string, BatchInFlightEntry> _batchInFlight = new(StringComparer.Ordinal);
    private readonly object _batchInFlightSync = new();
    private readonly SemaphoreSlim _batchRequestGate = new(1, 1);
    private long _batchFetchGeneration;
    private long _lastBatchRequestTimestamp;
    private long _nextBatchRequestTimestamp;

    /// <summary>Retrieves file reports with quota-aware spacing, retry, cache, and duplicate suppression.</summary>
    public Task<IReadOnlyList<FileReport>> GetFileReportsBatchAsync(
        IEnumerable<string> ids,
        VirusTotalBatchOptions? options = null,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        var selectedFields = fields?.ToArray();
        var selectedRelationships = relationships?.ToArray();
        return GetManyBatchAsync(
            ids,
            (id, token) => GetFileReportAsync(id, selectedFields, selectedRelationships, token),
            "file",
            NormalizeCaseInsensitiveId,
            selectedFields,
            selectedRelationships,
            options,
            nameof(ids),
            cancellationToken);
    }

    /// <summary>Retrieves URL reports with quota-aware spacing, retry, cache, and duplicate suppression.</summary>
    public Task<IReadOnlyList<UrlReport>> GetUrlReportsBatchAsync(
        IEnumerable<string> ids,
        VirusTotalBatchOptions? options = null,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        var selectedFields = fields?.ToArray();
        var selectedRelationships = relationships?.ToArray();
        return GetManyBatchAsync(
            ids,
            (id, token) => GetUrlReportAsync(id, selectedFields, selectedRelationships, token),
            "url",
            id => id,
            selectedFields,
            selectedRelationships,
            options,
            nameof(ids),
            cancellationToken);
    }

    /// <summary>Retrieves IP address reports with quota-aware spacing, retry, cache, and duplicate suppression.</summary>
    public Task<IReadOnlyList<IpAddressReport>> GetIpAddressReportsBatchAsync(
        IEnumerable<string> ids,
        VirusTotalBatchOptions? options = null,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        var selectedFields = fields?.ToArray();
        var selectedRelationships = relationships?.ToArray();
        return GetManyBatchAsync(
            ids,
            (id, token) => GetIpAddressReportAsync(id, selectedFields, selectedRelationships, token),
            "ip_address",
            NormalizeCaseInsensitiveId,
            selectedFields,
            selectedRelationships,
            options,
            nameof(ids),
            cancellationToken);
    }

    /// <summary>Retrieves domain reports with quota-aware spacing, retry, cache, and duplicate suppression.</summary>
    public Task<IReadOnlyList<DomainReport>> GetDomainReportsBatchAsync(
        IEnumerable<string> ids,
        VirusTotalBatchOptions? options = null,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? relationships = null,
        CancellationToken cancellationToken = default)
    {
        var selectedFields = fields?.ToArray();
        var selectedRelationships = relationships?.ToArray();
        return GetManyBatchAsync(
            ids,
            (id, token) => GetDomainReportAsync(id, selectedFields, selectedRelationships, token),
            "domain",
            NormalizeCaseInsensitiveId,
            selectedFields,
            selectedRelationships,
            options,
            nameof(ids),
            cancellationToken);
    }

    /// <summary>Retrieves analysis reports with quota-aware spacing, retry, cache, and duplicate suppression.</summary>
    public Task<IReadOnlyList<AnalysisReport>> GetAnalysesBatchAsync(
        IEnumerable<string> ids,
        VirusTotalBatchOptions? options = null,
        CancellationToken cancellationToken = default)
        => GetManyBatchAsync(
            ids,
            (id, token) => GetAnalysisAsync(id, token),
            "analysis",
            id => id,
            null,
            null,
            options,
            nameof(ids),
            cancellationToken);

    private static string NormalizeCaseInsensitiveId(string id) => id.ToLowerInvariant();

    private static string[] ValidateIds(IEnumerable<string> ids, string paramName)
    {
        if (ids == null)
            throw new ArgumentNullException(paramName);

        var array = ids as string[] ?? ids.ToArray();
        if (array.Length == 0)
            throw new ArgumentException("The collection must not be empty.", paramName);

        for (var i = 0; i < array.Length; i++)
        {
            if (string.IsNullOrWhiteSpace(array[i]))
                throw new ArgumentException("The collection cannot contain null, empty, or whitespace ids.", paramName);
        }

        return array;
    }

    private static async Task<IReadOnlyList<T>> GetManyAsync<T>(
        IEnumerable<string> ids,
        Func<string, CancellationToken, Task<T?>> fetch,
        string paramName,
        CancellationToken cancellationToken)
        where T : class
    {
        var idArray = ValidateIds(ids, paramName);
        var results = new List<T>(idArray.Length);
        foreach (var id in idArray)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = await fetch(id, cancellationToken).ConfigureAwait(false);
            if (result is not null)
                results.Add(result);
        }
        return results;
    }

    private async Task<IReadOnlyList<T>> GetManyBatchAsync<T>(
        IEnumerable<string> ids,
        Func<string, CancellationToken, Task<T?>> fetch,
        string resource,
        Func<string, string> normalizeId,
        IEnumerable<string>? fields,
        IEnumerable<string>? relationships,
        VirusTotalBatchOptions? options,
        string paramName,
        CancellationToken cancellationToken)
        where T : class
    {
        var suppliedOptions = options ?? new VirusTotalBatchOptions();
        var effectiveOptions = new VirusTotalBatchOptions
        {
            MinimumInterval = suppliedOptions.MinimumInterval,
            CacheDuration = suppliedOptions.CacheDuration,
            MaxRetries = suppliedOptions.MaxRetries
        };
        effectiveOptions.Validate();
        var idArray = ValidateIds(ids, paramName);
        PruneExpiredBatchCache();
        var results = new List<T>(idArray.Length);
        var currentBatch = new Dictionary<string, T?>(StringComparer.Ordinal);

        foreach (var id in idArray)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var normalizedId = normalizeId(id);
            var cacheKey = CreateCacheKey(resource, normalizedId, fields, relationships);
            if (!currentBatch.TryGetValue(cacheKey, out var result))
            {
                if (!TryGetCached(cacheKey, effectiveOptions.CacheDuration, out result))
                {
                    result = await GetOrFetchBatchResultAsync(
                            cacheKey,
                            fetch,
                            id,
                            effectiveOptions,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                currentBatch.Add(cacheKey, result);
            }

            if (result is not null)
                results.Add(result);
        }

        return results;
    }

    private async Task<T?> GetOrFetchBatchResultAsync<T>(
        string cacheKey,
        Func<string, CancellationToken, Task<T?>> fetch,
        string id,
        VirusTotalBatchOptions options,
        CancellationToken cancellationToken)
        where T : class
    {
        var inFlightKey = CreateInFlightKey(cacheKey, options);
        BatchInFlightEntry shared;
        long waiterId;
        var created = false;
        lock (_batchInFlightSync)
        {
            // Cache publication happens before a completed entry is removed, and
            // removal requires this coordination lock. Recheck here so a caller that
            // missed the optimistic lookup cannot fall through the handoff gap
            // and start a duplicate request after the producer has completed.
            if (TryGetCached(cacheKey, options.CacheDuration, out T? cached))
                return cached;

            if (!_batchInFlight.TryGetValue(inFlightKey, out shared!) ||
                !shared.TryAddWaiter(options.CacheDuration, out waiterId))
            {
                var generation = Interlocked.Increment(ref _batchFetchGeneration);
                shared = new BatchInFlightEntry(
                    async token => (object?)await FetchWithBatchPolicyAsync(fetch, id, options, token)
                        .ConfigureAwait(false),
                    (value, duration) => SetCached(cacheKey, value, duration, generation),
                    generation);
                if (!shared.TryAddWaiter(options.CacheDuration, out waiterId))
                    throw new InvalidOperationException("Unable to register a batch fetch waiter.");
                _batchInFlight[inFlightKey] = shared;
                created = true;
            }
        }

        var task = shared.Task;
        using var waiterCancellation = cancellationToken.Register(
            () => shared.ReleaseWaiter(waiterId));
        if (created)
        {
            _ = task.ContinueWith(
                completed => CompleteBatchFetch(inFlightKey, shared, completed),
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }

        try
        {
            var value = await AwaitSharedBatchFetchAsync(task, cancellationToken).ConfigureAwait(false);
            var result = value as T;
            SetCached(cacheKey, result, options.CacheDuration, shared.Generation);
            return result;
        }
        finally
        {
            if (shared.ReleaseWaiter(waiterId))
                RemoveBatchFetch(inFlightKey, shared);
        }
    }

    private void CompleteBatchFetch(string inFlightKey, BatchInFlightEntry entry, Task<object?> task)
    {
        if (task.IsFaulted)
            _ = task.Exception;
        RemoveBatchFetch(inFlightKey, entry);
    }

    private void RemoveBatchFetch(string inFlightKey, BatchInFlightEntry entry)
    {
        lock (_batchInFlightSync)
        {
            if (_batchInFlight.TryGetValue(inFlightKey, out var current) && ReferenceEquals(current, entry))
                _batchInFlight.Remove(inFlightKey);
        }
    }

    private static async Task<object?> AwaitSharedBatchFetchAsync(
        Task<object?> task,
        CancellationToken cancellationToken)
    {
        if (!cancellationToken.CanBeCanceled || task.IsCompleted)
            return await task.ConfigureAwait(false);

        var cancellation = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using (cancellationToken.Register(
                   state => ((TaskCompletionSource<bool>)state!).TrySetResult(true),
                   cancellation))
        {
            if (task != await Task.WhenAny(task, cancellation.Task).ConfigureAwait(false))
                throw new OperationCanceledException(cancellationToken);
        }

        return await task.ConfigureAwait(false);
    }

    private async Task<T?> FetchWithBatchPolicyAsync<T>(
        Func<string, CancellationToken, Task<T?>> fetch,
        string id,
        VirusTotalBatchOptions options,
        CancellationToken cancellationToken)
        where T : class
    {
        for (var attempt = 0; ; attempt++)
        {
            await WaitForBatchRequestSlotAsync(options.MinimumInterval, cancellationToken).ConfigureAwait(false);
            try
            {
                return await fetch(id, cancellationToken).ConfigureAwait(false);
            }
            catch (RateLimitExceededException exception)
            {
                var fallbackDelay = options.MinimumInterval > TimeSpan.Zero
                    ? options.MinimumInterval
                    : TimeSpan.FromSeconds(20);
                var retryDelay = exception.RetryAfter.GetValueOrDefault(fallbackDelay);
                if (retryDelay < TimeSpan.Zero)
                    retryDelay = TimeSpan.Zero;
                await ApplySharedRetryDelayAsync(retryDelay).ConfigureAwait(false);
                if (attempt >= options.MaxRetries)
                    throw;
            }
        }
    }

    private async Task ApplySharedRetryDelayAsync(TimeSpan retryDelay)
    {
        await _batchRequestGate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            var now = Stopwatch.GetTimestamp();
            var retryTicksDouble = retryDelay <= TimeSpan.Zero
                ? 0d
                : Math.Ceiling(retryDelay.TotalSeconds * Stopwatch.Frequency);
            var retryTicks = retryTicksDouble >= long.MaxValue ? long.MaxValue : (long)retryTicksDouble;
            var retryTimestamp = retryTicks >= long.MaxValue - now ? long.MaxValue : now + retryTicks;
            if (retryTimestamp > _nextBatchRequestTimestamp)
                _nextBatchRequestTimestamp = retryTimestamp;
        }
        finally
        {
            _batchRequestGate.Release();
        }
    }

    private async Task WaitForBatchRequestSlotAsync(TimeSpan minimumInterval, CancellationToken cancellationToken)
    {
        while (true)
        {
            TimeSpan delay;
            await _batchRequestGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var now = Stopwatch.GetTimestamp();
                var intervalTicks = minimumInterval <= TimeSpan.Zero
                    ? 0L
                    : checked((long)Math.Ceiling(minimumInterval.TotalSeconds * Stopwatch.Frequency));
                var intervalTimestamp = intervalTicks >= long.MaxValue - _lastBatchRequestTimestamp
                    ? long.MaxValue
                    : _lastBatchRequestTimestamp + intervalTicks;
                var requiredTimestamp = _nextBatchRequestTimestamp > intervalTimestamp
                    ? _nextBatchRequestTimestamp
                    : intervalTimestamp;
                var remainingTicks = requiredTimestamp - now;
                if (remainingTicks <= 0)
                {
                    _lastBatchRequestTimestamp = now;
                    return;
                }

                delay = TimeSpan.FromSeconds((double)remainingTicks / Stopwatch.Frequency);
            }
            finally
            {
                _batchRequestGate.Release();
            }

            await DelaySafelyAsync(delay, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task DelaySafelyAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        var maximumSlice = TimeSpan.FromMilliseconds(int.MaxValue - 1d);
        while (delay > TimeSpan.Zero)
        {
            var slice = delay > maximumSlice ? maximumSlice : delay;
            await Task.Delay(slice, cancellationToken).ConfigureAwait(false);
            delay -= slice;
        }
    }

    private bool TryGetCached<T>(string key, TimeSpan cacheDuration, out T? value)
        where T : class
    {
        value = null;
        if (cacheDuration <= TimeSpan.Zero)
            return false;

        lock (_batchCacheSync)
        {
            if (!_batchCache.TryGetValue(key, out var cached))
                return false;

            var callerExpiration = cached.CreatedAt.Add(cacheDuration);
            var effectiveExpiration = callerExpiration < cached.ExpiresAt
                ? callerExpiration
                : cached.ExpiresAt;
            if (effectiveExpiration <= DateTimeOffset.UtcNow)
            {
                if (cached.ExpiresAt <= DateTimeOffset.UtcNow)
                    _batchCache.Remove(key);
                return false;
            }

            value = cached.Value as T;
            return cached.Value is null || value is not null;
        }
    }

    private void SetCached<T>(string key, T? value, TimeSpan cacheDuration, long generation)
        where T : class
    {
        if (cacheDuration <= TimeSpan.Zero)
            return;

        var now = DateTimeOffset.UtcNow;
        lock (_batchCacheSync)
        {
            if (_batchCache.TryGetValue(key, out var current))
            {
                if (current.Generation > generation)
                    return;
                if (current.Generation == generation)
                {
                    var requestedExpiration = current.CreatedAt.Add(cacheDuration);
                    if (requestedExpiration > current.ExpiresAt)
                        _batchCache[key] = new BatchCacheEntry(
                            value,
                            current.CreatedAt,
                            requestedExpiration,
                            generation);
                    return;
                }
            }

            _batchCache[key] = new BatchCacheEntry(value, now, now.Add(cacheDuration), generation);
        }
    }

    private void PruneExpiredBatchCache()
    {
        lock (_batchCacheSync)
        {
            var now = DateTimeOffset.UtcNow;
            var expiredKeys = _batchCache
                .Where(pair => pair.Value.ExpiresAt <= now)
                .Select(pair => pair.Key)
                .ToArray();
            foreach (var key in expiredKeys)
                _batchCache.Remove(key);
        }
    }

    private static string CreateInFlightKey(string cacheKey, VirusTotalBatchOptions options)
    {
        var key = new StringBuilder();
        AppendCacheComponent(key, cacheKey);
        AppendCacheComponent(key, options.MinimumInterval.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture));
        AppendCacheComponent(key, options.MaxRetries.ToString(System.Globalization.CultureInfo.InvariantCulture));
        return key.ToString();
    }

    private static string CreateCacheKey(
        string resource,
        string id,
        IEnumerable<string>? fields,
        IEnumerable<string>? relationships)
    {
        var key = new StringBuilder();
        AppendCacheComponent(key, resource);
        AppendCacheComponent(key, id);
        AppendCacheSequence(key, fields);
        AppendCacheSequence(key, relationships);
        return key.ToString();
    }

    private static void AppendCacheSequence(StringBuilder key, IEnumerable<string>? values)
    {
        var array = values?.OrderBy(value => value, StringComparer.Ordinal).ToArray() ?? Array.Empty<string>();
        key.Append(array.Length).Append(':');
        foreach (var value in array)
            AppendCacheComponent(key, value);
    }

    private static void AppendCacheComponent(StringBuilder key, string value)
        => key.Append(value.Length).Append(':').Append(value);

    private sealed class BatchCacheEntry
    {
        internal BatchCacheEntry(
            object? value,
            DateTimeOffset createdAt,
            DateTimeOffset expiresAt,
            long generation)
        {
            Value = value;
            CreatedAt = createdAt;
            ExpiresAt = expiresAt;
            Generation = generation;
        }

        internal object? Value { get; }
        internal DateTimeOffset CreatedAt { get; }
        internal DateTimeOffset ExpiresAt { get; }
        internal long Generation { get; }
    }

    private sealed class BatchInFlightEntry
    {
        private readonly CancellationTokenSource _cancellation = new();
        private readonly Action<object?, TimeSpan> _cacheResult;
        private readonly Dictionary<long, TimeSpan> _waiterCacheDurations = new();
        private readonly object _sync = new();
        private readonly Lazy<Task<object?>> _task;
        private bool _acceptingWaiters = true;
        private bool _completed;
        private long _nextWaiterId;

        internal BatchInFlightEntry(
            Func<CancellationToken, Task<object?>> fetch,
            Action<object?, TimeSpan> cacheResult,
            long generation)
        {
            _cacheResult = cacheResult;
            Generation = generation;
            _task = new Lazy<Task<object?>>(
                () => ExecuteAsync(fetch),
                LazyThreadSafetyMode.ExecutionAndPublication);
        }

        internal Task<object?> Task => _task.Value;
        internal long Generation { get; }

        internal bool TryAddWaiter(TimeSpan cacheDuration, out long waiterId)
        {
            lock (_sync)
            {
                if (!_acceptingWaiters)
                {
                    waiterId = 0;
                    return false;
                }
                waiterId = ++_nextWaiterId;
                _waiterCacheDurations.Add(waiterId, cacheDuration);
                return true;
            }
        }

        internal bool ReleaseWaiter(long waiterId)
        {
            var cancel = false;
            lock (_sync)
            {
                if (!_waiterCacheDurations.Remove(waiterId))
                    return false;
                if (_waiterCacheDurations.Count == 0 && !_completed)
                {
                    _acceptingWaiters = false;
                    cancel = true;
                }
            }

            if (cancel)
                _cancellation.Cancel();
            return cancel;
        }

        private async Task<object?> ExecuteAsync(Func<CancellationToken, Task<object?>> fetch)
        {
            try
            {
                var result = await fetch(_cancellation.Token).ConfigureAwait(false);
                lock (_sync)
                {
                    _completed = true;
                    var maximumCacheDuration = TimeSpan.Zero;
                    foreach (var cacheDuration in _waiterCacheDurations.Values)
                    {
                        if (cacheDuration > maximumCacheDuration)
                            maximumCacheDuration = cacheDuration;
                    }
                    _cacheResult(result, maximumCacheDuration);
                }
                return result;
            }
            catch
            {
                lock (_sync)
                    _completed = true;
                throw;
            }
        }
    }
}
