using System;
using System.Collections.Concurrent;
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
    private readonly ConcurrentDictionary<string, BatchCacheEntry> _batchCache = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _batchRequestGate = new(1, 1);
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
                    result = await FetchWithBatchPolicyAsync(fetch, id, effectiveOptions, cancellationToken)
                        .ConfigureAwait(false);
                    SetCached(cacheKey, result, effectiveOptions.CacheDuration);
                }
                currentBatch.Add(cacheKey, result);
            }

            if (result is not null)
                results.Add(result);
        }

        return results;
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
            catch (RateLimitExceededException exception) when (attempt < options.MaxRetries)
            {
                var fallbackDelay = options.MinimumInterval > TimeSpan.Zero
                    ? options.MinimumInterval
                    : TimeSpan.FromSeconds(20);
                var retryDelay = exception.RetryAfter.GetValueOrDefault(fallbackDelay);
                if (retryDelay < TimeSpan.Zero)
                    retryDelay = TimeSpan.Zero;
                await DelaySafelyAsync(retryDelay, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task WaitForBatchRequestSlotAsync(TimeSpan minimumInterval, CancellationToken cancellationToken)
    {
        await _batchRequestGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var now = Stopwatch.GetTimestamp();
            var remainingTicks = _nextBatchRequestTimestamp - now;
            if (remainingTicks > 0)
            {
                var delay = TimeSpan.FromSeconds((double)remainingTicks / Stopwatch.Frequency);
                await DelaySafelyAsync(delay, cancellationToken).ConfigureAwait(false);
                now = Stopwatch.GetTimestamp();
            }

            var intervalTicks = minimumInterval <= TimeSpan.Zero
                ? 0L
                : checked((long)Math.Ceiling(minimumInterval.TotalSeconds * Stopwatch.Frequency));
            _nextBatchRequestTimestamp = checked(now + intervalTicks);
        }
        finally
        {
            _batchRequestGate.Release();
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
        if (cacheDuration <= TimeSpan.Zero || !_batchCache.TryGetValue(key, out var cached))
            return false;

        if (cached.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            _batchCache.TryRemove(key, out _);
            return false;
        }

        value = cached.Value as T;
        return cached.Value is null || value is not null;
    }

    private void SetCached<T>(string key, T? value, TimeSpan cacheDuration)
        where T : class
    {
        if (cacheDuration <= TimeSpan.Zero)
            return;

        _batchCache[key] = new BatchCacheEntry(value, DateTimeOffset.UtcNow.Add(cacheDuration));
    }

    private void PruneExpiredBatchCache()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var pair in _batchCache)
        {
            if (pair.Value.ExpiresAt <= now)
                _batchCache.TryRemove(pair.Key, out _);
        }
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
        internal BatchCacheEntry(object? value, DateTimeOffset expiresAt)
        {
            Value = value;
            ExpiresAt = expiresAt;
        }

        internal object? Value { get; }
        internal DateTimeOffset ExpiresAt { get; }
    }
}
