using System;

namespace VirusTotalAnalyzer;

/// <summary>Controls quota-aware VirusTotal batch requests.</summary>
public sealed class VirusTotalBatchOptions
{
    /// <summary>
    /// Gets or sets the minimum interval between request starts. The default of 20 seconds
    /// stays within the public API's four-requests-per-minute guidance.
    /// </summary>
    public TimeSpan MinimumInterval { get; set; } = TimeSpan.FromSeconds(20);

    /// <summary>Gets or sets how long successful report responses remain in the client cache.</summary>
    public TimeSpan CacheDuration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Gets or sets the maximum number of retries after a rate-limit response.</summary>
    public int MaxRetries { get; set; } = 3;

    internal void Validate()
    {
        if (MinimumInterval < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(MinimumInterval), "MinimumInterval cannot be negative.");
        if (MinimumInterval > TimeSpan.FromDays(1))
            throw new ArgumentOutOfRangeException(nameof(MinimumInterval), "MinimumInterval cannot exceed one day.");
        if (CacheDuration < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(CacheDuration), "CacheDuration cannot be negative.");
        if (CacheDuration > TimeSpan.FromDays(365))
            throw new ArgumentOutOfRangeException(nameof(CacheDuration), "CacheDuration cannot exceed 365 days.");
        if (MaxRetries < 0)
            throw new ArgumentOutOfRangeException(nameof(MaxRetries), "MaxRetries cannot be negative.");
    }
}
