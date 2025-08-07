using System;

namespace VirusTotalAnalyzer.Models;

public sealed class RateLimitExceededException : ApiException
{
    public TimeSpan? RetryAfter { get; }
    public int? RemainingQuota { get; }

    public RateLimitExceededException(ApiError? error, TimeSpan? retryAfter, int? remainingQuota)
        : base(error)
    {
        RetryAfter = retryAfter;
        RemainingQuota = remainingQuota;
    }
}
