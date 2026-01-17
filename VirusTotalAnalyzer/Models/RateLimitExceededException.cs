using System;
using System.Net;

namespace VirusTotalAnalyzer.Models;

public sealed class RateLimitExceededException : ApiException
{
    public TimeSpan? RetryAfter { get; }
    public int? RemainingQuota { get; }

    public RateLimitExceededException(ApiError? error, TimeSpan? retryAfter, int? remainingQuota)
        : this(error, retryAfter, remainingQuota, null, null)
    {
    }

    public RateLimitExceededException(ApiError? error, TimeSpan? retryAfter, int? remainingQuota, HttpStatusCode? statusCode, string? requestId)
        : base(error, null, statusCode, requestId)
    {
        RetryAfter = retryAfter;
        RemainingQuota = remainingQuota;
    }
}
