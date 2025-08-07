using System;

namespace VirusTotalAnalyzer.Models;

public class ApiException : Exception
{
    public ApiError? Error { get; }

    public ApiException(ApiError? error, string? message = null)
        : base(message ?? error?.Message)
        => Error = error;
}
