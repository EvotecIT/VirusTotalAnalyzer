using System;
using System.Net;

namespace VirusTotalAnalyzer.Models;

public class ApiException : Exception
{
    public ApiError? Error { get; }
    public HttpStatusCode? StatusCode { get; }
    public string? RequestId { get; }

    public ApiException(ApiError? error, string? message = null)
        : this(error, message, null, null)
    {
    }

    public ApiException(ApiError? error, string? message, HttpStatusCode? statusCode, string? requestId)
        : base(message ?? error?.Message)
    {
        Error = error;
        StatusCode = statusCode;
        RequestId = requestId;
    }
}
