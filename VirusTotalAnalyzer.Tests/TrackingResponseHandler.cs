using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer.Tests;

internal sealed class TrackingResponseHandler : HttpMessageHandler
{
    private readonly HttpStatusCode _statusCode;
    private readonly Func<HttpContent> _contentFactory;

    public TrackingHttpResponseMessage? LastResponse { get; private set; }

    public TrackingResponseHandler(HttpStatusCode statusCode, Func<HttpContent>? contentFactory = null)
    {
        _statusCode = statusCode;
        _contentFactory = contentFactory ?? (() => new ByteArrayContent(Array.Empty<byte>()));
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = new TrackingHttpResponseMessage(_statusCode)
        {
            Content = _contentFactory()
        };
        LastResponse = response;
        return Task.FromResult<HttpResponseMessage>(response);
    }
}

internal sealed class TrackingHttpResponseMessage : HttpResponseMessage
{
    public TrackingHttpResponseMessage(HttpStatusCode statusCode)
        : base(statusCode)
    {
    }

    public bool Disposed { get; private set; }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            Disposed = true;
        }
        base.Dispose(disposing);
    }
}
