using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer.Tests;

internal sealed class TrackingHandler : HttpMessageHandler
{
    public bool Disposed { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        Disposed = true;
    }
}
