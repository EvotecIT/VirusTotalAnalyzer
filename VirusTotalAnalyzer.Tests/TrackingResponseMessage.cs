using System.Net.Http;

namespace VirusTotalAnalyzer.Tests;

internal sealed class TrackingResponseMessage : HttpResponseMessage
{
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
