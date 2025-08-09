using System.IO;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer.Tests;

internal sealed class TrackingStream : MemoryStream
{
    public bool Disposed { get; private set; }

    public TrackingStream(byte[] buffer) : base(buffer) { }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            Disposed = true;
        }
        base.Dispose(disposing);
    }

#if !NETFRAMEWORK
    public override ValueTask DisposeAsync()
    {
        Disposed = true;
        return base.DisposeAsync();
    }
#endif
}
