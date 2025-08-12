using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer.Tests;

internal sealed class NonSeekableStream : Stream
{
    private readonly Stream _inner;

    public NonSeekableStream(byte[] data) => _inner = new MemoryStream(data);

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _inner.Length;
    public override long Position
    {
        get => _inner.Position;
        set => throw new NotSupportedException();
    }

    public override void Flush() => _inner.Flush();
    public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _inner.ReadAsync(buffer, offset, count, cancellationToken);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _inner.Dispose();
        }
        base.Dispose(disposing);
    }

#if !NETFRAMEWORK
    public override ValueTask DisposeAsync()
    {
        return _inner.DisposeAsync();
    }
#endif
}
