using System;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer;

internal sealed class StreamWithResponse : Stream
#if !NET472
    , IAsyncDisposable
#endif
{
    private readonly HttpResponseMessage _response;
    private readonly Stream _stream;

    public StreamWithResponse(HttpResponseMessage response, Stream stream)
    {
        _response = response ?? throw new ArgumentNullException(nameof(response));
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
    }

    public override bool CanRead => _stream.CanRead;
    public override bool CanSeek => _stream.CanSeek;
    public override bool CanWrite => _stream.CanWrite;
    public override long Length => _stream.Length;
    public override long Position
    {
        get => _stream.Position;
        set => _stream.Position = value;
    }

    public override void Flush() => _stream.Flush();
    public override int Read(byte[] buffer, int offset, int count) => _stream.Read(buffer, offset, count);
    public override long Seek(long offset, SeekOrigin origin) => _stream.Seek(offset, origin);
    public override void SetLength(long value) => _stream.SetLength(value);
    public override void Write(byte[] buffer, int offset, int count) => _stream.Write(buffer, offset, count);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        _stream.ReadAsync(buffer, offset, count, cancellationToken);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        _stream.WriteAsync(buffer, offset, count, cancellationToken);

#if !NET472
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        _stream.ReadAsync(buffer, cancellationToken);

    public override ValueTask DisposeAsync()
    {
        var dispose = _stream.DisposeAsync();
        _response.Dispose();
        return dispose;
    }
#endif

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _stream.Dispose();
            _response.Dispose();
        }
        base.Dispose(disposing);
    }
}
