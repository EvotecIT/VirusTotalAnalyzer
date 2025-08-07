using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class MultipartFormDataBuilderTests
{
    [Fact]
    public async Task Build_ReturnsContentWithBoundary()
    {
        using var ms = new NonSeekableStream(Encoding.UTF8.GetBytes("hi"));
        var builder = new MultipartFormDataBuilder(ms, "test.txt");
        using var content = builder.Build();

        var boundaryParam = content.Headers.ContentType!.Parameters.First(p => p.Name == "boundary");
        Assert.Equal(builder.Boundary, boundaryParam.Value);

        var bytes = await content.ReadAsByteArrayAsync();
        var expected = Encoding.UTF8.GetBytes(
            $"--{builder.Boundary}\r\n" +
            "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n" +
            "Content-Type: application/octet-stream\r\n\r\n" +
            "hi\r\n" +
            $"--{builder.Boundary}--\r\n");
        Assert.Equal(expected, bytes);
        Assert.False(ms.CanSeek);
    }

    private sealed class NonSeekableStream : Stream
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
    }
}
