using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer;

/// <summary>
/// Builds a multipart/form-data <see cref="HttpContent"/> that streams the provided file.
/// </summary>
public sealed class MultipartFormDataBuilder
{
    private readonly Stream _stream;
    private readonly string _fileName;

    public MultipartFormDataBuilder(Stream stream, string fileName)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _fileName = fileName ?? throw new ArgumentNullException(nameof(fileName));
        Boundary = "---------------------------" + Guid.NewGuid().ToString("N");
    }

    /// <summary>
    /// Gets the boundary string used for the multipart content.
    /// </summary>
    public string Boundary { get; }

    /// <summary>
    /// Builds the <see cref="HttpContent"/> that streams the file with boundaries.
    /// </summary>
    public HttpContent Build()
    {
        var start = Encoding.UTF8.GetBytes($"--{Boundary}\r\n" +
            $"Content-Disposition: form-data; name=\"file\"; filename=\"{_fileName}\"\r\n" +
            "Content-Type: application/octet-stream\r\n\r\n");
        var end = Encoding.UTF8.GetBytes($"\r\n--{Boundary}--\r\n");
        return new MultipartStreamContent(_stream, start, end, Boundary);
    }

    private sealed class MultipartStreamContent : HttpContent
    {
        private readonly Stream _file;
        private readonly byte[] _start;
        private readonly byte[] _end;

        public MultipartStreamContent(Stream file, byte[] start, byte[] end, string boundary)
        {
            _file = file;
            _start = start;
            _end = end;
            Headers.ContentType = new MediaTypeHeaderValue("multipart/form-data");
            Headers.ContentType.Parameters.Add(new NameValueHeaderValue("boundary", boundary));
        }

#if NET472
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext context)
            => SerializeToStreamAsync(stream, CancellationToken.None);
#else
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
            => SerializeToStreamAsync(stream, CancellationToken.None);

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken)
            => SerializeToStreamAsync(stream, cancellationToken);
#endif

        private async Task SerializeToStreamAsync(Stream target, CancellationToken cancellationToken)
        {
            await target.WriteAsync(_start, 0, _start.Length, cancellationToken).ConfigureAwait(false);
            await _file.CopyToAsync(target, 81920, cancellationToken).ConfigureAwait(false);
            await target.WriteAsync(_end, 0, _end.Length, cancellationToken).ConfigureAwait(false);
        }

        protected override bool TryComputeLength(out long length)
        {
            if (_file.CanSeek)
            {
                length = _start.Length + (_file.Length - _file.Position) + _end.Length;
                return true;
            }
            length = 0;
            return false;
        }
    }
}

