using System;
using System.Collections.Generic;
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
    private readonly List<KeyValuePair<string, string>> _fields = new();

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
    /// Adds an additional form field to the multipart content.
    /// </summary>
    public MultipartFormDataBuilder WithFormField(string name, string value)
    {
        if (name is null)
            throw new ArgumentNullException(nameof(name));
        if (value is null)
            throw new ArgumentNullException(nameof(value));
        _fields.Add(new KeyValuePair<string, string>(name, value));
        return this;
    }

    /// <summary>
    /// Builds the <see cref="HttpContent"/> that streams the file with boundaries.
    /// </summary>
    public HttpContent Build()
    {
        var builder = new StringBuilder();
        foreach (var field in _fields)
        {
            builder.Append($"--{Boundary}\r\n");
            builder.Append($"Content-Disposition: form-data; name=\"{field.Key}\"\r\n\r\n");
            builder.Append(field.Value);
            builder.Append("\r\n");
        }
        builder.Append($"--{Boundary}\r\n");
        builder.Append($"Content-Disposition: form-data; name=\"file\"; filename=\"{_fileName}\"\r\n");
        builder.Append("Content-Type: application/octet-stream\r\n\r\n");
        var start = Encoding.UTF8.GetBytes(builder.ToString());
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

