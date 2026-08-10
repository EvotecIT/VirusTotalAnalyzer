using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class MonitorUploadTests
{
    [Fact]
    public async Task UploadMonitorFileAsync_StreamsMultipartAndReturnsReceipt()
    {
        const string responseJson = "{\"data\":{\"id\":\"m1\",\"type\":\"monitor_item\",\"attributes\":{\"path\":\"/Product/1.0/app.exe\",\"last_detections_count\":2}}}";
        var handler = new SingleResponseHandler(JsonResponse(responseJson));
        using var httpClient = CreateHttpClient(handler);
        using var client = new VirusTotalClient(httpClient);
        using var source = new TrackingStream(Encoding.UTF8.GetBytes("abc"));

        var result = await client.UploadMonitorFileAsync(
            source,
            "app.exe",
            new MonitorUploadOptions
            {
                Path = "/Product/1.0/app.exe",
                VerifySha256 = false
            });

        Assert.False(source.Disposed);
        Assert.Equal(HttpMethod.Post, handler.Request!.Method);
        Assert.Equal("/api/v3/monitor/items", handler.Request.RequestUri!.AbsolutePath);
        Assert.StartsWith("multipart/form-data; boundary=", handler.Request.Content!.Headers.ContentType!.ToString());
        Assert.Contains("name=\"path\"", handler.Content);
        Assert.Contains("/Product/1.0/app.exe", handler.Content);
        Assert.Contains("filename=\"app.exe\"", handler.Content);
        Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", result.LocalSha256);
        Assert.Equal("m1", result.MonitorId);
        Assert.Equal("/Product/1.0/app.exe", result.RemotePath);
        Assert.Equal(2, result.CurrentDetectionCount);
        Assert.Equal(MonitorUploadDisposition.Created, result.Disposition);
        Assert.Equal(MonitorUploadVerificationStatus.NotRequested, result.VerificationStatus);
    }

    [Fact]
    public async Task UploadMonitorFileAsync_VerifiesRemoteSha256()
    {
        const string sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        var handler = new QueueHandler(
            JsonResponse("{\"data\":{\"id\":\"m1\",\"type\":\"monitor_item\",\"attributes\":{\"path\":\"/app.exe\"}}}"),
            JsonResponse($"{{\"data\":{{\"id\":\"m1\",\"type\":\"monitor_item\",\"attributes\":{{\"path\":\"/app.exe\",\"sha256\":\"{sha256}\"}}}}}}"));
        using var httpClient = CreateHttpClient(handler);
        using var client = new VirusTotalClient(httpClient);
        using var source = new MemoryStream(Encoding.UTF8.GetBytes("abc"));

        var result = await client.UploadMonitorFileAsync(
            source,
            "app.exe",
            new MonitorUploadOptions
            {
                ExistingItemId = "m1",
                VerificationTimeout = TimeSpan.Zero,
                PollingInterval = TimeSpan.FromMilliseconds(1)
            });

        Assert.Equal(MonitorUploadDisposition.Replaced, result.Disposition);
        Assert.Equal(MonitorUploadVerificationStatus.Verified, result.VerificationStatus);
        Assert.Equal(sha256, result.RemoteSha256);
        Assert.Contains("name=\"item\"", handler.Contents[0]);
        Assert.Contains("m1", handler.Contents[0]);
        Assert.Equal("/api/v3/monitor/items/m1", handler.Requests[1].RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task UploadMonitorFileAsync_PreservesUploadReceiptWhenConfigResponseIsSparse()
    {
        const string sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        var handler = new QueueHandler(
            JsonResponse($"{{\"data\":{{\"id\":\"m1\",\"type\":\"monitor_item\",\"attributes\":{{\"path\":\"/app.exe\",\"sha256\":\"{sha256}\",\"last_detections_count\":2}}}}}}"),
            JsonResponse("{\"data\":{\"id\":\"m1\",\"type\":\"monitor_item\",\"attributes\":{\"details\":\"release 1\"}}}"));
        using var httpClient = CreateHttpClient(handler);
        using var client = new VirusTotalClient(httpClient);
        using var source = new MemoryStream(Encoding.UTF8.GetBytes("abc"));

        var result = await client.UploadMonitorFileAsync(
            source,
            "app.exe",
            new MonitorUploadOptions
            {
                Path = "/app.exe",
                Details = "release 1",
                VerificationTimeout = TimeSpan.Zero,
                PollingInterval = TimeSpan.FromMilliseconds(1)
            });

        Assert.Equal(MonitorUploadVerificationStatus.Verified, result.VerificationStatus);
        Assert.Equal("/app.exe", result.RemotePath);
        Assert.Equal(sha256, result.RemoteSha256);
        Assert.Equal(2, result.CurrentDetectionCount);
        Assert.Equal("release 1", result.Item.Attributes.Details);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal("/api/v3/monitor/items/m1/config", handler.Requests[1].RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task UploadMonitorFileAsync_ReplacementWaitsPastPreviousRemoteSha256()
    {
        const string sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        var handler = new QueueHandler(
            JsonResponse("{\"data\":{\"id\":\"m1\",\"type\":\"monitor_item\",\"attributes\":{\"path\":\"/app.exe\",\"sha256\":\"previous\"}}}"),
            JsonResponse($"{{\"data\":{{\"id\":\"m1\",\"type\":\"monitor_item\",\"attributes\":{{\"path\":\"/app.exe\",\"sha256\":\"{sha256}\"}}}}}}"));
        using var httpClient = CreateHttpClient(handler);
        using var client = new VirusTotalClient(httpClient);
        using var source = new MemoryStream(Encoding.UTF8.GetBytes("abc"));

        var result = await client.UploadMonitorFileAsync(
            source,
            "app.exe",
            new MonitorUploadOptions
            {
                ExistingItemId = "m1",
                VerificationTimeout = TimeSpan.FromSeconds(1),
                PollingInterval = TimeSpan.FromMilliseconds(1)
            });

        Assert.Equal(MonitorUploadVerificationStatus.Verified, result.VerificationStatus);
        Assert.Equal(sha256, result.RemoteSha256);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task UploadMonitorFileAsync_HashMismatchFailsClosed()
    {
        var handler = new QueueHandler(
            JsonResponse("{\"data\":{\"id\":\"m1\",\"type\":\"monitor_item\",\"attributes\":{\"path\":\"/app.exe\"}}}"),
            JsonResponse("{\"data\":{\"id\":\"m1\",\"type\":\"monitor_item\",\"attributes\":{\"path\":\"/app.exe\",\"sha256\":\"different\"}}}"));
        using var httpClient = CreateHttpClient(handler);
        using var client = new VirusTotalClient(httpClient);
        using var source = new MemoryStream(Encoding.UTF8.GetBytes("abc"));

        var exception = await Assert.ThrowsAsync<InvalidDataException>(() => client.UploadMonitorFileAsync(
            source,
            "app.exe",
            new MonitorUploadOptions
            {
                Path = "/app.exe",
                VerificationTimeout = TimeSpan.Zero,
                PollingInterval = TimeSpan.FromMilliseconds(1)
            }));

        Assert.Contains("SHA-256 mismatch", exception.Message);
    }

    [Fact]
    public async Task UploadMonitorFileAsync_MissingRemoteSha256TimesOutFailClosed()
    {
        var handler = new QueueHandler(
            JsonResponse("{\"data\":{\"id\":\"m1\",\"type\":\"monitor_item\",\"attributes\":{\"path\":\"/app.exe\"}}}"),
            JsonResponse("{\"data\":{\"id\":\"m1\",\"type\":\"monitor_item\",\"attributes\":{\"path\":\"/app.exe\"}}}"));
        using var httpClient = CreateHttpClient(handler);
        using var client = new VirusTotalClient(httpClient);
        using var source = new MemoryStream(Encoding.UTF8.GetBytes("abc"));

        var exception = await Assert.ThrowsAsync<TimeoutException>(() => client.UploadMonitorFileAsync(
            source,
            "app.exe",
            new MonitorUploadOptions
            {
                Path = "/app.exe",
                VerificationTimeout = TimeSpan.Zero,
                PollingInterval = TimeSpan.FromMilliseconds(1)
            }));

        Assert.Contains("remote SHA-256", exception.Message);
    }

    [Fact]
    public async Task UploadMonitorFileAsync_NonSeekableCallerStreamRemainsOpen()
    {
        var handler = new SingleResponseHandler(JsonResponse(
            "{\"data\":{\"id\":\"m1\",\"type\":\"monitor_item\",\"attributes\":{\"path\":\"/app.exe\"}}}"));
        using var httpClient = CreateHttpClient(handler);
        using var client = new VirusTotalClient(httpClient);
        using var source = new NonSeekableTrackingStream(Encoding.UTF8.GetBytes("abc"));

        var result = await client.UploadMonitorFileAsync(
            source,
            "app.exe",
            new MonitorUploadOptions { Path = "/app.exe", VerifySha256 = false });

        Assert.False(source.WasDisposed);
        Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", result.LocalSha256);
    }

    [Fact]
    public async Task UploadMonitorFileAsync_UsesTrustedLargeFileUploadUrlAbove32Mb()
    {
        var handler = new LargeUploadHandler();
        using var httpClient = CreateHttpClient(handler);
        using var client = new VirusTotalClient(httpClient);
        using var source = new SeekableZeroStream(32L * 1024L * 1024L + 1);

        var result = await client.UploadMonitorFileAsync(
            source,
            "large.bin",
            new MonitorUploadOptions { Path = "/large.bin", VerifySha256 = false });

        Assert.True(result.UsedLargeFileUploadUrl);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal("/api/v3/monitor/items/upload_url", handler.Requests[0].AbsolutePath);
        Assert.Equal("https://uploads.virustotal.com/monitor/upload", handler.Requests[1].AbsoluteUri);
    }

    [Fact]
    public async Task UploadMonitorFileAsync_UpgradesDocumentedHttpUploadUrlToHttps()
    {
        var handler = new LargeUploadHandler("http://www.virustotal.com/_ah/upload/token");
        using var httpClient = CreateHttpClient(handler);
        using var client = new VirusTotalClient(httpClient);
        using var source = new SeekableZeroStream(32L * 1024L * 1024L + 1);

        await client.UploadMonitorFileAsync(
            source,
            "large.bin",
            new MonitorUploadOptions { Path = "/large.bin", VerifySha256 = false });

        Assert.Equal("https://www.virustotal.com/_ah/upload/token", handler.Requests[1].AbsoluteUri);
    }

    private static HttpClient CreateHttpClient(HttpMessageHandler handler) => new(handler)
    {
        BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
    };

    private static HttpResponseMessage JsonResponse(string json) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json")
    };

    private sealed class NonSeekableTrackingStream : Stream
    {
        private readonly MemoryStream _inner;

        public NonSeekableTrackingStream(byte[] data) => _inner = new MemoryStream(data);

        public bool WasDisposed { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
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
                WasDisposed = true;
                _inner.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    private sealed class SeekableZeroStream : Stream
    {
        public SeekableZeroStream(long length) => Length = length;

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length { get; }
        public override long Position { get; set; }
        public override void Flush() { }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var remaining = Length - Position;
            if (remaining <= 0)
            {
                return 0;
            }

            var read = (int)Math.Min(count, remaining);
            Array.Clear(buffer, offset, read);
            Position += read;
            return read;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Read(buffer, offset, count));
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            Position = origin switch
            {
                SeekOrigin.Begin => offset,
                SeekOrigin.Current => Position + offset,
                SeekOrigin.End => Length + offset,
                _ => throw new ArgumentOutOfRangeException(nameof(origin))
            };
            return Position;
        }

        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class LargeUploadHandler : HttpMessageHandler
    {
        private readonly string _uploadUrl;

        public LargeUploadHandler(string uploadUrl = "https://uploads.virustotal.com/monitor/upload")
            => _uploadUrl = uploadUrl;

        public List<Uri> Requests { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri!);
            if (Requests.Count == 1)
            {
                return Task.FromResult(JsonResponse(
                    $"{{\"data\":\"{_uploadUrl}\"}}"));
            }

            return Task.FromResult(JsonResponse(
                "{\"data\":{\"id\":\"large\",\"type\":\"monitor_item\",\"attributes\":{\"path\":\"/large.bin\"}}}"));
        }
    }
}
