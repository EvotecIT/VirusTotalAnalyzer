using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer;

internal sealed class PreparedMonitorUpload : IDisposable
{
    private readonly bool _ownsStream;
    private readonly string? _temporaryPath;

    private PreparedMonitorUpload(Stream stream, long length, string sha256, bool ownsStream, string? temporaryPath)
    {
        Stream = stream;
        Length = length;
        Sha256 = sha256;
        _ownsStream = ownsStream;
        _temporaryPath = temporaryPath;
    }

    public Stream Stream { get; }

    public long Length { get; }

    public string Sha256 { get; }

    public static async Task<PreparedMonitorUpload> CreateAsync(
        Stream source,
        CancellationToken cancellationToken)
    {
        if (source.CanSeek)
        {
            var position = source.Position;
            try
            {
                var hash = await ComputeSha256Async(source, cancellationToken).ConfigureAwait(false);
                return new PreparedMonitorUpload(source, source.Length - position, hash, false, null);
            }
            finally
            {
                source.Position = position;
            }
        }

        var temporaryPath = Path.GetTempFileName();
        try
        {
            string hash;
            using (var destination = new FileStream(
                temporaryPath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                81920,
                useAsync: true))
            using (var algorithm = SHA256.Create())
            using (var crypto = new CryptoStream(destination, algorithm, CryptoStreamMode.Write))
            {
                await source.CopyToAsync(crypto, 81920, cancellationToken).ConfigureAwait(false);
                crypto.FlushFinalBlock();
                hash = ToLowerHex(algorithm.Hash!);
            }

            var uploadStream = new FileStream(
                temporaryPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                81920,
                useAsync: true);
            return new PreparedMonitorUpload(uploadStream, uploadStream.Length, hash, true, temporaryPath);
        }
        catch
        {
            TryDelete(temporaryPath);
            throw;
        }
    }

    public void Dispose()
    {
        if (_ownsStream)
        {
            Stream.Dispose();
        }
        if (_temporaryPath is not null)
        {
            TryDelete(_temporaryPath);
        }
    }

    private static async Task<string> ComputeSha256Async(Stream stream, CancellationToken cancellationToken)
    {
        using var algorithm = SHA256.Create();
        var buffer = ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                algorithm.TransformBlock(buffer, 0, read, null, 0);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        algorithm.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return ToLowerHex(algorithm.Hash!);
    }

    private static string ToLowerHex(byte[] value)
#if NET472
        => BitConverter.ToString(value).Replace("-", string.Empty).ToLowerInvariant();
#else
        => Convert.ToHexString(value).ToLowerInvariant();
#endif

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch
        {
            // Cleanup is best effort. The upload result or primary exception is more important.
        }
    }
}
