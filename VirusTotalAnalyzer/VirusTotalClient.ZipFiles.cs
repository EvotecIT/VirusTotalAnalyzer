using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

public sealed partial class VirusTotalClient
{
    /// <summary>Starts creation of a password-protected ZIP from files known to VirusTotal.</summary>
    public Task<ZipFile?> CreateZipFileAsync(
        CreateZipFileRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }
        if (request.Data is null || request.Data.Hashes is null ||
            request.Data.Hashes.Count == 0 || request.Data.Hashes.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("At least one non-empty file hash is required.", nameof(request));
        }
        return SendJsonDataAsync<CreateZipFileRequest, ZipFile>(
            HttpMethod.Post,
            "intelligence/zip_files",
            request,
            cancellationToken);
    }

    /// <summary>Gets the current state of a VirusTotal Intelligence ZIP job.</summary>
    public Task<ZipFile?> GetZipFileAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        return GetDataAsync<ZipFile>($"intelligence/zip_files/{Uri.EscapeDataString(id)}", cancellationToken);
    }

    /// <summary>Gets the temporary signed download URL for a completed ZIP job.</summary>
    public async Task<Uri?> GetZipFileDownloadUrlAsync(
        string id,
        CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        ThrowIfDisposed();
        using var response = await _httpClient
            .GetAsync($"intelligence/zip_files/{Uri.EscapeDataString(id)}/download_url", cancellationToken)
            .ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<DownloadUrlResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return result is not null && Uri.TryCreate(result.Data, UriKind.Absolute, out var uri)
            ? ValidateSignedDownloadUri(uri)
            : null;
    }

    /// <summary>Downloads a completed VirusTotal Intelligence ZIP job.</summary>
    public Task<Stream> DownloadZipFileAsync(string id, CancellationToken cancellationToken = default)
    {
        ValidateId(id, nameof(id));
        return DownloadFromAuthenticatedEndpointAsync(
            $"intelligence/zip_files/{Uri.EscapeDataString(id)}/download",
            cancellationToken);
    }
}
