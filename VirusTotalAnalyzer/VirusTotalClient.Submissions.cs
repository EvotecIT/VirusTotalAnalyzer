using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

public sealed partial class VirusTotalClient
{
    public async Task<Uri?> GetUploadUrlAsync(CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync("files/upload_url", cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        var result = await JsonSerializer.DeserializeAsync<UploadUrlResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        if (result is null || string.IsNullOrEmpty(result.Data))
        {
            return null;
        }
        return new Uri(result.Data);
    }

    /// <summary>
    /// Submits a file for analysis.
    /// </summary>
    /// <param name="stream">The file stream to upload.</param>
    /// <param name="fileName">The name of the file.</param>
    /// <param name="password">Optional password for the file; sent via the <c>x-virustotal-password</c> header.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the operation.</param>
    /// <returns>An <see cref="AnalysisReport"/> for the submitted file or <see langword="null"/> if the response is empty.</returns>
    public async Task<AnalysisReport?> SubmitFileAsync(Stream stream, string fileName, string? password = null, CancellationToken cancellationToken = default)
    {

        Stream uploadStream = stream;
        bool disposeUploadStream = false;
        if (!stream.CanSeek)
        {
            var buffer = new MemoryStream();
            await stream.CopyToAsync(buffer, 81920, cancellationToken).ConfigureAwait(false);
            buffer.Position = 0;
            uploadStream = buffer;
            disposeUploadStream = true;
        }

        string requestUrl = "files";
        if (uploadStream.CanSeek && uploadStream.Length > 33554432)
        {
            var uploadUrl = await GetUploadUrlAsync(cancellationToken).ConfigureAwait(false);
            if (uploadUrl is null)
            {
                if (disposeUploadStream)
                {
                    uploadStream.Dispose();
                }
                throw new InvalidOperationException("Upload URL was not provided by the API.");
            }
            requestUrl = uploadUrl.ToString();
        }

        var builder = new MultipartFormDataBuilder(uploadStream, fileName);
        using var content = builder.Build();
        using var request = new HttpRequestMessage(HttpMethod.Post, requestUrl)
        {
            Content = content
        };
        if (!string.IsNullOrEmpty(password))
        {
            request.Headers.Add("x-virustotal-password", password);
        }
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var respStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var respStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        try
        {
            return await JsonSerializer.DeserializeAsync<AnalysisReport>(respStream, _jsonOptions, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            if (disposeUploadStream)
            {
                uploadStream.Dispose();
            }
        }
    }

    public Task<AnalysisReport?> SubmitFileAsync(Stream stream, string fileName, CancellationToken cancellationToken)
        => SubmitFileAsync(stream, fileName, null, cancellationToken);

    /// <summary>
    /// Submits a private file for analysis.
    /// </summary>
    /// <param name="stream">The file stream to upload.</param>
    /// <param name="fileName">The name of the file.</param>
    /// <param name="password">Optional password for the file; sent via the <c>x-virustotal-password</c> header.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the operation.</param>
    /// <returns>A <see cref="PrivateAnalysis"/> describing the analysis.</returns>
    public async Task<PrivateAnalysis?> SubmitPrivateFileAsync(
        Stream stream,
        string fileName,
        string? password = null,
        CancellationToken cancellationToken = default)
    {
        var builder = new MultipartFormDataBuilder(stream, fileName);
        using var content = builder.Build();
        using var request = new HttpRequestMessage(HttpMethod.Post, "private/analyses")
        {
            Content = content
        };
        if (!string.IsNullOrEmpty(password))
        {
            request.Headers.Add("x-virustotal-password", password);
        }
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var respStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var respStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<PrivateAnalysis>(respStream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }


    public async Task<AnalysisReport?> ReanalyzeHashAsync(string hash, AnalysisType analysisType = AnalysisType.File, CancellationToken cancellationToken = default)
    {
        var path = $"{GetPath(analysisType)}/{hash}/analyse";
        using var response = await _httpClient.PostAsync(path, content: null, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<AnalysisReport>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public Task<AnalysisReport?> ReanalyzeFileAsync(string hash, CancellationToken cancellationToken = default)
        => ReanalyzeHashAsync(hash, AnalysisType.File, cancellationToken);

    public Task<AnalysisReport?> ReanalyzeUrlAsync(string id, CancellationToken cancellationToken = default)
        => ReanalyzeHashAsync(id, AnalysisType.Url, cancellationToken);

    public async Task<AnalysisReport?> SubmitUrlAsync(string url, AnalysisType analysisType = AnalysisType.Url, CancellationToken cancellationToken = default)
    {
        if (analysisType != AnalysisType.Url)
        {
            throw new ArgumentOutOfRangeException(nameof(analysisType));
        }
        using var content = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("url", url) });
        using var response = await _httpClient.PostAsync("urls", content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
#if NET472
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        return await JsonSerializer.DeserializeAsync<AnalysisReport>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public Task<AnalysisReport?> SubmitUrlAsync(string url, CancellationToken cancellationToken = default)
        => SubmitUrlAsync(url, AnalysisType.Url, cancellationToken);
}
