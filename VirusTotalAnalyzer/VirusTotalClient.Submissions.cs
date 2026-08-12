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
    public Task<Uri?> GetUploadUrlAsync(CancellationToken cancellationToken = default)
        => GetUploadUrlCoreAsync("files/upload_url", cancellationToken);

    /// <summary>Gets a single-use large-file upload URL for VirusTotal Private Scanning.</summary>
    public Task<Uri?> GetPrivateUploadUrlAsync(CancellationToken cancellationToken = default)
        => GetUploadUrlCoreAsync("private/files/upload_url", cancellationToken);

    private async Task<Uri?> GetUploadUrlCoreAsync(string path, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        using var response = await _httpClient.GetAsync(path, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<UploadUrlResponse>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        if (result is null || string.IsNullOrEmpty(result.Data))
        {
            return null;
        }

        return TryNormalizeVirusTotalUploadUri(result.Data, out var uri) ? uri : null;
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
        if (stream is null)
        {
            throw new ArgumentNullException(nameof(stream));
        }
        if (fileName is null)
        {
            throw new ArgumentNullException(nameof(fileName));
        }
        if (fileName.Length == 0)
        {
            throw new ArgumentException("File name must not be empty.", nameof(fileName));
        }

        ThrowIfDisposed();
        using var prepared = await PreparedUpload.CreateAsync(stream, cancellationToken).ConfigureAwait(false);
        string requestUrl = "files";
        if (prepared.Length > 33554432)
        {
            var uploadUrl = await GetUploadUrlAsync(cancellationToken).ConfigureAwait(false);
            if (uploadUrl is null)
            {
                throw new InvalidOperationException("Upload URL was not provided by the API.");
            }
            requestUrl = uploadUrl.ToString();
        }

        var builder = new MultipartFormDataBuilder(prepared.Stream, fileName);
        using var content = builder.Build();
        using var request = new HttpRequestMessage(HttpMethod.Post, requestUrl) { Content = content };
        if (!string.IsNullOrEmpty(password))
        {
            request.Headers.Add("x-virustotal-password", password);
        }
        using var response = await _httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var respStream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<AnalysisReport>(respStream, cancellationToken).ConfigureAwait(false);
    }

    public Task<AnalysisReport?> SubmitFileAsync(Stream stream, string fileName, CancellationToken cancellationToken)
    {
        if (stream is null)
        {
            throw new ArgumentNullException(nameof(stream));
        }
        if (fileName is null)
        {
            throw new ArgumentNullException(nameof(fileName));
        }
        if (fileName.Length == 0)
        {
            throw new ArgumentException("File name must not be empty.", nameof(fileName));
        }
        return SubmitFileAsync(stream, fileName, null, cancellationToken);
    }

    /// <summary>
    /// Submits a private file for analysis.
    /// </summary>
    /// <param name="stream">The file stream to upload.</param>
    /// <param name="fileName">The name of the file.</param>
    /// <param name="options">Private Scanning sandbox, retention, storage, locale, and archive options.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the operation.</param>
    /// <returns>A <see cref="PrivateAnalysis"/> describing the analysis.</returns>
    public async Task<PrivateAnalysis?> SubmitPrivateFileAsync(
        Stream stream,
        string fileName,
        PrivateFileUploadOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (stream is null)
        {
            throw new ArgumentNullException(nameof(stream));
        }
        if (fileName is null)
        {
            throw new ArgumentNullException(nameof(fileName));
        }
        if (fileName.Length == 0)
        {
            throw new ArgumentException("File name must not be empty.", nameof(fileName));
        }
        options ??= new PrivateFileUploadOptions();
        options.Validate();
        ThrowIfDisposed();
        using var prepared = await PreparedUpload.CreateAsync(stream, cancellationToken).ConfigureAwait(false);
        string requestUrl = "private/files";
        if (prepared.Length > 33554432)
        {
            var uploadUrl = await GetPrivateUploadUrlAsync(cancellationToken).ConfigureAwait(false);
            if (uploadUrl is null)
            {
                throw new InvalidOperationException("Private upload URL was not provided by the API.");
            }
            requestUrl = uploadUrl.ToString();
        }

        var builder = new MultipartFormDataBuilder(prepared.Stream, fileName);
        options.AddFormFields(builder);
        using var content = builder.Build();
        using var request = new HttpRequestMessage(HttpMethod.Post, requestUrl)
        {
            Content = content
        };
        using var response = await _httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var respStream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<PrivateAnalysis>(respStream, cancellationToken).ConfigureAwait(false);
    }


    public async Task<AnalysisReport?> ReanalyzeHashAsync(string hash, AnalysisType analysisType = AnalysisType.File, CancellationToken cancellationToken = default)
    {
        if (hash is null)
        {
            throw new ArgumentNullException(nameof(hash));
        }
        if (hash.Length == 0)
        {
            throw new ArgumentException("Hash must not be empty.", nameof(hash));
        }
        var path = $"{GetPath(analysisType)}/{Uri.EscapeDataString(hash)}/analyse";
        using var response = await _httpClient.PostAsync(path, content: null, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<AnalysisReport>(stream, cancellationToken).ConfigureAwait(false);
    }

    public Task<AnalysisReport?> ReanalyzeFileAsync(string hash, CancellationToken cancellationToken = default)
    {
        if (hash is null)
        {
            throw new ArgumentNullException(nameof(hash));
        }
        if (hash.Length == 0)
        {
            throw new ArgumentException("Hash must not be empty.", nameof(hash));
        }
        return ReanalyzeHashAsync(hash, AnalysisType.File, cancellationToken);
    }

    /// <summary>Requests a new analysis for an existing IP address object.</summary>
    public Task<AnalysisReport?> ReanalyzeIpAddressAsync(
        string ipAddress,
        CancellationToken cancellationToken = default)
        => ReanalyzeResourceAsync("ip_addresses", ipAddress, cancellationToken);

    /// <summary>Requests a new analysis for an existing domain object.</summary>
    public Task<AnalysisReport?> ReanalyzeDomainAsync(
        string domain,
        CancellationToken cancellationToken = default)
        => ReanalyzeResourceAsync("domains", domain, cancellationToken);

    private async Task<AnalysisReport?> ReanalyzeResourceAsync(
        string resourcePath,
        string id,
        CancellationToken cancellationToken)
    {
        ValidateId(id, nameof(id));
        ThrowIfDisposed();
        using var response = await _httpClient
            .PostAsync($"{resourcePath}/{Uri.EscapeDataString(id)}/analyse", content: null, cancellationToken)
            .ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<AnalysisReport>(stream, cancellationToken).ConfigureAwait(false);
    }

    public Task<AnalysisReport?> ReanalyzeUrlAsync(string id, CancellationToken cancellationToken = default)
    {
        if (id is null)
        {
            throw new ArgumentNullException(nameof(id));
        }
        if (id.Length == 0)
        {
            throw new ArgumentException("Id must not be empty.", nameof(id));
        }
        return ReanalyzeHashAsync(id, AnalysisType.Url, cancellationToken);
    }

    public Task<AnalysisReport?> ReanalyzeUrlAsync(string url)
    {
        if (url is null)
        {
            throw new ArgumentNullException(nameof(url));
        }
        if (url.Length == 0)
        {
            throw new ArgumentException("Url must not be empty.", nameof(url));
        }
        return ReanalyzeUrlAsync(VirusTotalClientExtensions.GetUrlId(url), cancellationToken: default);
    }

    public Task<AnalysisReport?> SubmitUrlAsync(string url, CancellationToken cancellationToken = default)
        => SubmitUrlAsync(url, options: null, cancellationToken);

    public Task<AnalysisReport?> SubmitUrlAsync(
        string url,
        bool waitForCompletion,
        bool? analyze = null,
        CancellationToken cancellationToken = default)
    {
        var options = new SubmitUrlOptions
        {
            WaitForCompletion = waitForCompletion,
            Analyze = analyze
        };
        return SubmitUrlAsync(url, options, cancellationToken);
    }

    public async Task<AnalysisReport?> SubmitUrlAsync(
        string url,
        SubmitUrlOptions? options,
        CancellationToken cancellationToken = default)
    {
        if (url is null)
        {
            throw new ArgumentNullException(nameof(url));
        }
        if (url.Length == 0)
        {
            throw new ArgumentException("URL must not be empty.", nameof(url));
        }
        var path = new StringBuilder("urls");
        var hasQuery = false;
        if (options?.WaitForCompletion == true)
        {
            path.Append("?wait_for_completion=true");
            hasQuery = true;
        }
        if (options?.Analyze.HasValue == true)
        {
            path.Append(hasQuery ? '&' : '?')
                .Append("analyze=")
                .Append(options.Analyze.Value ? "true" : "false");
        }
        using var content = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("url", url) });
        using var response = await _httpClient.PostAsync(path.ToString(), content, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        using var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync<AnalysisReport>(stream, cancellationToken).ConfigureAwait(false);
    }
}
