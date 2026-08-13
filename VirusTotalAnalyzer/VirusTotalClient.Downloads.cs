using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer;

public sealed partial class VirusTotalClient
{
    private const int MaximumDownloadRedirects = 10;

    private static HttpClient CreateDownloadClient(TimeSpan timeout)
        => new(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = timeout };

    private static (HttpClient ApiClient, HttpClient DownloadClient) CreateConfiguredClients(
        string apiKey,
        HttpMessageHandler apiHandler,
        HttpMessageHandler downloadHandler,
        bool disposeHandlers,
        TimeSpan? timeout)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(apiKey));
        }

        ValidateRedirectHandler(apiHandler, nameof(apiHandler));
        ValidateRedirectHandler(downloadHandler, nameof(downloadHandler));
        if (ReferenceEquals(apiHandler, downloadHandler))
        {
            throw new ArgumentException(
                "The authenticated API and unauthenticated download handlers must be different instances.",
                nameof(downloadHandler));
        }

        var requestTimeout = timeout ?? TimeSpan.FromMinutes(10);
        var apiClient = new HttpClient(apiHandler, disposeHandlers)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/"),
            Timeout = requestTimeout
        };
        apiClient.DefaultRequestHeaders.Add("x-apikey", apiKey);
        var downloadClient = new HttpClient(downloadHandler, disposeHandlers)
        {
            Timeout = requestTimeout
        };
        return (apiClient, downloadClient);
    }

    private static void ValidateRedirectHandler(HttpMessageHandler? handler, string parameterName)
    {
        if (handler is null)
        {
            throw new ArgumentNullException(parameterName);
        }

        for (var current = handler; current is not null; current = (current as DelegatingHandler)?.InnerHandler)
        {
            if (current is HttpClientHandler httpClientHandler && httpClientHandler.AllowAutoRedirect)
            {
                throw new ArgumentException(
                    "Automatic redirects must be disabled so VirusTotal credentials are never forwarded to signed download hosts.",
                    parameterName);
            }
#if !NETFRAMEWORK
            if (current is SocketsHttpHandler socketsHttpHandler && socketsHttpHandler.AllowAutoRedirect)
            {
                throw new ArgumentException(
                    "Automatic redirects must be disabled so VirusTotal credentials are never forwarded to signed download hosts.",
                    parameterName);
            }
#endif

            if (current is not DelegatingHandler)
            {
                break;
            }
        }
    }

    private static Uri ValidateSignedDownloadUri(Uri? uri)
    {
        if (uri is null || !uri.IsAbsoluteUri ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("VirusTotal returned an invalid or insecure signed download URL.");
        }

        return uri;
    }

    private async Task<Stream> DownloadFromSignedUrlAsync(Uri uri, CancellationToken cancellationToken)
    {
        var currentUri = ValidateSignedDownloadUri(uri);
        for (var redirectCount = 0; redirectCount <= MaximumDownloadRedirects; redirectCount++)
        {
            var response = await _downloadClient
                .GetAsync(currentUri, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
            var disposeResponse = true;
            try
            {
                if (IsRedirect(response.StatusCode))
                {
                    if (redirectCount == MaximumDownloadRedirects || response.Headers.Location is null)
                    {
                        throw new HttpRequestException("The signed VirusTotal download exceeded the redirect limit or returned no redirect location.");
                    }

                    var redirectUri = response.Headers.Location.IsAbsoluteUri
                        ? response.Headers.Location
                        : new Uri(currentUri, response.Headers.Location);
                    currentUri = ValidateSignedDownloadUri(redirectUri);
                    continue;
                }

                await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
                var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
                disposeResponse = false;
                return new StreamWithResponse(response, stream);
            }
            finally
            {
                if (disposeResponse)
                {
                    response.Dispose();
                }
            }
        }

        throw new HttpRequestException("The signed VirusTotal download exceeded the redirect limit.");
    }

    private async Task<Stream> DownloadFromAuthenticatedEndpointAsync(
        string requestPath,
        CancellationToken cancellationToken)
    {
        var response = await _httpClient
            .GetAsync(requestPath, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        var disposeResponse = true;
        try
        {
            if (IsRedirect(response.StatusCode))
            {
                if (response.Headers.Location is null)
                {
                    throw new HttpRequestException("The VirusTotal download endpoint returned a redirect without a location.");
                }

                var requestUri = response.RequestMessage?.RequestUri ??
                    new Uri(_httpClient.BaseAddress ?? throw new InvalidOperationException("The VirusTotal API base address is not configured."), requestPath);
                var redirectUri = response.Headers.Location.IsAbsoluteUri
                    ? response.Headers.Location
                    : new Uri(requestUri, response.Headers.Location);

                response.Dispose();
                disposeResponse = false;
                return await DownloadFromSignedUrlAsync(
                        ValidateSignedDownloadUri(redirectUri),
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
            var stream = await response.Content.ReadContentStreamAsync(cancellationToken).ConfigureAwait(false);
            disposeResponse = false;
            return new StreamWithResponse(response, stream);
        }
        finally
        {
            if (disposeResponse)
            {
                response.Dispose();
            }
        }
    }

    private static bool IsRedirect(HttpStatusCode statusCode)
        => statusCode == HttpStatusCode.MovedPermanently ||
           statusCode == HttpStatusCode.Redirect ||
           statusCode == HttpStatusCode.RedirectMethod ||
           statusCode == HttpStatusCode.TemporaryRedirect ||
           (int)statusCode == 308;
}
