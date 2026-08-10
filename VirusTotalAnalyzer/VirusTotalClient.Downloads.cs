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

    private static bool IsRedirect(HttpStatusCode statusCode)
        => statusCode == HttpStatusCode.MovedPermanently ||
           statusCode == HttpStatusCode.Redirect ||
           statusCode == HttpStatusCode.RedirectMethod ||
           statusCode == HttpStatusCode.TemporaryRedirect ||
           (int)statusCode == 308;
}
