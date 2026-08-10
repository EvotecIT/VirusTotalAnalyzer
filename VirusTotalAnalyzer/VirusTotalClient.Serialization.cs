using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;

namespace VirusTotalAnalyzer;

public sealed partial class VirusTotalClient
{
    private async Task<T?> DeserializeDataAsync<T>(Stream stream, CancellationToken cancellationToken)
    {
        var response = await JsonSerializer.DeserializeAsync<ApiResponse<T>>(stream, _jsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return response == null ? default : response.Data;
    }

    private static bool TryNormalizeVirusTotalUploadUri(string? value, out Uri? normalized)
    {
        normalized = null;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return false;
        }

        var trustedHost = string.Equals(uri.Host, "virustotal.com", StringComparison.OrdinalIgnoreCase) ||
            uri.Host.EndsWith(".virustotal.com", StringComparison.OrdinalIgnoreCase);
        if (!trustedHost ||
            !(string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
              string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        if (string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            uri = new UriBuilder(uri)
            {
                Scheme = Uri.UriSchemeHttps,
                Port = -1
            }.Uri;
        }

        normalized = uri;
        return true;
    }
}
