using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer;

internal static class HttpContentExtensions
{
    public static Task<Stream> ReadContentStreamAsync(this HttpContent content, CancellationToken cancellationToken)
    {
#if NET472
        return content.ReadAsStreamAsync();
#else
        return content.ReadAsStreamAsync(cancellationToken);
#endif
    }
}
