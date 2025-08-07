using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer.Tests;

internal sealed class SingleResponseHandler : HttpMessageHandler
{
    private readonly HttpResponseMessage _response;

    public HttpRequestMessage? Request { get; private set; }
    public string? Content { get; private set; }

    public SingleResponseHandler(HttpResponseMessage response) => _response = response;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Request = request;
        if (request.Content != null)
        {
#if NETFRAMEWORK
            Content = await request.Content.ReadAsStringAsync().ConfigureAwait(false);
#else
            Content = await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
#endif
        }
        return _response;
    }
}
