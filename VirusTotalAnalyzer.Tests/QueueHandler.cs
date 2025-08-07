using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer.Tests;

internal sealed class QueueHandler : HttpMessageHandler
{
    private readonly Queue<HttpResponseMessage> _responses;

    public List<HttpRequestMessage> Requests { get; } = new();
    public List<string?> Contents { get; } = new();

    public QueueHandler(params HttpResponseMessage[] responses)
        => _responses = new Queue<HttpResponseMessage>(responses);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        if (request.Content != null)
        {
#if NETFRAMEWORK
            var text = await request.Content.ReadAsStringAsync().ConfigureAwait(false);
#else
            var text = await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
#endif
            Contents.Add(text);
        }
        else
        {
            Contents.Add(null);
        }
        return _responses.Dequeue();
    }
}
