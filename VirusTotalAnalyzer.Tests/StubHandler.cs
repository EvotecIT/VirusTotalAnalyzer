using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer.Tests;

internal sealed class StubHandler : HttpMessageHandler
{
    private readonly string _response;
    private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>? _responseFactory;

    public StubHandler(string response) => _response = response;

    public StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> responseFactory)
    {
        _response = string.Empty;
        _responseFactory = responseFactory ?? throw new ArgumentNullException(nameof(responseFactory));
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        => _responseFactory?.Invoke(request, cancellationToken)
           ?? Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
           {
               Content = new StringContent(_response, System.Text.Encoding.UTF8, "application/json")
           });
}
