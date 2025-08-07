using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer.Tests;

internal sealed class StubHandler : HttpMessageHandler
{
    private readonly string _response;

    public StubHandler(string response) => _response = response;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(_response, System.Text.Encoding.UTF8, "application/json")
        });
}
