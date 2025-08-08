using System.Net.Http;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class VirusTotalClientDisposeTests
{
    [Fact]
    public void Dispose_DisposesHttpClient_WhenOwned()
    {
        var handler = new TrackingHandler();
        var httpClient = new HttpClient(handler);
        var client = new VirusTotalClient(httpClient, disposeClient: true);

        client.Dispose();

        Assert.True(handler.Disposed);
    }

    [Fact]
    public void Dispose_DoesNotDisposeHttpClient_WhenNotOwned()
    {
        var handler = new TrackingHandler();
        var httpClient = new HttpClient(handler);
        var client = new VirusTotalClient(httpClient);

        client.Dispose();

        Assert.False(handler.Disposed);
        httpClient.Dispose();
    }
}
