using System;
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
        IVirusTotalClient client = new VirusTotalClient(httpClient, disposeClient: true);

        client.Dispose();

        Assert.True(handler.Disposed);
    }

    [Fact]
    public void Dispose_DoesNotDisposeHttpClient_WhenNotOwned()
    {
        var handler = new TrackingHandler();
        var httpClient = new HttpClient(handler);
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        client.Dispose();

        Assert.False(handler.Disposed);
        httpClient.Dispose();
    }

    [Fact]
    public async Task GetFileReportAsync_ThrowsObjectDisposedException_WhenDisposed()
    {
        var handler = new TrackingHandler();
        var httpClient = new HttpClient(handler);
        var client = new VirusTotalClient(httpClient);

        client.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.GetFileReportAsync("file-id"));

        httpClient.Dispose();
    }

    [Fact]
    public void GetFileNamesPagedAsync_ThrowsObjectDisposedException_WhenDisposed()
    {
        var handler = new TrackingHandler();
        var httpClient = new HttpClient(handler);
        var client = new VirusTotalClient(httpClient);

        client.Dispose();

        Assert.Throws<ObjectDisposedException>(() => client.GetFileNamesPagedAsync("file-id"));

        httpClient.Dispose();
    }
}
