using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;
using VirusTotalAnalyzer.Models;

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

    [Theory]
    [MemberData(nameof(DownloadFailureScenarios))]
    public async Task DownloadMethods_DisposeResponseOnFailure(Func<VirusTotalClient, Task> action)
    {
        var handler = new TrackingResponseHandler(HttpStatusCode.InternalServerError);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        using var client = new VirusTotalClient(httpClient);

        await Assert.ThrowsAsync<ApiException>(() => action(client));

        Assert.NotNull(handler.LastResponse);
        Assert.True(handler.LastResponse!.Disposed);
        httpClient.Dispose();
    }

    public static TheoryData<Func<VirusTotalClient, Task>> DownloadFailureScenarios()
        => new()
        {
            { client => client.DownloadFileAsync("id") },
            { client => client.DownloadYaraRulesetAsync("id") },
            { client => client.DownloadLivehuntNotificationFileAsync("id") },
            { client => client.DownloadRetrohuntNotificationFileAsync("id") },
            { client => client.DownloadPcapAsync("id") }
        };
}
