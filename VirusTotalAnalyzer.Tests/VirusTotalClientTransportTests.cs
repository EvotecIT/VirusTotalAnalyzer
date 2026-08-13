using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public partial class VirusTotalClientTests
{
    [Fact]
    public void PublicConstructor_RequiresSeparatedHandlers()
    {
        var constructor = Assert.Single(typeof(VirusTotalClient).GetConstructors());
        var parameters = constructor.GetParameters();

        Assert.Collection(
            parameters,
            parameter => Assert.Equal(typeof(string), parameter.ParameterType),
            parameter => Assert.Equal(typeof(HttpMessageHandler), parameter.ParameterType),
            parameter => Assert.Equal(typeof(HttpMessageHandler), parameter.ParameterType),
            parameter => Assert.Equal(typeof(bool), parameter.ParameterType),
            parameter => Assert.Equal(typeof(string), parameter.ParameterType),
            parameter => Assert.Equal(typeof(TimeSpan?), parameter.ParameterType));
    }

    [Fact]
    public void Constructor_RejectsAuthenticatedDownloadClient()
    {
        var apiClient = new HttpClient(new QueueHandler());
        var downloadClient = new HttpClient(new QueueHandler());
        downloadClient.DefaultRequestHeaders.Add("x-apikey", "must-not-leak");

        var exception = Assert.Throws<ArgumentException>(
            () => new VirusTotalClient(apiClient, downloadClient));

        Assert.Equal("downloadClient", exception.ParamName);
    }

    [Fact]
    public void HandlerConstructor_RejectsAutomaticRedirects()
    {
        using var automaticApiHandler = new HttpClientHandler { AllowAutoRedirect = true };
        using var controlledApiHandler = new HttpClientHandler { AllowAutoRedirect = false };
        using var automaticDownloadHandler = new HttpClientHandler { AllowAutoRedirect = true };
        using var controlledDownloadHandler = new HttpClientHandler { AllowAutoRedirect = false };

        var apiException = Assert.Throws<ArgumentException>(() => new VirusTotalClient(
            "secret",
            automaticApiHandler,
            controlledDownloadHandler));
        var downloadException = Assert.Throws<ArgumentException>(() => new VirusTotalClient(
            "secret",
            controlledApiHandler,
            automaticDownloadHandler));

        Assert.Equal("apiHandler", apiException.ParamName);
        Assert.Equal("downloadHandler", downloadException.ParamName);
    }

    [Fact]
    public void HandlerConstructor_RejectsAutomaticRedirectsInDelegatingChain()
    {
        using var automaticInnerHandler = new HttpClientHandler { AllowAutoRedirect = true };
        using var apiHandler = new PassThroughHandler(automaticInnerHandler);
        using var downloadHandler = new HttpClientHandler { AllowAutoRedirect = false };

        var exception = Assert.Throws<ArgumentException>(() => new VirusTotalClient(
            "secret",
            apiHandler,
            downloadHandler));

        Assert.Equal("apiHandler", exception.ParamName);
    }

    [Fact]
    public void HandlerConstructor_RejectsSharedAuthenticatedAndDownloadHandler()
    {
        var handler = new QueueHandler();

        var exception = Assert.Throws<ArgumentException>(() => new VirusTotalClient(
            "secret",
            handler,
            handler));

        Assert.Equal("downloadHandler", exception.ParamName);
    }

#if !NETFRAMEWORK
    [Fact]
    public void HandlerConstructor_RejectsAutomaticRedirectsInSocketsHandler()
    {
        using var apiHandler = new SocketsHttpHandler { AllowAutoRedirect = true };
        using var downloadHandler = new SocketsHttpHandler { AllowAutoRedirect = false };

        var exception = Assert.Throws<ArgumentException>(() => new VirusTotalClient(
            "secret",
            apiHandler,
            downloadHandler));

        Assert.Equal("apiHandler", exception.ParamName);
    }
#endif

    [Fact]
    public async Task HandlerConstructor_UsesInjectedTransportsWithoutLeakingApiKey()
    {
        var apiHandler = new QueueHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                "{\"data\":\"https://storage.example/files/abc\"}",
                Encoding.UTF8,
                "application/json")
        });
        var downloadHandler = new QueueHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(new byte[] { 1, 2, 3 })
        });
        using var client = new VirusTotalClient("secret", apiHandler, downloadHandler);

        using var stream = await client.DownloadFileAsync("abc");
        Assert.Equal(1, stream.ReadByte());

        var apiRequest = Assert.Single(apiHandler.Requests);
        Assert.True(apiRequest.Headers.Contains("x-apikey"));
        var downloadRequest = Assert.Single(downloadHandler.Requests);
        Assert.False(downloadRequest.Headers.Contains("x-apikey"));
        Assert.Null(downloadRequest.Headers.Authorization);
    }

    private sealed class PassThroughHandler : DelegatingHandler
    {
        public PassThroughHandler(HttpMessageHandler innerHandler)
            : base(innerHandler)
        {
        }
    }
}
