using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public partial class VirusTotalClientTests
{
    [Fact]
    public async Task GetFileReportsAsync_ReturnsCombinedResults()
    {
        var json = "{\"data\":[{\"id\":\"a\",\"type\":\"file\"},{\"id\":\"b\",\"type\":\"file\"}]}";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var reports = await client.GetFileReportsAsync(new[] { "a", "b" });

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("ids=a,b", handler.Request.RequestUri.Query.TrimStart('?'));
        Assert.NotNull(reports);
        Assert.Collection(reports!,
            r => Assert.Equal("a", r.Id),
            r => Assert.Equal("b", r.Id));
    }

    [Fact]
    public async Task GetUrlReportsAsync_ReturnsCombinedResults()
    {
        var json = "{\"data\":[{\"id\":\"u1\",\"type\":\"url\"},{\"id\":\"u2\",\"type\":\"url\"}]}";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var reports = await client.GetUrlReportsAsync(new[] { "u1", "u2" });

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/urls", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("ids=u1,u2", handler.Request.RequestUri.Query.TrimStart('?'));
        Assert.NotNull(reports);
        Assert.Collection(reports!,
            r => Assert.Equal("u1", r.Id),
            r => Assert.Equal("u2", r.Id));
    }

    [Fact]
    public async Task GetIpAddressReportsAsync_ReturnsCombinedResults()
    {
        var json = "{\"data\":[{\"id\":\"1.1.1.1\",\"type\":\"ip_address\"},{\"id\":\"8.8.8.8\",\"type\":\"ip_address\"}]}";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var reports = await client.GetIpAddressReportsAsync(new[] { "1.1.1.1", "8.8.8.8" });

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/ip_addresses", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("ids=1.1.1.1,8.8.8.8", handler.Request.RequestUri.Query.TrimStart('?'));
        Assert.NotNull(reports);
        Assert.Collection(reports!,
            r => Assert.Equal("1.1.1.1", r.Id),
            r => Assert.Equal("8.8.8.8", r.Id));
    }

    [Fact]
    public async Task GetDomainReportsAsync_ReturnsCombinedResults()
    {
        var json = "{\"data\":[{\"id\":\"example.com\",\"type\":\"domain\"},{\"id\":\"vt.com\",\"type\":\"domain\"}]}";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var reports = await client.GetDomainReportsAsync(new[] { "example.com", "vt.com" });

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/domains", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("ids=example.com,vt.com", handler.Request.RequestUri.Query.TrimStart('?'));
        Assert.NotNull(reports);
        Assert.Collection(reports!,
            r => Assert.Equal("example.com", r.Id),
            r => Assert.Equal("vt.com", r.Id));
    }

    [Fact]
    public async Task GetAnalysesAsync_ReturnsCombinedResults()
    {
        var json = "{\"data\":[{\"id\":\"a1\",\"type\":\"analysis\",\"data\":{\"attributes\":{}}},{\"id\":\"a2\",\"type\":\"analysis\",\"data\":{\"attributes\":{}}}]}";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        var reports = await client.GetAnalysesAsync(new[] { "a1", "a2" });

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/analyses", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("ids=a1,a2", handler.Request.RequestUri.Query.TrimStart('?'));
        Assert.NotNull(reports);
        Assert.Collection(reports!,
            r => Assert.Equal("a1", r.Id),
            r => Assert.Equal("a2", r.Id));
    }
}
