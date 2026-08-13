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
    public async Task GetFileReportsAsync_UsesIndividualV3ObjectsInInputOrder()
    {
        var handler = CreateTwoObjectHandler("a", "b", "file");
        IVirusTotalClient client = CreateClient(handler);

        var reports = await client.GetFileReportsAsync(new[] { "a", "b" });

        Assert.Collection(reports!, item => Assert.Equal("a", item.Id), item => Assert.Equal("b", item.Id));
        AssertPaths(handler, "/api/v3/files/a", "/api/v3/files/b");
    }

    [Fact]
    public async Task GetUrlReportsAsync_UsesIndividualV3ObjectsInInputOrder()
    {
        var handler = CreateTwoObjectHandler("u1", "u2", "url");
        IVirusTotalClient client = CreateClient(handler);

        var reports = await client.GetUrlReportsAsync(new[] { "u1", "u2" });

        Assert.Collection(reports!, item => Assert.Equal("u1", item.Id), item => Assert.Equal("u2", item.Id));
        AssertPaths(handler, "/api/v3/urls/u1", "/api/v3/urls/u2");
    }

    [Fact]
    public async Task GetIpAddressReportsAsync_UsesIndividualV3ObjectsInInputOrder()
    {
        var handler = CreateTwoObjectHandler("1.1.1.1", "8.8.8.8", "ip_address");
        IVirusTotalClient client = CreateClient(handler);

        var reports = await client.GetIpAddressReportsAsync(new[] { "1.1.1.1", "8.8.8.8" });

        Assert.Collection(reports!, item => Assert.Equal("1.1.1.1", item.Id), item => Assert.Equal("8.8.8.8", item.Id));
        AssertPaths(handler, "/api/v3/ip_addresses/1.1.1.1", "/api/v3/ip_addresses/8.8.8.8");
    }

    [Fact]
    public async Task GetDomainReportsAsync_UsesIndividualV3ObjectsInInputOrder()
    {
        var handler = CreateTwoObjectHandler("example.com", "vt.com", "domain");
        IVirusTotalClient client = CreateClient(handler);

        var reports = await client.GetDomainReportsAsync(new[] { "example.com", "vt.com" });

        Assert.Collection(reports!, item => Assert.Equal("example.com", item.Id), item => Assert.Equal("vt.com", item.Id));
        AssertPaths(handler, "/api/v3/domains/example.com", "/api/v3/domains/vt.com");
    }

    [Fact]
    public async Task GetAnalysesAsync_UsesIndividualV3ObjectsInInputOrder()
    {
        var handler = CreateTwoObjectHandler("a1", "a2", "analysis", includeAttributes: true);
        IVirusTotalClient client = CreateClient(handler);

        var reports = await client.GetAnalysesAsync(new[] { "a1", "a2" });

        Assert.Collection(reports!, item => Assert.Equal("a1", item.Id), item => Assert.Equal("a2", item.Id));
        AssertPaths(handler, "/api/v3/analyses/a1", "/api/v3/analyses/a2");
    }

    private static QueueHandler CreateTwoObjectHandler(string firstId, string secondId, string type, bool includeAttributes = false)
    {
        var attributes = includeAttributes ? ",\"attributes\":{}" : string.Empty;
        return new QueueHandler(
            JsonResponse($"{{\"data\":{{\"id\":\"{firstId}\",\"type\":\"{type}\"{attributes}}}}}"),
            JsonResponse($"{{\"data\":{{\"id\":\"{secondId}\",\"type\":\"{type}\"{attributes}}}}}"));
    }

    private static HttpResponseMessage JsonResponse(string json)
        => new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static IVirusTotalClient CreateClient(QueueHandler handler)
        => new VirusTotalClient(new HttpClient(handler) { BaseAddress = new Uri("https://www.virustotal.com/api/v3/") });

    private static void AssertPaths(QueueHandler handler, string first, string second)
    {
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal(first, handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal(second, handler.Requests[1].RequestUri!.AbsolutePath);
    }
}
