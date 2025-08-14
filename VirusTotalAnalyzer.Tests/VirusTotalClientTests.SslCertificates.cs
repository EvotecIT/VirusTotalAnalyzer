using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public partial class VirusTotalClientTests
{
    [Fact]
    public async Task GetSslCertificateAsync_DeserializesResponseAndUsesCorrectPath()
    {
        var json = "{\"data\":{\"id\":\"c1\",\"type\":\"ssl_certificate\",\"links\":{\"self\":\"https://www.virustotal.com/api/v3/ssl_certificates/c1\"},\"data\":{\"attributes\":{\"sha256\":\"hash\",\"subject\":\"CN=example\",\"issuer\":\"CN=ca\"}}}}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var cert = await client.GetSslCertificateAsync("c1");

        Assert.NotNull(cert);
        Assert.Equal("c1", cert!.Id);
        Assert.Equal(ResourceType.SslCertificate, cert.Type);
        Assert.Equal("hash", cert.Data.Attributes.Sha256);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/ssl_certificates/c1", handler.Request!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task GetDomainSslCertificatesAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"c1\",\"type\":\"ssl_certificate\",\"data\":{\"attributes\":{\"sha256\":\"hash\"}}}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var certs = await client.GetDomainSslCertificatesAsync("example.com");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/domains/example.com/ssl_certificates", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(certs);
        Assert.Single(certs!);
        Assert.Equal("hash", certs[0].Data.Attributes.Sha256);
    }

    [Fact]
    public async Task GetDomainSslCertificatesAsync_BuildsQueryWithLimitAndCursor()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.GetDomainSslCertificatesAsync("example.com", limit: 10, cursor: "abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("?limit=10&cursor=abc", handler.Request!.RequestUri!.Query);
    }

    [Fact]
    public async Task GetIpAddressSslCertificatesAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"c1\",\"type\":\"ssl_certificate\",\"data\":{\"attributes\":{\"sha256\":\"hash\"}}}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var certs = await client.GetIpAddressSslCertificatesAsync("1.2.3.4");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/ip_addresses/1.2.3.4/ssl_certificates", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(certs);
        Assert.Single(certs!);
        Assert.Equal("hash", certs[0].Data.Attributes.Sha256);
    }

    [Fact]
    public async Task GetIpAddressSslCertificatesAsync_BuildsQueryWithLimitAndCursor()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await client.GetIpAddressSslCertificatesAsync("1.2.3.4", limit: 10, cursor: "abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("?limit=10&cursor=abc", handler.Request!.RequestUri!.Query);
    }
}

