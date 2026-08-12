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
    private const string CertificateJson = "{\"id\":\"c1\",\"type\":\"ssl_cert\",\"links\":{\"self\":\"https://www.virustotal.com/api/v3/ssl_certs/c1\"},\"attributes\":{\"thumbprint_sha256\":\"hash\",\"subject\":{\"CN\":\"example.com\"},\"issuer\":{\"CN\":\"Example CA\"},\"validity\":{\"not_before\":\"2020-05-26 15:35:06\",\"not_after\":\"2020-08-18 15:35:06\"}}}";

    [Fact]
    public async Task GetSslCertificateAsync_DeserializesResponseAndUsesCorrectPath()
    {
        var handler = Handler($"{{\"data\":{CertificateJson}}}");
        using var client = CreateCertificateClient(handler);

        var certificate = await client.GetSslCertificateAsync("c1");

        Assert.Equal("/api/v3/ssl_certs/c1", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(certificate);
        Assert.Equal(ResourceType.SslCertificate, certificate!.Type);
        Assert.Equal("hash", certificate.Attributes.ThumbprintSha256);
        Assert.Equal("example.com", certificate.Attributes.Subject["CN"]);
        Assert.Equal("Example CA", certificate.Attributes.Issuer["CN"]);
    }

    [Theory]
    [InlineData(true, "/api/v3/domains/example.com/historical_ssl_certificates")]
    [InlineData(false, "/api/v3/ip_addresses/1.2.3.4/historical_ssl_certificates")]
    public async Task HistoricalSslCertificatePages_PreserveContextAndCursor(bool domain, string expectedPath)
    {
        var certificateWithContext = CertificateJson.Substring(0, CertificateJson.Length - 1) +
                                     ",\"context_attributes\":{\"first_seen_date\":\"2020-06-11\",\"last_seen_date\":\"2020-07-12\",\"port\":\"443\",\"source\":\"passive-ssl\"}}";
        var json = "{\"data\":[" + certificateWithContext + "],\"meta\":{\"cursor\":\"next-page\"}}";
        var handler = Handler(json);
        using var client = CreateCertificateClient(handler);

        var page = domain
            ? await client.GetDomainHistoricalSslCertificatesPageAsync("example.com", limit: 10, cursor: "abc")
            : await client.GetIpAddressHistoricalSslCertificatesPageAsync("1.2.3.4", limit: 10, cursor: "abc");

        Assert.Equal(expectedPath, handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("?limit=10&cursor=abc", handler.Request.RequestUri.Query);
        Assert.Equal("next-page", page!.NextCursor);
        var certificate = Assert.Single(page.Data);
        Assert.Equal(ResourceType.SslCertificate, certificate.Type);
        Assert.Equal(443, certificate.ContextAttributes!.Port);
        Assert.Equal("2020-06-11", certificate.ContextAttributes.FirstSeenDate);
        Assert.Equal("2020-07-12", certificate.ContextAttributes.LastSeenDate);
        Assert.True(certificate.ContextAttributes.AdditionalProperties.ContainsKey("source"));
        Assert.Equal("hash", certificate.Attributes.ThumbprintSha256);
    }

    private static SingleResponseHandler Handler(string json)
        => new(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });

    private static VirusTotalClient CreateCertificateClient(SingleResponseHandler handler)
        => new(new HttpClient(handler) { BaseAddress = new Uri("https://www.virustotal.com/api/v3/") });
}
