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
    public async Task GetDomainSubdomainsAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"d1\",\"type\":\"domain\",\"data\":{\"attributes\":{\"domain\":\"sub.example.com\"}}}]}";
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

        var subdomains = await client.GetDomainSubdomainsAsync("example.com");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/domains/example.com/subdomains", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(subdomains);
        Assert.Single(subdomains!);
        Assert.Equal("sub.example.com", subdomains[0].Data.Attributes.Domain);
    }

    [Fact]
    public async Task GetDomainSubdomainsAsync_BuildsQueryWithLimitAndCursor()
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
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await client.GetDomainSubdomainsAsync("example.com", limit: 10, cursor: "abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("?limit=10&cursor=abc", handler.Request!.RequestUri!.Query);
    }

    [Fact]
    public async Task GetDomainSiblingsAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"d1\",\"type\":\"domain\",\"data\":{\"attributes\":{\"domain\":\"sibling.com\"}}}]}";
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

        var siblings = await client.GetDomainSiblingsAsync("example.com");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/domains/example.com/siblings", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(siblings);
        Assert.Single(siblings!);
        Assert.Equal("sibling.com", siblings[0].Data.Attributes.Domain);
    }

    [Fact]
    public async Task GetDomainSiblingsAsync_BuildsQueryWithLimitAndCursor()
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
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await client.GetDomainSiblingsAsync("example.com", limit: 10, cursor: "abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("?limit=10&cursor=abc", handler.Request!.RequestUri!.Query);
    }

    [Fact]
    public async Task GetDomainUrlsAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"u1\",\"type\":\"url\",\"data\":{\"attributes\":{\"url\":\"http://example.com/\"}}}]}";
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

        var urls = await client.GetDomainUrlsAsync("example.com");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/domains/example.com/urls", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(urls);
        Assert.Single(urls!);
        Assert.Equal("http://example.com/", urls[0].Data.Attributes.Url);
    }

    [Fact]
    public async Task GetDomainUrlsAsync_BuildsQueryWithLimitAndCursor()
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
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await client.GetDomainUrlsAsync("example.com", limit: 10, cursor: "abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("?limit=10&cursor=abc", handler.Request!.RequestUri!.Query);
    }

    [Fact]
    public async Task GetDomainDnsRecordsAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"d1\",\"type\":\"dns_record\",\"data\":{\"attributes\":{\"type\":\"A\",\"value\":\"1.2.3.4\",\"ttl\":300}}}]}";
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

        var records = await client.GetDomainDnsRecordsAsync("example.com");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/domains/example.com/dns_records", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(records);
        Assert.Single(records!);
        Assert.Equal("A", records[0].Data.Attributes.RecordType);
        Assert.Equal("1.2.3.4", records[0].Data.Attributes.Value);
        Assert.Equal(300, records[0].Data.Attributes.Ttl);
    }

    [Fact]
    public async Task GetDomainDnsRecordsAsync_BuildsQueryWithLimitAndCursor()
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
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await client.GetDomainDnsRecordsAsync("example.com", limit: 10, cursor: "abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("?limit=10&cursor=abc", handler.Request!.RequestUri!.Query);
    }

    [Fact]
    public async Task GetDomainReferrerFilesAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"f1\",\"type\":\"file\",\"attributes\":{\"md5\":\"abc\"}}]}";
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

        var files = await client.GetDomainReferrerFilesAsync("example.com");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/domains/example.com/referrer_files", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(files);
        Assert.Single(files!);
        Assert.Equal("abc", files[0].Attributes.Md5);
    }

    [Fact]
    public async Task GetDomainReferrerFilesAsync_BuildsQueryWithLimitAndCursor()
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
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await client.GetDomainReferrerFilesAsync("example.com", limit: 10, cursor: "abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("?limit=10&cursor=abc", handler.Request!.RequestUri!.Query);
    }

    [Fact]
    public async Task GetDomainDownloadedFilesAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"f1\",\"type\":\"file\",\"attributes\":{\"md5\":\"abc\"}}]}";
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

        var files = await client.GetDomainDownloadedFilesAsync("example.com");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/domains/example.com/downloaded_files", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(files);
        Assert.Single(files!);
        Assert.Equal("abc", files[0].Attributes.Md5);
    }

    [Fact]
    public async Task GetDomainDownloadedFilesAsync_BuildsQueryWithLimitAndCursor()
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
        IVirusTotalClient client = new VirusTotalClient(httpClient);

        await client.GetDomainDownloadedFilesAsync("example.com", limit: 10, cursor: "abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("?limit=10&cursor=abc", handler.Request!.RequestUri!.Query);
    }
}
