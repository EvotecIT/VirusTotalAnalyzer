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
    public async Task GetFileContactedUrlsAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"u1\",\"type\":\"url\",\"data\":{\"attributes\":{\"url\":\"https://example.com\"}}}]}";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var urls = await client.GetFileContactedUrlsAsync("abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/contacted_urls", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(urls);
        Assert.Single(urls!);
        Assert.Equal("https://example.com", urls[0].Data.Attributes.Url);
    }

    [Fact]
    public async Task GetFileContactedDomainsAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"d1\",\"type\":\"domain\",\"data\":{\"attributes\":{\"domain\":\"example.com\"}}}]}";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var domains = await client.GetFileContactedDomainsAsync("abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/contacted_domains", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(domains);
        Assert.Single(domains!);
        Assert.Equal("example.com", domains[0].Data.Attributes.Domain);
    }

    [Fact]
    public async Task GetFileContactedIpsAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"i1\",\"type\":\"ip_address\",\"data\":{\"attributes\":{\"ip_address\":\"1.2.3.4\"}}}]}";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var ips = await client.GetFileContactedIpsAsync("abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/contacted_ips", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(ips);
        Assert.Single(ips!);
        Assert.Equal("1.2.3.4", ips[0].Data.Attributes.IpAddress);
    }

    [Fact]
    public async Task GetFileReferrerFilesAsync_UsesCorrectPathAndDeserializesResponse()
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
        var client = new VirusTotalClient(httpClient);

        var files = await client.GetFileReferrerFilesAsync("abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/referrer_files", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(files);
        Assert.Single(files!);
        Assert.Equal("abc", files[0].Attributes.Md5);
    }

    [Fact]
    public async Task GetFileDownloadedFilesAsync_UsesCorrectPathAndDeserializesResponse()
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
        var client = new VirusTotalClient(httpClient);

        var files = await client.GetFileDownloadedFilesAsync("abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/downloaded_files", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(files);
        Assert.Single(files!);
        Assert.Equal("abc", files[0].Attributes.Md5);
    }

    [Fact]
    public async Task GetFileBundledFilesAsync_UsesCorrectPathAndDeserializesResponse()
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
        var client = new VirusTotalClient(httpClient);

        var files = await client.GetFileBundledFilesAsync("abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/bundled_files", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(files);
        Assert.Single(files!);
        Assert.Equal("abc", files[0].Attributes.Md5);
    }

    [Fact]
    public async Task GetFileDroppedFilesAsync_UsesCorrectPathAndDeserializesResponse()
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
        var client = new VirusTotalClient(httpClient);

        var files = await client.GetFileDroppedFilesAsync("abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/dropped_files", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(files);
        Assert.Single(files!);
        Assert.Equal("abc", files[0].Attributes.Md5);
    }

    [Fact]
    public async Task GetFileSimilarFilesAsync_UsesCorrectPathAndDeserializesResponse()
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
        var client = new VirusTotalClient(httpClient);

        var files = await client.GetFileSimilarFilesAsync("abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/similar_files", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(files);
        Assert.Single(files!);
        Assert.Equal("abc", files[0].Attributes.Md5);
    }

    [Fact]
    public async Task GetUrlDownloadedFilesAsync_UsesCorrectPathAndDeserializesResponse()
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
        var client = new VirusTotalClient(httpClient);

        var files = await client.GetUrlDownloadedFilesAsync("abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/urls/abc/downloaded_files", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(files);
        Assert.Single(files!);
        Assert.Equal("abc", files[0].Attributes.Md5);
    }

    [Fact]
    public async Task GetUrlReferrerFilesAsync_UsesCorrectPathAndDeserializesResponse()
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
        var client = new VirusTotalClient(httpClient);

        var files = await client.GetUrlReferrerFilesAsync("abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/urls/abc/referrer_files", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(files);
        Assert.Single(files!);
        Assert.Equal("abc", files[0].Attributes.Md5);
    }

    [Fact]
    public async Task GetUrlContactedIpsAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"i1\",\"type\":\"ip_address\",\"data\":{\"attributes\":{\"ip_address\":\"1.2.3.4\"}}}]}";
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var ips = await client.GetUrlContactedIpsAsync("abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/urls/abc/contacted_ips", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(ips);
        Assert.Single(ips!);
        Assert.Equal("1.2.3.4", ips[0].Data.Attributes.IpAddress);
    }

    [Fact]
    public async Task WaitForAnalysisCompletionAsync_HandlesNullData_ThrowsTimeout()
    {
        var json = "{\"id\":\"an\",\"type\":\"analysis\",\"data\":null}";
        var handler = new StubHandler(json);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await Assert.ThrowsAsync<TimeoutException>(() =>
            client.WaitForAnalysisCompletionAsync("an", TimeSpan.FromMilliseconds(50), TimeSpan.FromMilliseconds(10)));
    }
}

