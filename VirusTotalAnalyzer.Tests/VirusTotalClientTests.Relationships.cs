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
    public async Task GetFileContactedUrlsAsync_DeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"1\",\"type\":\"url\",\"attributes\":{\"url\":\"http://example.com\"}}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var urls = await client.GetFileContactedUrlsAsync("abc");

        Assert.NotNull(urls);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/contacted_urls", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("http://example.com", urls![0].Attributes.Url);
    }

    [Fact]
    public async Task GetFileContactedUrlsAsync_ThrowsApiException()
    {
        var errorJson = "{\"error\":{\"code\":\"NotFoundError\",\"message\":\"not found\"}}";
        var response = new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent(errorJson, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var ex = await Assert.ThrowsAsync<ApiException>(() => client.GetFileContactedUrlsAsync("abc"));
        Assert.Equal("NotFoundError", ex.Error?.Code);
        Assert.Equal("not found", ex.Message);
    }

    [Fact]
    public async Task GetFileContactedDomainsAsync_DeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"1\",\"type\":\"domain\",\"attributes\":{\"domain\":\"example.com\"}}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var domains = await client.GetFileContactedDomainsAsync("abc");

        Assert.NotNull(domains);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/contacted_domains", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("example.com", domains![0].Attributes.Domain);
    }

    [Fact]
    public async Task GetFileContactedDomainsAsync_ThrowsApiException()
    {
        var errorJson = "{\"error\":{\"code\":\"NotFoundError\",\"message\":\"not found\"}}";
        var response = new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent(errorJson, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var ex = await Assert.ThrowsAsync<ApiException>(() => client.GetFileContactedDomainsAsync("abc"));
        Assert.Equal("NotFoundError", ex.Error?.Code);
        Assert.Equal("not found", ex.Message);
    }

    [Fact]
    public async Task GetFileContactedIpsAsync_DeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"1\",\"type\":\"ipAddress\",\"attributes\":{\"ip_address\":\"1.2.3.4\"}}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var ips = await client.GetFileContactedIpsAsync("abc");

        Assert.NotNull(ips);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/contacted_ips", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("1.2.3.4", ips![0].Attributes.IpAddress);
    }

    [Fact]
    public async Task GetFileContactedIpsAsync_ThrowsApiException()
    {
        var errorJson = "{\"error\":{\"code\":\"NotFoundError\",\"message\":\"not found\"}}";
        var response = new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent(errorJson, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var ex = await Assert.ThrowsAsync<ApiException>(() => client.GetFileContactedIpsAsync("abc"));
        Assert.Equal("NotFoundError", ex.Error?.Code);
        Assert.Equal("not found", ex.Message);
    }

    [Fact]
    public async Task GetFileReferrerFilesAsync_DeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"file1\",\"type\":\"file\"}]}";
        var handler = new SingleResponseHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var files = await client.GetFileReferrerFilesAsync("abc");

        Assert.NotNull(files);
        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/referrer_files", handler.Request!.RequestUri!.AbsolutePath);
        Assert.Equal("file1", files![0].Id);
    }

    [Fact]
    public async Task GetFileReferrerFilesAsync_ThrowsApiException()
    {
        var errorJson = "{\"error\":{\"code\":\"NotFoundError\",\"message\":\"not found\"}}";
        var response = new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent(errorJson, Encoding.UTF8, "application/json")
        };
        var handler = new SingleResponseHandler(response);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var ex = await Assert.ThrowsAsync<ApiException>(() => client.GetFileReferrerFilesAsync("abc"));
        Assert.Equal("NotFoundError", ex.Error?.Code);
        Assert.Equal("not found", ex.Message);
    }
}

