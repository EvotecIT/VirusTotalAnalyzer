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
    public async Task GetFileSubmissionsAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"s1\",\"type\":\"submission\",\"data\":{\"attributes\":{\"date\":1}}}]}"; 
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

        var submissions = await client.GetFileSubmissionsAsync("abc");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/files/abc/submissions", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(submissions);
        Assert.Single(submissions!);
        Assert.Equal(1, submissions[0].Data.Attributes.Date.ToUnixTimeSeconds());
    }

    [Fact]
    public async Task GetDomainResolutionsAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"r1\",\"type\":\"resolution\",\"data\":{\"attributes\":{\"host_name\":\"example.com\",\"ip_address\":\"1.2.3.4\",\"date\":1}}}]}";
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

        var resolutions = await client.GetDomainResolutionsAsync("example.com");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/domains/example.com/resolutions", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(resolutions);
        Assert.Single(resolutions!);
        Assert.Equal("1.2.3.4", resolutions[0].Data.Attributes.IpAddress);
    }

    [Fact]
    public async Task GetDomainSubmissionsAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"s1\",\"type\":\"submission\",\"data\":{\"attributes\":{\"date\":1}}}]}";
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

        var submissions = await client.GetDomainSubmissionsAsync("example.com");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/domains/example.com/submissions", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(submissions);
        Assert.Single(submissions!);
        Assert.Equal(1, submissions[0].Data.Attributes.Date.ToUnixTimeSeconds());
    }

    [Fact]
    public async Task GetIpAddressResolutionsAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"r1\",\"type\":\"resolution\",\"data\":{\"attributes\":{\"host_name\":\"example.com\",\"ip_address\":\"1.2.3.4\",\"date\":1}}}]}";
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

        var resolutions = await client.GetIpAddressResolutionsAsync("1.2.3.4");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/ip_addresses/1.2.3.4/resolutions", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(resolutions);
        Assert.Single(resolutions!);
        Assert.Equal("example.com", resolutions[0].Data.Attributes.HostName);
    }

    [Fact]
    public async Task GetIpAddressSubmissionsAsync_UsesCorrectPathAndDeserializesResponse()
    {
        var json = "{\"data\":[{\"id\":\"s1\",\"type\":\"submission\",\"data\":{\"attributes\":{\"date\":1}}}]}";
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

        var submissions = await client.GetIpAddressSubmissionsAsync("1.2.3.4");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/ip_addresses/1.2.3.4/submissions", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(submissions);
        Assert.Single(submissions!);
        Assert.Equal(1, submissions[0].Data.Attributes.Date.ToUnixTimeSeconds());
    }

    [Fact]
    public async Task GetIpAddressCommunicatingFilesAsync_UsesCorrectPathAndDeserializesResponse()
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

        var files = await client.GetIpAddressCommunicatingFilesAsync("1.2.3.4");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/ip_addresses/1.2.3.4/communicating_files", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(files);
        Assert.Single(files!);
        Assert.Equal("abc", files[0].Attributes.Md5);
    }

    [Fact]
    public async Task GetIpAddressDownloadedFilesAsync_UsesCorrectPathAndDeserializesResponse()
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

        var files = await client.GetIpAddressDownloadedFilesAsync("1.2.3.4");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/ip_addresses/1.2.3.4/downloaded_files", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(files);
        Assert.Single(files!);
        Assert.Equal("abc", files[0].Attributes.Md5);
    }

    [Fact]
    public async Task GetIpAddressReferrerFilesAsync_UsesCorrectPathAndDeserializesResponse()
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

        var files = await client.GetIpAddressReferrerFilesAsync("1.2.3.4");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/ip_addresses/1.2.3.4/referrer_files", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(files);
        Assert.Single(files!);
        Assert.Equal("abc", files[0].Attributes.Md5);
    }

    [Fact]
    public async Task GetIpAddressUrlsAsync_UsesCorrectPathAndDeserializesResponse()
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
        var client = new VirusTotalClient(httpClient);

        var urls = await client.GetIpAddressUrlsAsync("1.2.3.4");

        Assert.NotNull(handler.Request);
        Assert.Equal("/api/v3/ip_addresses/1.2.3.4/urls", handler.Request!.RequestUri!.AbsolutePath);
        Assert.NotNull(urls);
        Assert.Single(urls!);
        Assert.Equal("http://example.com/", urls[0].Data.Attributes.Url);
    }
}
