using System;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using VirusTotalAnalyzer.Models;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class VirusTotalClientRetryTests
{
    [Fact]
    public async Task ExecuteWithRateLimitRetryAsync_RetriesRequest()
    {
        var errorJson = "{\"error\":{\"code\":\"RateLimitExceeded\",\"message\":\"too many\"}}";
        var rateLimitResponse = new HttpResponseMessage((HttpStatusCode)429)
        {
            Content = new StringContent(errorJson, Encoding.UTF8, "application/json")
        };
        rateLimitResponse.Headers.Add("Retry-After", "0");

        var successJson = "{\"id\":\"user-id\",\"type\":\"user\",\"data\":{\"attributes\":{\"username\":\"name\",\"role\":\"user\"}}}";
        var successResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(successJson, Encoding.UTF8, "application/json")
        };

        var handler = new QueueHandler(rateLimitResponse, successResponse);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var user = await client.ExecuteWithRateLimitRetryAsync(c => c.GetUserAsync("user-id"));

        Assert.NotNull(user);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task ExecuteWithRateLimitRetryAsync_PrefersServerRetryAfter()
    {
        var errorJson = "{\"error\":{\"code\":\"RateLimitExceeded\",\"message\":\"too many\"}}";
        var rateLimitResponse = new HttpResponseMessage((HttpStatusCode)429)
        {
            Content = new StringContent(errorJson, Encoding.UTF8, "application/json")
        };
        rateLimitResponse.Headers.Add("Retry-After", "0");

        var successJson = "{\"id\":\"user-id\",\"type\":\"user\",\"data\":{\"attributes\":{\"username\":\"name\",\"role\":\"user\"}}}";
        var successResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(successJson, Encoding.UTF8, "application/json")
        };

        var handler = new QueueHandler(rateLimitResponse, successResponse);
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        var sw = Stopwatch.StartNew();
        var user = await client.ExecuteWithRateLimitRetryAsync(
            c => c.GetUserAsync("user-id"),
            maxRetries: 1,
            defaultRetryDelay: TimeSpan.FromMinutes(1));
        sw.Stop();

        Assert.NotNull(user);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task ExecuteWithRateLimitRetryAsync_ThrowsAfterMaxRetries()
    {
        var errorJson = "{\"error\":{\"code\":\"RateLimitExceeded\",\"message\":\"too many\"}}";        
        HttpResponseMessage CreateRateLimitResponse()
        {
            var response = new HttpResponseMessage((HttpStatusCode)429)
            {
                Content = new StringContent(errorJson, Encoding.UTF8, "application/json")
            };
            response.Headers.Add("Retry-After", "0");
            return response;
        }

        var handler = new QueueHandler(
            CreateRateLimitResponse(),
            CreateRateLimitResponse(),
            CreateRateLimitResponse());
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        var client = new VirusTotalClient(httpClient);

        await Assert.ThrowsAsync<RateLimitExceededException>(() =>
            client.ExecuteWithRateLimitRetryAsync(c => c.GetUserAsync("user-id"), maxRetries: 2));

        Assert.Equal(3, handler.Requests.Count);
    }
}
