using System;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public partial class VirusTotalClientTests
{
    private static VirusTotalClient CreateClient()
    {
        var httpClient = new HttpClient(new StubHandler("{}"))
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
        };
        return new VirusTotalClient(httpClient);
    }

    [Fact]
    public async Task SubmitFileAsync_NullStream_Throws()
    {
        var client = CreateClient();
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await client.SubmitFileAsync(null!, "file"));
    }

    [Fact]
    public async Task SubmitFileAsync_NullFileName_Throws()
    {
        var client = CreateClient();
        using var stream = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await client.SubmitFileAsync(stream, null!));
    }

    [Fact]
    public async Task SubmitFileAsync_EmptyFileName_Throws()
    {
        var client = CreateClient();
        using var stream = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentException>(async () => await client.SubmitFileAsync(stream, ""));
    }

    [Fact]
    public async Task SubmitPrivateFileAsync_NullStream_Throws()
    {
        var client = CreateClient();
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await client.SubmitPrivateFileAsync(null!, "file"));
    }

    [Fact]
    public async Task SubmitPrivateFileAsync_NullFileName_Throws()
    {
        var client = CreateClient();
        using var stream = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await client.SubmitPrivateFileAsync(stream, null!));
    }

    [Fact]
    public async Task SubmitPrivateFileAsync_EmptyFileName_Throws()
    {
        var client = CreateClient();
        using var stream = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentException>(async () => await client.SubmitPrivateFileAsync(stream, ""));
    }

    [Fact]
    public async Task ReanalyzeHashAsync_NullHash_Throws()
    {
        var client = CreateClient();
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await client.ReanalyzeHashAsync(null!));
    }

    [Fact]
    public async Task ReanalyzeHashAsync_EmptyHash_Throws()
    {
        var client = CreateClient();
        await Assert.ThrowsAsync<ArgumentException>(async () => await client.ReanalyzeHashAsync(""));
    }

    [Fact]
    public async Task ReanalyzeFileAsync_NullHash_Throws()
    {
        var client = CreateClient();
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await client.ReanalyzeFileAsync(null!));
    }

    [Fact]
    public async Task ReanalyzeFileAsync_EmptyHash_Throws()
    {
        var client = CreateClient();
        await Assert.ThrowsAsync<ArgumentException>(async () => await client.ReanalyzeFileAsync(""));
    }

    [Fact]
    public async Task SubmitUrlAsync_NullUrl_Throws()
    {
        var client = CreateClient();
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await client.SubmitUrlAsync((string)null!, CancellationToken.None));
    }

    [Fact]
    public async Task SubmitUrlAsync_EmptyUrl_Throws()
    {
        var client = CreateClient();
        await Assert.ThrowsAsync<ArgumentException>(async () => await client.SubmitUrlAsync(string.Empty, CancellationToken.None));
    }

    [Fact]
    public async Task CreateRetrohuntJobAsync_NullRequest_Throws()
    {
        var client = CreateClient();
        await Assert.ThrowsAsync<ArgumentNullException>(() => client.CreateRetrohuntJobAsync(null!));
    }
}

