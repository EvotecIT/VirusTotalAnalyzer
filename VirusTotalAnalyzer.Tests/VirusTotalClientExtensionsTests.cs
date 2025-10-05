using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using VirusTotalAnalyzer;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class VirusTotalClientExtensionsTests
{
    [Fact]
    public async Task ScanFileAsync_Throws_WhenFilePathNull()
    {
        using var client = CreateClient();
        await Assert.ThrowsAsync<ArgumentNullException>(() => client.ScanFileAsync(null!));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task ScanFileAsync_Throws_WhenFilePathWhitespace(string filePath)
    {
        using var client = CreateClient();
        await Assert.ThrowsAsync<ArgumentException>(() => client.ScanFileAsync(filePath));
    }

    [Fact]
    public async Task ScanFileAsync_Throws_WhenFileDoesNotExist()
    {
        using var client = CreateClient();
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        var exception = await Assert.ThrowsAsync<FileNotFoundException>(() => client.ScanFileAsync(path));
        Assert.Equal(path, exception.FileName);
    }

    private static IVirusTotalClient CreateClient()
        => new VirusTotalClient(new HttpClient(new StubHandler("{}")));
}
