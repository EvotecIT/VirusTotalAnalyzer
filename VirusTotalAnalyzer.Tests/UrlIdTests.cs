using System;
using System.Text;
using VirusTotalAnalyzer;
using Xunit;

namespace VirusTotalAnalyzer.Tests;

public class UrlIdTests
{
    [Theory]
    [InlineData("HTTP://Virustotal.com", "http://virustotal.com/")]
    [InlineData("https://virustotal.com:443/#frag", "https://virustotal.com/")]
    [InlineData("http://virustotal.com:80/path", "http://virustotal.com/path")]
    [InlineData("http://virustotal.com#fragment", "http://virustotal.com/")]
    public void GetUrlId_CanonicalizesAndEncodes(string url, string canonical)
    {
        var id = VirusTotalClientExtensions.GetUrlId(url);
        var expected = Convert.ToBase64String(Encoding.UTF8.GetBytes(canonical))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        Assert.Equal(expected, id);
    }

    [Theory]
    [InlineData("HTTP://Virustotal.com", "http://virustotal.com/")]
    [InlineData("https://virustotal.com:443/#frag", "https://virustotal.com/")]
    [InlineData("http://virustotal.com:80/path", "http://virustotal.com/path")]
    [InlineData("http://virustotal.com#fragment", "http://virustotal.com/")]
    public void TryGetUrlId_CanonicalizesAndEncodes(string url, string canonical)
    {
        var result = VirusTotalClientExtensions.TryGetUrlId(url, out var id);
        var expected = Convert.ToBase64String(Encoding.UTF8.GetBytes(canonical))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        Assert.True(result);
        Assert.Equal(expected, id);
    }

    [Fact]
    public void TryGetUrlId_ReturnsFalse_WhenUrlInvalid()
    {
        var result = VirusTotalClientExtensions.TryGetUrlId("invalid", out var id);
        Assert.False(result);
        Assert.Null(id);
    }

    [Fact]
    public void GetUrlId_Throws_WhenUrlInvalid()
    {
        Assert.Throws<UriFormatException>(() => VirusTotalClientExtensions.GetUrlId("invalid"));
    }
}
